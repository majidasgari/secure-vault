# SPEC 02 — Interfaces: headless daemon, local socket API, MCP stdio server

Modules: `vault/daemon.py`, `vault/api/{__init__,service,socket_server,client,mcp_server}.py`,
`vault/mcp.py` (console entry), `vault/gui.py` (P3, GUI entry — same service in-process).

## 0. Process model (recap of SPEC/00 §5)

* **The GUI process** (`python -m vault` → `vault.gui:main`) owns the `VaultSession` and the
  socket server. It is the only process that can derive keys.
* **The MCP bridge** (`python -m vault.mcp`) is a thin, stateless process spawned by the agent
  runtime (Hermes). It speaks MCP JSON-RPC on **stdio** and forwards each call to the daemon
  over the Unix socket with the **`mcp` role token**. It never touches the vault files.
* **Headless daemon** (`python -m vault.daemon --home … --unlock-file …`) = the same service
  without Qt, used by the test/CI smoke tests and by anyone who wants the vault available to
  agents without a GUI. It loads Qt-free modules only. `--unlock-file` reads the password from a
  `0600` file (never from argv) — used by tests.
* If the socket is missing/refused, the bridge returns the MCP error `VAULT_NOT_RUNNING` (it does
  **not** auto-start the GUI).

## 1. `vault/api/service.py` — the shared, transport-independent command surface

```python
class Service:
    """Wraps VaultSession and exposes exactly the commands the two transports need."""
    def __init__(self, session: VaultSession, *, on_secret_request: Callable[[dict], None] | None = None)
    def dispatch(self, method: str, params: dict, *, role: str, session_id: str) -> dict
```
`role` ∈ `{"ui", "mcp"}`, provided by the transport (in-process call or token), never by
client-supplied data. `dispatch` is the single place where methods are routed; unknown method →
`BadRequest("unknown_method")` (the transports map this to JSON-RPC `-32601`).

Method list (all take a dict, all return a dict; errors raise `VaultError`):

| method | role | notes |
|---|---|---|
| `vault.status` | ui, mcp | `session.status()`; allowed while locked (metadata only, no counts of content) |
| `vault.locked` | ui, mcp | `{"locked": bool}` |
| `vault.unlock` | ui only | `{"password": str}` → `{"locked": False, "status": {...}}` |
| `vault.lock` | ui only | `{}` |
| `vault.list_folder` | ui, mcp | `{"path": "/"}` → `{"path", "note", "entries": [...]}`; entries: `{name, path, is_dir, size, mtime, sensitivity, tags, secret: bool}` |
| `vault.read_file` | ui, mcp | `{"path", "encoding"?}` → `{"path","content","sensitivity","size"}` (denied for secret+ to mcp) |
| `vault.read_lines` | ui, mcp | `{"path","start","count"}` → `{"path","start","count","text","total_lines"}` |
| `vault.write_file` | ui, mcp | `{"path","content","encoding"?, "sensitivity"?}` → `{"path","size","sensitivity","created": bool}` |
| `vault.write_lines` | ui, mcp | `{"path","text","mode":"append"|"prepend"|"insert","at_line"?}` → `{"path","size","lines"}` |
| `vault.mkdir` | ui, mcp | `{"path"}` |
| `vault.file_ops` | ui, mcp | `{"op":"move"|"copy"|"delete"|"mkdir","src","dst"?,"recursive"?}` |
| `vault.set_sensitivity` | ui, mcp | `{"path","level"}`; mcp may only raise |
| `vault.set_tags` | ui, mcp | `{"path","tags":[...]}` |
| `vault.folder_note` | ui, mcp | `{"path"}` → `{"path","note"}` |
| `vault.set_folder_note` | ui, mcp | `{"path","text"}` |
| `vault.search_filenames` | ui, mcp | `{"query","limit"?}` |
| `vault.search_text` | ui, mcp | `{"query","limit"?}` |
| `vault.search_semantic` | ui, mcp | `{"query","limit"?}` |
| `vault.request_open_secret` | mcp only | `{"path"}` → `{"request_id","status"}` |
| `vault.resolve_open_secret` | ui only | `{"request_id","approved"}` |
| `vault.pending_requests` | ui only | `{}` |
| `vault.access_log` | ui, mcp | `{"limit","offset","source"?,"outcome"?}` → read-only view of the log |
| `vault.read_secret` | **ui only** | `{"path"}` → content; used by the UI after confirmation / by the native viewer. Never reachable with an `mcp` token. |
| `vault.get_settings` | ui, mcp | `{}` → settings minus secrets |
| `vault.set_settings` | ui only | `{"language","auto_lock_seconds","semantic":{"enabled"}}` (+ `vault_home` only via the UI at first run) |
| `vault.semantic_index` | ui only | `{"force"?: bool}` → run `index_all` synchronously (small vaults) |
| `vault.stats` | ui, mcp | `{"files","folders","by_level","store"}` |
| `vault.verify_blobs` | ui | integrity check → `{"checked","bad":[...]}` |

Logging behaviour of `dispatch`: one `access_log` row per call with `source` derived from role
(`ui`/`mcp`), `tool` = method name, `target_path` from params, `outcome` = `allow|deny|error`,
`code` = the `VaultError.code` when applicable, `session` = the transport session id.

## 2. `vault/api/socket_server.py` — local Unix-socket JSON-RPC

* Path: `runtime_dir()/daemon.sock`, permissions `0600`, unlink a stale socket at start
  (refuse if another live daemon answers: try connect → if it answers, exit with
  `AlreadyExists("daemon_already_running")`).
* Token file: `runtime_dir()/tokens.json`, mode `0600`, written at startup:
  `{"mcp": "<32-byte hex>", "created_at": …}`. Regenerated on every daemon start. Only the
  `mcp` token lives here (the UI needs no token: it is in-process).
* Protocol: **newline-delimited JSON**, one request per line, one response per line.
  Request: `{"id": <str|int>, "token": "<hex>", "method": "<vault.*>", "params": {...}}`.
  Response (success): `{"id": ..., "ok": true, "result": {...}}`.
  Response (error): `{"id": ..., "ok": false, "error": {"code": "...", "message": "...", "details": {...}}}`.
  Malformed line → `{"ok": false, "error": {"code": "BAD_REQUEST"}}` with `id: null`.
* Auth: `hmac.compare_digest(token, mcp_token)`; wrong/absent token → `UNAUTHORIZED` and a
  `deny` row in the access log with `tool="<method>"`, `source="socket"`.
* `ThreadingUnixStreamServer`, one handler per connection, request loop until EOF; a client may
  pipeline requests but responses must be returned in order per connection.
* The server never blocks on the UI: `request_open_secret` returns immediately with
  `status="pending"`; the UI answers later via `resolve_open_secret`.
* Also serve a tiny `{"method":"vault.ping"}` → `{"pong": true, "locked": bool, "ts": …}` for
  liveness (used by the MCP bridge and by `tools/smoke_mcp.py`).
* A monotonically increasing `session_id` (`sock-<n>`) is assigned per connection and used in
  the access log.

## 3. `vault/api/client.py`

```python
class VaultClient:
    def __init__(self, *, socket_path: Path | None = None, token: str | None = None, timeout: float = 30.0)
    @classmethod def from_runtime(cls, *, role: str = "mcp") -> "VaultClient"   # reads runtime_dir()/tokens.json
    def call(self, method: str, params: dict | None = None) -> dict             # raises VaultError subclasses
    def ping(self) -> dict
    def close(self) -> None
```
`call` converts `{"ok": false}` into the matching `VaultError` subclass by `code`, and
connection errors (`FileNotFoundError`, `ConnectionRefusedError`) into
`VaultNotRunning("daemon is not running — start `secure-vault`")`.

## 4. `vault/api/mcp_server.py` — MCP over stdio, **no external dependencies**

JSON-RPC 2.0, one JSON object per line on stdin/stdout (no `Content-Length` framing — that is
the `stdio` transport used by Claude/Hermes MCP clients; implement **both**: if a line starts
with `Content-Length:` parse LSP-style headers, otherwise parse the line as JSON. Be liberal in
what you accept, strict in what you emit — emit **newline-delimited JSON**).

Handshake:
* `initialize` → `{"protocolVersion": <client's if it is one of the supported versions, else
  "2025-06-18">, "capabilities": {"tools": {}, "resources": {"listChanged": false},
  "prompts": {}}, "serverInfo": {"name": "secure-vault", "version": <__version__>},
  "instructions": "Personal encrypted vault. Content of secret/secretfile files is never
  returned to agents; use request_open_secret for secretfile."}`.
  Supported: `2024-11-05`, `2025-03-26`, `2025-06-18`.
* `notifications/initialized` → no response (notification).
* `ping` → `{}`.
* `tools/list`, `tools/call`, `resources/list`, `resources/read`, `resources/templates/list`,
  `prompts/list` → `{"prompts": []}`, `logging/setLevel` → `{}`.
* Notifications (no `id`) never get a response; unknown **methods** → `-32601`; unknown
  **notification** → silently ignored; parse error → `-32700`; invalid params → `-32602`.
* Any `VaultError` from the client → JSON-RPC error `-32000` with
  `data = {"code": ..., "message": ..., "details": {...}}`. Every tool/resource failure is a
  proper JSON-RPC error, never a silent success.

### 4.1 Tools (exact names, descriptions, input schema)

`tools/list` returns exactly these 14 tools, with `inputSchema` in JSON Schema draft-07 style.
Descriptions must mention the sensitivity rules where relevant.

| tool | input schema (properties → required) | result payload (in `content[0].text`, JSON string) |
|---|---|---|
| `vault_status` | `{}` | `{"locked", "home", "files", "folders", "by_level", "daemon": {"running": true}}` |
| `list_folder` | `path` (str, default `"/"`) | `{"path","note","entries":[{name,path,is_dir,size,mtime,sensitivity,tags,secret}]}` |
| `read_file` | `path` (req), `encoding?` | `{"path","content","sensitivity","size"}` |
| `read_lines` | `path` (req), `start` (int, default 1), `count` (int, default 200) | `{"path","start","count","total_lines","text"}` |
| `write_file` | `path` (req), `content` (req), `encoding?`, `sensitivity?` (enum, default `normal`) | `{"path","size","sensitivity","created"}` |
| `write_lines` | `path` (req), `text` (req), `mode` (enum append/prepend/insert, default append), `at_line?` | `{"path","size","lines"}` |
| `mkdir` | `path` (req) | `{"path","created"}` |
| `file_ops` | `op` (req, enum move/copy/delete/mkdir), `src` (req), `dst?`, `recursive?` | `{"op","src","dst","affected": n}` |
| `set_sensitivity` | `path` (req), `level` (req, enum normal/secret/secretfile) | `{"path","from","to"}` — raising only; downgrade → `SENSITIVITY_DOWNGRADE_FORBIDDEN` |
| `search_filenames` | `query` (req), `limit` (int, default 50) | `{"query","count","results":[…]}` |
| `search_text` | `query` (req), `limit` (int, default 50) | `{"query","count","results":[{logical_path,sensitivity,snippet,score}]}` |
| `search_semantic` | `query` (req), `limit` (int, default 50) | same shape as `search_text` |
| `read_folder_note` / `write_folder_note` | `path` (req) / `path` (req), `text` (req) | `{"path","note"}` / `{"path","updated": true}` |
| `request_open_secret` | `path` (req) | `{"request_id","status":"pending"\|"shown"\|"denied","note":"The user is asked to display it on their desktop; the content is never returned to the agent."}` |
| `get_access_log` | `limit` (int, default 100), `offset` (int, default 0), `source?` (enum ui/mcp/socket), `outcome?` (enum allow/deny/error) | `{"count","entries":[{ts,iso,source,role,tool,target_path,outcome,code,details}]}` |

Every successful `tools/call` result:
```json
{"content": [{"type": "text", "text": "<the JSON payload above, pretty-printed>"}],
 "structuredContent": <the payload object>,
 "isError": false}
```
Failures: `isError: true` **and** a JSON-RPC error? No — MCP convention: choose one. Decision:
tool-level failures return `{"content":[{"type":"text","text":"<code>: <message>"}],
"isError": true, "structuredContent": {"code": …, "message": …, "details": …}}` (no JSON-RPC
error), while protocol-level problems (unknown tool, bad params, parse error) use JSON-RPC
error codes (`-32602`, `-32601`, `-32700`). Document this in `docs/MCP.md`.

### 4.2 Resources

* `resources/list` → templates + a few concrete entries:
  `vault://status`, `vault://root` (top-level listing), `vault://recent` (last 20 files by mtime).
* `resources/templates/list` → `vault://folder/{path}`, `vault://note/{path}`,
  `vault://search?q={query}`, `vault://log?limit={n}`.
* `resources/read` → `{"contents":[{"uri","mimeType","text"}]}`; `mimeType`
  `application/json` for listings, `text/markdown` for notes when the logical path ends in
  `.md` (else `text/plain`). Reading a `secret`/`secretfile` note → JSON-RPC error `-32000`,
  `data.code = "PERMISSION_DENIED"`. URIs use percent-encoding for paths with spaces/Persian
  characters (decode with `urllib.parse.unquote`).
* `resources/subscribe` → `-32601` (not supported).

### 4.3 Bridge behaviour

* Every inbound request is forwarded as `VaultClient.call("vault." + mapped_method, params)`;
  the log therefore contains the MCP tool name.
* Daemon unavailable → `-32000` with `data.code = "VAULT_NOT_RUNNING"` (and the message telling
  the user to start the app). Locked → `-32000` with `data.code = "VAULT_LOCKED"` for
  content-dependent tools; `vault_status`, `get_access_log` and `search_filenames` still work
  while locked? Decision: while locked, `search_filenames` **is** allowed (names are metadata),
  `get_access_log` allowed, `vault_status` allowed; everything else → `VAULT_LOCKED`.
* `--debug` writes diagnostics to **stderr only** (stdout is the MCP channel; a stray print
  would break the protocol — never print to stdout).
* The bridge has a `--selftest` mode that runs an in-process fake daemon (used by
  `tools/smoke_mcp.py` and by the tests when no real daemon is available).

## 5. `vault/daemon.py` — headless entry point

```
python -m vault.daemon [--home PATH] [--unlock-file PATH] [--socket PATH] [--json-events] [--debug]
```
* Loads/creates the session for `--home` (default `SECURE_VAULT_HOME` or the config default
  from `~/.config/secure-vault/ui.json`'s `last_vault_home`, else `DEFAULT_VAULT_HOME`).
* `--unlock-file` reads the password from a file (mode must be 0600, else refuse) so tests can
  start an unlocked headless daemon without a GUI. Without it, the daemon runs **locked** and
  only metadata/status calls succeed (documented; it is also the mode used to prove the
  locked-mode guarantees in the smoke test).
* Emits `{"event": "...", ...}` JSON lines on stdout when `--json-events` is given (unused by
  the GUI; used by the tests to know when it is ready: `{"event":"ready","socket":...}`).
* Installs SIGTERM/SIGINT handlers → `session.close()` → exit 0.
* Prints nothing else on stdout. All logging goes to stderr and to
  `~/.local/state/secure-vault/daemon.log` (rotating, 1MB × 3).
