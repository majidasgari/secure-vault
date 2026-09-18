# Secure Vault — MCP interface

Secure Vault exposes an MCP server over **stdio** so agents (Hermes, Claude, …) can see
the vault's structure, read and write `normal` files, and ask the user to display a
`secretfile`. Confidential content is never returned to the agent.

## 1. Registration with Hermes

The bridge is `bin/secure-vault-mcp`. Use an **absolute** path; the agent runtime may
have a different working directory. The app must be running and unlocked for content
tools to work.

`mcp_servers` JSON configuration:

```json
{
  "mcp_servers": {
    "secure-vault": {
      "command": "/data/Codes/secure-vault/bin/secure-vault-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

Equivalent CLI form:

```bash
hermes config set mcp_servers.secure-vault.command "/data/Codes/secure-vault/bin/secure-vault-mcp"
hermes config set mcp_servers.secure-vault.args "[]"
```

Some Hermes versions spell the key `mcpServers`; use whichever your version expects. The
`bin/secure-vault-mcp` launcher execs `python -m vault.mcp` without touching stdout, so
it is safe as a stdio server. Set `SECURE_VAULT_DEBUG=1` in `env` to pass `--debug`
(diagnostics go to stderr; stdout stays pure JSON-RPC).

## 2. Handshake and protocol

* Transport: JSON-RPC 2.0, one object per line. The server accepts both newline-delimited
  JSON and LSP-style `Content-Length` framing, and always **emits** newline-delimited
  JSON. Nothing but protocol JSON is ever written to stdout.
* `initialize` negotiates one of `2024-11-05`, `2025-03-26`, `2025-06-18` (default
  `2025-06-18`) and returns capabilities `{tools, resources, prompts}`, `serverInfo`
  `{name: "secure-vault", version: …}` and usage instructions.
* `notifications/initialized` (and any notification) produces **no** response.
* `ping` → `{}`.
* `prompts/list` → `{"prompts": []}`; `logging/setLevel` → `{}`;
  `resources/subscribe` → JSON-RPC `-32601` (not supported).

## 3. Error conventions

There are two distinct failure channels:

* **Protocol-level errors** use JSON-RPC `error` codes and no `result`:
  * `-32700` parse error (invalid JSON line);
  * `-32601` unknown method;
  * `-32602` unknown tool or missing required arguments;
  * `-32000` server error — used for `VAULT_NOT_RUNNING` and `VAULT_LOCKED`, with
    `data = {"code", "message", "details"}`.
* **Tool-level failures** return a normal `tools/call` result with `isError: true`:

  ```json
  {
    "content": [{"type": "text", "text": "PERMISSION_DENIED: content_forbidden"}],
    "isError": true,
    "structuredContent": {"code": "PERMISSION_DENIED", "message": "…", "details": {}}
  }
  ```

  This is used for policy failures such as `PERMISSION_DENIED`,
  `SENSITIVITY_DOWNGRADE_FORBIDDEN`, `NOT_FOUND`, `BAD_REQUEST`, etc.

A successful `tools/call` result is:

```json
{"content": [{"type": "text", "text": "<pretty JSON payload>"}],
 "structuredContent": <the payload object>,
 "isError": false}
```

## 4. Tools

All tools accept a JSON object and return an object. Paths use the vault-absolute form
(`/notes/a.md`); the server normalizes them.

| tool | parameters | result |
|---|---|---|
| `vault_status` | — | `{"locked","home","files","folders","by_level","semantic","auto_lock_seconds","store","daemon":{"running":true}}` |
| `list_folder` | `path` (default `/`) | `{"path","note","entries":[{name,path,is_dir,size,mtime,sensitivity,tags,note,secret}]}` |
| `digest` | `path` (default `/`), `depth` (default 1) | one overview: `{name,path,is_dir,note,entries:[{name,path,size,sensitivity,tags,note,first_line}]}` (recursive to `depth`); replaces N+1 list/read calls |
| `read_file` | `path` (req), `encoding` (default `utf-8`) | `{"path","content","sensitivity","size","note"}` |
| `read_lines` | `path` (req), `start` (1-based, default 1), `count` (default 200) | `{"path","start","count","text","total_lines"}` |
| `write_file` | `path` (req), `content` (req), `encoding`, `sensitivity` (`normal`/`secret`/`secretfile`) | `{"path","size","sensitivity","created"}` |
| `write_lines` | `path` (req), `text` (req), `mode` (`append`/`prepend`/`insert`), `at_line` | `{"path","size","lines"}` |
| `mkdir` | `path` (req) | `{"path","created":true}` |
| `file_ops` | `op` (`move`/`copy`/`delete`/`mkdir`), `src` (req), `dst`, `recursive` | `{"op","src","dst","affected"}` |
| `set_sensitivity` | `path` (req), `level` (req) | `{"path","from","to"}` — agents may only raise; lowering → `SENSITIVITY_DOWNGRADE_FORBIDDEN` |
| `search_filenames` | `query` (req), `limit` (default 50), `path_prefix` | `{"query","count","results":[{"logical_path","is_dir","sensitivity","size","mtime","match"}]}` |
| `search_text` | `query` (req), `limit` (default 50), `path_prefix` | same shape plus `snippet` (≤240 chars), `score`, `line` and `offset` (jump straight to the match with `read_lines`); `normal` files only |
| `search_semantic` | `query` (req), `limit` (default 50), `path_prefix` | same as `search_text`; needs an embedding provider |
| `read_folder_note` | `path` (req) | `{"path","note"}` |
| `write_folder_note` | `path` (req), `text` (req) | `{"path","updated":true}` |
| `read_file_note` | `path` (req) | `{"path","note"}` |
| `write_file_note` | `path` (req), `text` (req) | `{"path","updated":true}` |
| `all_tags` | — | `{"tags":[{name,count}]}` (metadata) |
| `files_by_tag` | `tag` (req) | `{"tag","count","results":[…]}` (metadata) |
| `semantic_status` | — | `{"semantic":{enabled,available,reason,model,chunking,chunks,indexed_files,db_path}}` |
| `semantic_reindex` | `path` (optional subtree), `force` (default true) | `{"indexed","skipped","chunks"}` — re-embed all or just one subtree |
| `request_open_secret` | `path` (req) | `{"request_id","status":"pending","note":"…"}` — `secretfile` only; content is never returned |
| `get_access_log` | `limit` (default 100), `offset`, `source` (`ui`/`mcp`/`socket`), `outcome` (`allow`/`deny`/`error`) | `{"count","entries":[{ts,iso,source,role,tool,target_path,outcome,code,details,session}]}` |

Agent-facing rules:

* `read_file`/`read_lines`/`search_text`/`search_semantic` never return `secret` or
  `secretfile` content.
* `write_file`/`write_lines` may create only `normal` files; raising an existing file's
  level is allowed (after which the agent can no longer read it).
* `request_open_secret` works only for `secretfile`; the user sees a desktop dialog and
  the native viewer, and the agent gets `{"status":"pending"}` with no content.
* `search_filenames` sees names of **all** levels (names are metadata).
* `search_filenames`/`search_text`/`search_semantic` accept `path_prefix` to scope the
  search to one folder subtree — cheaper and immune to a huge folder crowding out a small
  one.
* `read_file_note`/`write_file_note`/`digest` expose the short per-file notes and a folder
  overview; notes are user-authored metadata (both roles), file content never is.

## 5. Resources

`resources/list` advertises concrete resources:

* `vault://status` — the status payload (`application/json`).
* `vault://root` — top-level listing (`application/json`).
* `vault://recent` — the 20 most recently modified files (`application/json`).

`resources/templates/list` advertises:

* `vault://folder/{path}` — folder listing;
* `vault://note/{path}` — note content (`text/markdown` for `.md`, else `text/plain`);
* `vault://search?q={query}` — literal content search;
* `vault://log?limit={n}` — access log.

`resources/read` returns `{"contents":[{"uri","mimeType","text"}]}`. Paths are
percent-encoded in the URI and decoded with `urllib.parse.unquote`. Reading a
`secret`/`secretfile` note returns JSON-RPC `-32000` with `data.code =
"PERMISSION_DENIED"`. `resources/subscribe` is not supported (`-32601`).

## 6. Locked-mode behaviour

When the vault is locked (or the daemon is not running):

| works while locked | fails while locked |
|---|---|
| `vault_status`, `list_folder`, `search_filenames`, `all_tags`, `files_by_tag`, `semantic_status`, `get_access_log`, `resources/read` of `vault://status` | every content tool, `read_folder_note`, `read_file_note`, `digest`, `request_open_secret`, `resources/read` of a note |

Failure is `-32000` with `data.code = "VAULT_LOCKED"` when locked, or `-32000` with
`data.code = "VAULT_NOT_RUNNING"` when no app is running. The bridge never starts the
GUI automatically.

## 7. Manual smoke check

The repository ships an acceptance test that drives the real bridge over real stdio
against a scratch vault:

```bash
./.venv/bin/python tools/smoke_mcp.py
```

For an in-process fake daemon (no running app), the bridge also supports:

```bash
printf '' | ./bin/secure-vault-mcp --selftest
```
