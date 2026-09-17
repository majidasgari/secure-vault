# Secure Vault — Security model

This is the honest security statement for the implementation in `src/vault`. It
describes what an attacker can and cannot learn, the exact sensitivity policy, what is
logged, and — just as important — what this design does **not** protect against.

## 1. Threat model

The primary adversary is someone who obtains the synced vault folder (a cloud account,
a stolen laptop backup, a shared drive) but does **not** have the master password and is
not running the unlocked app. A secondary adversary is an AI agent connected through the
MCP bridge: the design assumes agents are untrusted and must be prevented from reading
confidential content even while the app is unlocked.

The app is offline by design: it never sends content anywhere. The only network traffic
is `tools/bootstrap.sh` fetching dependencies/fonts and the Windows builder fetching the
embeddable interpreter — never at runtime.

## 2. The leak model (what is readable without the master password)

Readable **without** the password, by anyone who can read the vault folder:

* file and folder **names** (logical paths), sizes, mtimes, **sensitivity level**, tags;
* the **access log** (who/what/when/outcome);
* the KDF salt and parameters, and a password-verification **canary** (an encrypted known
  plaintext) — all in the plaintext `.vault-meta.json`.

Never readable without the password:

* every byte of file **content** (except files above the plain threshold, see §6);
* folder notes;
* the FTS content index and embedding vectors (they live inside `secure.store`).

This matches the original design (§12): *"in locked mode only metadata/names/level are
visible"*. The plaintext metadata DB exists so that locked-mode listing and filename
search keep working, which is a deliberate, documented trade-off.

**The no-plaintext rule:** no file content and no folder-note text may ever be written
into the vault home outside the encrypted `files/*.enc` blobs and `secure.store`. The
only plaintext files in the vault home are `.vault-meta.json` (KDF params + canary) and
`meta.sqlite` (names/levels/tags/log). The test suite enforces this by scanning the whole
vault home for known plaintext markers after writes.

## 3. Sensitivity matrix (the policy boundary)

`src/vault/core/security.py` is the single source of truth. Levels are ordered
`normal < secret < secretfile`.

| level | see name (any source) | MCP read content | UI read content | content search | MCP request-open | UI viewer |
|---|---|---|---|---|---|---|
| `normal` | yes | **yes** | yes (no confirmation) | yes | yes | markdown/web preview |
| `secret` | yes (+ label) | **no** | yes, **after a confirmation dialog + tray notification** | no | **no** | native viewer (via UI confirmation) |
| `secretfile` | yes (+ label) | **no** | **native plain-text viewer only**, confirmation required | no | **yes** (`request_open_secret`; the user sees it, the agent never does) | native viewer |

Additional rules enforced by the same module:

* **Raise is allowed, lower is not (for agents).** UI, MCP and the importer may raise a
  level; only the UI may lower one, and only to a *different* level. A same-level call is
  a no-op. An MCP downgrade raises `SENSITIVITY_DOWNGRADE_FORBIDDEN`.
* **Agents may not create secrets.** `write_file` from `mcp` with a non-`normal`
  sensitivity on a *new* path is denied. An agent may raise the level of an *existing*
  file (and then can no longer read it).
* **No content search for confidential files.** Only `normal` content is indexed for FTS
  and embeddings; hits are re-checked against the policy anyway (defence in depth).
* **Locked mode.** Even `normal` files cannot be read while locked, because the key is
  gone. Metadata, filename search, `vault_status` and `get_access_log` still work.

## 4. Cryptography

* Master key: 32 bytes derived from the password with **Argon2id** (default:
  `time_cost=3`, `memory_kib=262144`, `parallelism=4`) via `argon2-cffi`; a
  **PBKDF2-HMAC-SHA512** fallback (600 000 iterations) is used when argon2 is missing.
* Per-file key: HKDF-SHA256 over the master key with `info = b"secure-vault/file/" + blob_id`.
* Content: AES-256-GCM. The **AAD binds the blob id and the sensitivity level**, so a
  blob moved to another id/level fails authentication with `TamperDetected`. Every header
  bit is authenticated; any corruption, truncation or version mismatch is reported as
  `TamperDetected`, never as a raw exception.
* The KDF salt is stored in `.vault-meta.json`; each blob carries its own HKDF salt and
  nonce in its header. The content store is one blob with the fixed id `secure.store`.

## 5. Logging

**Logged** (append-only `access_log` in `meta.sqlite`): timestamp, `source`
(`ui`/`mcp`/`socket`), role, tool/method name, target path, outcome
(`allow`/`deny`/`error`), the error `code` when applicable, and a transport session id.
Every `Service.dispatch` call and every denied socket token attempt writes a row; the UI
also writes a dedicated `ui.read_secretfile` row when a secret file is shown.

**Never logged**: passwords, derived keys, tokens, file content, folder-note text, or any
decrypted data. Logging is best-effort and must never mask or change the outcome of an
operation. The headless daemon's rotating log file lives in
`~/.local/state/secure-vault/daemon.log`.

## 6. The 10 MB plain-storage decision (and its consequence)

Files **strictly larger** than `plain_threshold_bytes` (default `10 * 1024 * 1024`) are
written to `files/` **unencrypted** (they still carry the header with the plain flag and
are only readable through the unlocked session). This is the user's original decision
(`docs/DESIGN.md` §1, §3.2) to avoid expensive encryption of large binaries.

**Consequence:** any such file is readable in cleartext by anyone with access to the
synced folder. Do not place passwords or confidential notes in files larger than the
threshold; keep credentials in small `secretfile` files. The setting is visible in the
vault metadata and can be lowered, but already-written plain blobs stay plain until
rewritten.

## 7. Password handling

* The master password is never stored and is only used to derive the key.
* **There is no recovery.** Losing the password means losing all content permanently.
* The daemon and the importer read the password from a `0600` file (`--unlock-file`),
  never from argv or an echoed stdin, so it does not appear in the process list.
* The UI reads it from the keyboard only. Passwords/keys are never put in MCP messages,
  the socket protocol, or logs.
* On lock, the master key bytearray is zeroed (`util.wipe`).

## 8. Verifying integrity

The GUI's **Tools → Verify integrity** checks every blob by attempting to decrypt it and
reports `checked` and `bad`. The same check from a shell (scratch or real vault):

```bash
read -r -s -p "master password: " SV_PW; echo
SV_PW="$SV_PW" PYTHONPATH=src ./.venv/bin/python - <<'PY'
import os
from pathlib import Path
from vault.core.session import VaultSession

home = Path("/data/Cloud/SecureVault")          # change as needed
session = VaultSession(home)
session.unlock(os.environ["SV_PW"])
checked, bad = 0, []
for row in session.index.walk("/"):
    if row.get("blob_id"):
        checked += 1
        if not session.fs.verify_blob(row):
            bad.append(row["logical_path"])
session.close()
print(f"checked={checked} bad={bad}")
PY
```

A `TamperDetected` result means the ciphertext (or its header/level) changed; restore the
file from a backup rather than trusting it.

## 9. What this design does NOT protect against

* An attacker who controls the **unlocked** process or its memory (malware, a debugger,
  `ptrace`, a malicious plugin) — the key is in memory while unlocked.
* **Screen capture**, screenshots, a shoulder-surfer, or the OS **clipboard** after you
  copy from the secret viewer.
* A **keylogger** or a compromised OS/input stack; the password is typed.
* **Cloud-provider metadata**: names, folder structure, levels, tags, sizes, mtimes and
  the access log are not encrypted and leak a lot of information on their own.
* **Plain files above 10 MB** (see §6).
* An agent that convinces **you** to approve a `request_open_secret` or to lower a level.
* A weak master password: Argon2id slows guessing but cannot save a guessable password.
* Simultaneous edits from two machines on the same synced folder (see `docs/SYNC.md`).
* Traffic/timing analysis of the sync client; the app itself makes no network calls.

## 10. The web UI (`python -m vault.web`)

The browser UI runs in a process that owns the `VaultSession` — the web process is
the key holder, exactly like the GUI — and exposes an HTTP JSON API plus an SSE
stream. Its security contract:

* **Token auth.** A random 32-byte token is generated at startup, written to
  `runtime_dir()/web.token` (mode `0600`) and printed once to stderr. Every
  `/api/*` request must carry it in the `X-Vault-Token` header; the `vault_token`
  cookie set by `GET /?token=…` is `HttpOnly; SameSite=Strict` and is **never**
  accepted as authorisation (CSRF defence). Static files (`/`, `/static/*`) need no
  token because they contain no vault data.
* **No key exposure.** The master password is typed in the browser, verified
  in-process, and never stored, echoed or logged. Decrypted content stays in the
  daemon process except for the specific file the user opened; the browser holds it
  only in the DOM (never `localStorage`, never the URL) and clears it on lock.
* **Same sensitivity rules as the desktop UI.** `secret` files get a confirmation
  and a disabled markdown preview; `secretfile` content is rendered as plain text
  only and `GET /api/blob` returns `403` for it. `vault.read_secret` is not exposed
  to the browser at all.
* **Throttling.** Wrong passwords are answered with `401 bad_password`, a `deny`
  row in the access log (`source="web"`) and an in-memory per-IP delay (5 s ×
  failures past the fifth, capped at 60 s). The counter is never persisted.
* **No store.** All `/api/*` responses are `Cache-Control: no-store`; the SPA has
  no external references and works fully offline.
* **Loopback by default.** A non-loopback `--host` is refused unless `--allow-lan`
  is passed; the server then warns that the token is the only protection.

The token is only as safe as the machine: any process running as your user can read
`web.token`, and anyone with the token **and** the password can read the vault.
Exposing the server beyond loopback over plain HTTP also exposes the token to
network sniffers — use a TLS reverse proxy if you need that. See `docs/WEBUI.md`.
