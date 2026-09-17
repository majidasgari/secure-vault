# SPEC 06 — Tests, smoke tests, and what the human must verify

Everything here must be runnable with `./.venv/bin/python` and **no network**.

## 1. Runner

`tests/run_tests.py` — stdlib `unittest` discovery over `tests/test_*.py`, `-v` by default,
non-zero exit on failure, `--only <pattern>` to filter, prints a final summary table
(`suite | tests | failures | errors | time`). Puts `src/` and the repo root on `sys.path`.

Every suite uses `tests/support.py`:

```python
def tmp_vault(tmpdir=None, *, password="correct horse battery staple", settings=None) -> VaultSession
def scratch_home(tmpdir) -> Path                     # temp dir, never the user's vault home
def fake_daemon(session) -> FakeDaemon               # in-process socket server with known tokens
def mcp_stdio(env_overrides) -> MCPProcess           # context manager spawning python -m vault.mcp
def assert_no_plaintext(root: Path, needles: list[bytes])   # scans every file under root
def assert_under(path, root)                         # guards against writing outside tmp
```

`tests/` must never touch `/data/Cloud/SecureVault` or the real mirror except in the one
read-only importer test that is explicitly opt-in (`SECURE_VAULT_REAL_MIRROR=1`).

## 2. Suites (each file = one suite; the listed assertions are the minimum)

### `test_crypto.py`
round-trip (sizes 0, 1, 1 KB, 5 MB synthetic) · wrong password → `Unauthorized`/`TamperDetected` ·
bit-flip anywhere in the header or ciphertext → `TamperDetected` · `blob_id` mismatch →
`TamperDetected` · `sensitivity` mismatch → `TamperDetected` (the AAD binding) · plain blobs
carry the header and round-trip · truncated/garbage input → `TamperDetected`, never a raw
exception · canary verify accepts the right password and rejects a wrong one without raising ·
`new_kdf_params()` uses `argon2id` when importable and the PBKDF2 path also round-trips
(monkeypatch `available_kdf()`) · derived keys for two different salts differ · HKDF per-file
keys differ per blob id · `wipe()` zeroes a bytearray.

### `test_meta.py`
create/load `VaultMeta` · atomic save leaves no `.tmp` · `schema_version` bump to 2 → `BadRequest`
· missing/invalid file → `NotFound` · settings mutation + save persists · canary present and the
right length.

### `test_index.py`
schema creation is idempotent (open twice) · `upsert_file`/`get_file`/`require_file` ·
`delete_file` recursive removes children and returns them · `list_dir` ordering (dirs first,
then case-insensitive name) · `move` rewrites descendant paths · tags set/get/`files_by_tag`/
`all_tags` · access log append-only + filters + CSV export · kv get/set · a row with
`logical_path='a/../b'` is rejected (it must go through `normalize_logical_path`) ·
`list_dir` of `"/"` and of a missing dir (`NotFound`).

### `test_vaultfs.py`
write/read/update/delete · updating content replaces the blob and the old blob file is gone ·
`gc_orphans` counts and deletes exactly the unreferenced blobs · a blob larger than a patched
`plain_threshold` is stored with the plain flag and `encrypted=0` in the DB · reading a plain
blob of a **locked** session fails with `VaultLocked` · `verify_blob` detects a corrupted blob.

### `test_security.py`
the full matrix from SPEC/01 §9 driven as a table: for each `(level, source)` pair assert
`can_see_name`, `can_read_content`, `can_search_content`, `can_request_open_secret` — plus the
raise/lower rules (`ui` may lower, `mcp` may not, same-level is a no-op for both).

### `test_session.py`
`create` → `unlock` → `lock` → `unlock` cycle · wrong password → `Unauthorized("bad_password")` ·
methods called while locked raise `VaultLocked` · `list_folder` works while locked (metadata) but
`read_text` does not · write/read/move/copy/delete/mkdir/tags/folder notes · a new file from
source `mcp` with `sensitivity="secret"` → `PermissionDenied`; creating a `normal` file from
`mcp` is allowed; raising to `secret` from `mcp` is allowed; lowering from `mcp` →
`DowngradeForbidden` · reading a `secret` file from `mcp` → `PermissionDenied` **and** an access
log row with `outcome="deny"`, `code="PERMISSION_DENIED"` · `request_open_secret` from `mcp` on a
`secretfile` returns `pending` and calls the registered callback, on a `secret` raises
`PermissionDenied` · `auto_lock_due()` with a patched clock · `stats()`/`status()` · large file
(11 MB of zeros, patched threshold to 1 MB) is stored plain and `assert_no_plaintext` on the
encrypted store still holds for the *content* of an encrypted file · **no plaintext leakage**:
after writing a note with the marker `TOP-SECRET-MARKER`, `assert_no_plaintext(home, [marker])`
passes for every file under the vault home except a plain-threshold file.

### `test_store.py`
unlock creates the decrypted store under the runtime dir (mode 0600) and lock removes it ·
`secure.store` never contains the note text or the folder note text (byte scan) ·
`store.dec` never exists inside the vault home · FTS indexing + search ordering (bm25) ·
`normalize_fa` cases (ی/ي, ک/ك, digits, diacritics, ZWNJ preserved) applied on both sides —
a query with `ي` finds a note written with `ی` and vice versa · removing a file removes its FTS
rows and vectors · `stats()` counts · flush-after-write survives a simulated crash (open a
second store instance from the file and see the data) · folder notes round-trip with Persian text.

### `test_search.py`
the three kinds are independent: a note whose **filename** matches but body does not appears only
in filename results; a `secret` note appears in filename results but never in text/semantic
results; empty query → `BadRequest`; limit respected; snippet ≤ 240 chars and contains the query
token; semantic with `StubProvider` returns similarity-ordered results; semantic without a
provider → `ProviderUnavailable`.

### `test_api_service.py`
`Service.dispatch` routing for every method (>30 cases, table-driven) · role enforcement
(`vault.read_secret` with `role="mcp"` → `PermissionDenied`; `vault.unlock` from `mcp` →
`PermissionDenied`) · unknown method → `BadRequest("unknown_method")` · the access log gets one
row per dispatch with the right `source`/`tool`/`outcome`.

### `test_api_socket.py`
start the server on a temp socket (`fake_daemon`) · `vault.ping` without a token →
`UNAUTHORIZED` · wrong token → `UNAUTHORIZED` + a deny row · the `mcp` token can call
`vault.list_folder` but not `vault.unlock`/`vault.read_secret` · malformed JSON line →
`BAD_REQUEST` with `id=null` · two pipelined requests get two in-order responses · a client that
disconnects mid-line does not kill the server (a following request still succeeds) ·
`VaultClient.from_runtime` reads the token and `call` maps error codes to the right exception
classes · connection-refused → `VaultNotRunning`.

### `test_mcp_protocol.py`
spawn the real `python -m vault.mcp` against a `FakeDaemon` (a scratch vault + socket server):
`initialize` handshake echoes a supported protocol version and lists the 3 capabilities ·
`notifications/initialized` produces no response · `ping` → `{}` · `tools/list` returns exactly
the 14 tools from SPEC/02 §4.1 with the documented required params · `tools/call` for
`vault_status`, `list_folder`, `read_file`, `write_file`, `search_filenames`, `write_folder_note`,
`get_access_log` succeed with the documented payload shapes · `read_file` on a `secret` file →
`isError: true`, `structuredContent.code == "PERMISSION_DENIED"` · `set_sensitivity` downgrade →
`SENSITIVITY_DOWNGRADE_FORBIDDEN` · `request_open_secret` returns `pending` and the content never
appears in any response · unknown tool → `-32602` with a clear message · unknown method →
`-32601` · invalid JSON line → `-32700` · `resources/templates/list` returns the 4 templates ·
`resources/read` of `vault://status` and of `vault://note/<path>` works, of a `secret` note →
`-32000`/`PERMISSION_DENIED` · a stray write to **stdout** by a logging call is impossible
(assert every stdout line parses as JSON) · the daemon being down → `VAULT_NOT_RUNNING`.

### `test_importers.py`
build a tiny mirror fixture in a temp dir (`_meta/index.json` with 2 notebooks, 3 notes, 1 tag,
1 asset with a `:/<id>` reference, an `_index.md`, a stray `idea.md` and a skipped `README.md`)
· dry run writes nothing (hash the whole vault before/after) · real run: counts, folder
structure, tags, frontmatter stripped from the body, `<assets>` import + link rewrite to
`vault:/attachments/…`, stray imported, `_index.md`/`README.md` skipped · a second run is a
no-op (`notes_skipped == 3`, nothing updated) · touching a note's `updated` in the fixture
updates the vault file · `--mark-secret '*idea*'` imports that note as `secret` with content
search excluded · an untracked file at a colliding path is renamed, never overwritten ·
a note referencing a missing resource does not fail the run (counted in `unresolved_refs`) ·
the mirror is never modified (compare mtimes/hashes before/after) · `--home` inside the mirror →
refused.

### `test_i18n.py`
`fa.json` and `en.json` have identical key sets (report the diff) · no empty values · every
`tr("…")` key used in `vault/ui/**` and `vault/api/**` exists in both catalogues (regex scan) ·
every `error.<CODE>` key exists for all `VaultError.code` values · missing key renders
`⟦key⟧` and never raises · `set_language` flips `Translator.lang` and notifies callbacks ·
one representative widget retranslates on `set_language` (offscreen).

### `test_ui_smoke.py` (`QT_QPA_PLATFORM=offscreen`, skipped with a clear message if PySide6
   is missing)
import the package · build the app with `--self-test` against a scratch vault: create → unlock →
main window constructed → tree has the expected folders → open a note in the editor →
`editor.preview_enabled is True` for `normal` and **False** after the file becomes `secret`
(and the confirmation hook is stubbed to approve) → the native viewer path for a `secretfile`
(`viewer.last_text` equals the content, and no `QWebEngineView` was created for it) →
`search_panel` returns results for all three kinds (semantic via `StubProvider`) →
`log_panel.row_count()` grows after an action → `i18n.set_language("en")` changes a known label
and back to `fa` sets `Qt.RightToLeft` · the settings dialog opens/closes without touching a real
vault path · locking returns the app to the unlock screen · no exception reaches the Qt message
handler (install a handler that records and assert it stayed empty).

### `test_paths_and_config.py`
`normalize_logical_path` rejections/acceptations (absolute, `..`, control chars, NUL, long paths,
backslashes, Unicode NFC) · `atomic_write_bytes` leaves no tmp · `user_config` round-trip keeps
unknown keys · `runtime_dir()` honours `XDG_RUNTIME_DIR` and creates it 0700 · `DEFAULT_VAULT_HOME`
and the settings default agree with the SPEC.

## 3. Smoke scripts (not unittest — they print `PASS`/`FAIL` per step and exit non-zero on failure)

* `tools/smoke_e2e.py` — scratch vault: create → unlock → write 3 notes (one Persian, one with
  an attachment-sized body, one marked `secret`) → search all three kinds → mark `secretfile` →
  `request_open_secret` → lock → prove content is unreachable → unlock → content intact →
  `verify_blobs` → print the vault tree and the access log summary.
* `tools/smoke_mcp.py` — start `python -m vault.daemon --unlock-file …` on a scratch vault, then
  drive `python -m vault.mcp` over real stdio: handshake, `tools/list`, `list_folder`,
  `read_file`, `write_file` + read-back, `set_sensitivity secret`, denied `read_file`,
  `search_filenames`, `resources/read` of `vault://status`, `request_open_secret`, then SIGTERM
  the daemon and assert `VAULT_NOT_RUNNING`. This is the **acceptance test for the agent-facing
  contract** and must pass before the task is reported done.
* `tools/smoke_import_real.sh` — the real-mirror run (SPEC/04 §7): reads the mirror read-only,
  imports into a scratch vault, and writes the report; must be run once by the agent with
  `--dry-run` **and** once for real, both green.

## 4. What the agent runs before reporting done

```
./.venv/bin/python tests/run_tests.py                 # all suites green
QT_QPA_PLATFORM=offscreen ./.venv/bin/python tests/test_ui_smoke.py
./.venv/bin/python tools/smoke_e2e.py
./.venv/bin/python tools/smoke_mcp.py
./.venv/bin/python tools/import_joplin.py --dry-run … # real mirror, scratch vault
./.venv/bin/python tools/import_joplin.py …           # real mirror, scratch vault, real run
./.venv/bin/python tools/build_windows_portable.py --check
```
The exact commands and their real output go into `docs/TESTING.md` (no invented output).

## 5. What the **user** must verify manually (leave this list in the hand-off message and in
   `docs/TESTING.md`)

1. First-run wizard + choosing his real vault home (`/data/Cloud/SecureVault`) and his own
   master password (the agent must never create the real vault or store a password).
2. The GUI on a real screen: fonts/RTL in Persian, icon in the KDE menu/taskbar, tray menu,
   desktop notifications, the secret-request popup arriving while the window is in the tray.
3. Opening a big real note in the markdown preview; editing + saving; sync behaviour with his
   cloud folder.
4. The importer against the real mirror **into his real vault** (after creating it).
5. Registering/enabling the MCP server in Hermes and asking an agent to list/search the vault.
6. Reading a `secretfile` in the native viewer and confirming an agent cannot obtain it.
