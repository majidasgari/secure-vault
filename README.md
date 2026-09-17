# Secure Vault — گاوصندوق

**گاوصندوق** یک برنامه‌ی شخصیِ رمزنگاری‌شده برای یادداشت‌ها و گذرواژه‌هاست که جای
Joplin و KeePass را می‌گیرد و «ایجنت‌آگاه» است: ایجنت‌ها از طریق MCP به آن دسترسی
دارند، اما محتوای فایل‌های *محرمانه* و *رمز* هرگز به آن‌ها داده نمی‌شود — فقط نام‌ها،
ساختار و سطح حساسیت قابل‌دیدن است و همه‌ی دسترسی‌ها در یک لاگ فقط‌الحاقی ثبت می‌شوند.
برای شروع سریع:

```bash
tools/bootstrap.sh
./bin/secure-vault          # روی این ماشین: QT_QPA_PLATFORM=offscreen ./bin/secure-vault --self-test
```

> **مهم:** گذرواژه‌ی اصلی ذخیره نمی‌شود و هیچ راهی برای بازیابی آن وجود ندارد.

---

## What it is

Secure Vault is a personal, offline-first encrypted vault with a Qt (PySide6) desktop
GUI. It stores notes and secrets as AES-256-GCM blobs in a single folder you can sync
with any cloud drive, keeps a plaintext metadata index (names, levels, tags, access
log) so locked-mode listing still works, and exposes an MCP server so agents can see
the structure and read `normal` files while `secret`/`secretfile` content stays
hidden. It is the final replacement for Joplin, with a deliberately tiny dependency
set: Python, PySide6, `cryptography`, `argon2-cffi`, `markdown-it-py` and Pygments.

## Status

* Core, socket API, MCP bridge, Qt UI, Joplin importer, desktop integration and the
  Windows portable **builder** are implemented; the 200-case test suite is green.
* The GUI has **not** been verified on a real screen yet — only headless/offscreen.
  Fonts, RTL, tray, notifications and the KDE menu icon must be checked by hand.
* The Windows portable build is **produced but not verified on Windows** (see
  `docs/WINDOWS.md`).
* Semantic search is opt-in and needs the extra in `requirements-semantic.txt`
  (`sentence-transformers`); it is never installed by `bootstrap.sh`.

## Install

Requires Python ≥ 3.11. On the target machine the venv already exists; on a fresh
checkout:

```bash
tools/bootstrap.sh
```

This creates `.venv`, writes `.venv/pip.conf` pointing at the local PyPI mirror
(`https://mirror-pypi.runflare.com/simple/`), installs `requirements.txt`, downloads
the optional Vazirmatn fonts (a failure is only a warning), and prints the next
commands. It is idempotent. Use `--skip-deps` when the dependencies are already
installed and `--desktop` to also install the desktop entry.

## First run

```bash
./bin/secure-vault
```

1. The first-run wizard asks for the vault home folder (default
   `/data/Cloud/SecureVault`, changeable in Settings) and a master password.
2. It can create the recommended top-level folders (`notes/`, `journal/`, `secrets/`,
   `attachments/`).
3. **There is no password recovery.** If you forget the master password the content is
   permanently unreadable — the key is derived from it and never stored.

Headless/offscreen check (used by CI and this repo's tests):

```bash
QT_QPA_PLATFORM=offscreen ./bin/secure-vault --self-test
# or, without the launcher:
QT_QPA_PLATFORM=offscreen PYTHONPATH=src ./.venv/bin/python -m vault --self-test
```

## Quick tour

* **Browser** (left dock): a tree of folders/files with a sensitivity label per entry.
* **Editor**: markdown source with a live preview for `normal` files. For `secret`
  files the preview is disabled; `secretfile` files never reach the editor at all.
* **Sensitivity levels**: right-click a file → *Set level* → `normal`, `secret` or
  `secretfile`. Lowering requires confirmation and is only possible from the UI.
* **Secret viewer**: a native plain-text window (no web engine) for `secretfile`
  content, so it cannot leak into the markdown renderer.
* **Search** (right dock): three separate searches — filenames, literal content
  (FTS5) and semantic (opt-in) — never hybridized.
* **Log panel** (right dock): the append-only access log; every agent call is there.
* **Tray**: lock, show, search and settings; `secret` opens raise a desktop
  notification, and an agent `request_open_secret` pops a dialog on your desktop.

## Giving agents access (MCP)

The MCP bridge is `bin/secure-vault-mcp`. It is a stateless stdio process that
forwards JSON-RPC to the running app over the local Unix socket with the `mcp` role
token. The app must be running and unlocked; otherwise tools return
`VAULT_NOT_RUNNING` / `VAULT_LOCKED`.

Register it with Hermes (the `mcp_servers` map):

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

Or with the CLI:

```bash
hermes config set mcp_servers.secure-vault.command "/data/Codes/secure-vault/bin/secure-vault-mcp"
hermes config set mcp_servers.secure-vault.args "[]"
```

Some clients spell the key `mcpServers`; use whichever your Hermes version expects.
Set `SECURE_VAULT_DEBUG=1` in the server environment for diagnostics on stderr
(stdout stays pure JSON-RPC).

What agents can do: list names/structure, read/write `normal` files, search filenames,
search the content of `normal` files, read/write folder notes, **raise** a level
(never lower), and ask you to display a `secretfile`. What they can **never** do:
read `secret`/`secretfile` content, search it, lower a level, or receive the content
of a `request_open_secret` call. See `docs/MCP.md` for the full tool reference.

## Importing from Joplin

The importer reads the existing markdown mirror **read-only** and writes into a vault:

```bash
printf '%s' 'your-master-password' > /tmp/sv.pw && chmod 600 /tmp/sv.pw
./.venv/bin/python tools/import_joplin.py \
    --home /tmp/scratch-vault --unlock-file /tmp/sv.pw --dry-run
./.venv/bin/python tools/import_joplin.py \
    --home /tmp/scratch-vault --unlock-file /tmp/sv.pw \
    --report docs/reports/joplin-real.md
```

It is idempotent (a second run is a no-op), rewrites `:/<id>` resource references to
`vault:/attachments/<file>` links, and never modifies the mirror. KeePass is an
explicit non-goal: passwords belong in `secretfile` files. See
`docs/IMPORT_JOPLIN.md`.

## Syncing

Sync the **whole vault home** (the encrypted `files/`, `secure.store` and the
plaintext `meta.sqlite`) with Dropbox/OneDrive/Google Drive. Never sync the runtime
directory (`$XDG_RUNTIME_DIR/secure-vault`, which holds `store.*.dec`, the socket and
the token). Do not run two daemons against the same synced folder on two machines.
See `docs/SYNC.md`.

## Security notes

Names, sizes, mtimes, sensitivity levels, tags and the access log are readable
without the password (they live in the plaintext `meta.sqlite`). File content, folder
notes, the FTS index and embeddings are never readable without the password. Files
strictly larger than 10 MB are stored **unencrypted** (a deliberate user decision);
keep secrets in small files. The master password is never stored. See
`docs/SECURITY.md` for the full threat model and the sensitivity matrix.

## Tests

Everything runs offline with the stdlib `unittest` runner:

```bash
./.venv/bin/python tests/run_tests.py                              # 200 cases
./.venv/bin/python tests/run_tests.py --only test_session          # one suite
QT_QPA_PLATFORM=offscreen ./.venv/bin/python tests/test_ui_smoke.py
./.venv/bin/python tools/smoke_e2e.py
./.venv/bin/python tools/smoke_mcp.py
./.venv/bin/python tools/build_windows_portable.py --check         # prints CHECK OK
```

The Joplin real-mirror run is opt-in and read-only (see `docs/TESTING.md`). See that
file for the scratch-vault recipe and the list of things you must verify by hand.

## Repository layout

```
secure-vault/
├── bin/                 secure-vault, secure-vault-mcp launchers
├── assets/              icon.svg + Vazirmatn fonts
├── i18n/                fa.json, en.json UI catalogues
├── src/vault/           the package (core, api, ui, importers)
├── tests/               unittest suites + run_tests.py
├── tools/               bootstrap, desktop install, importer CLI, smoke scripts, Windows builder
├── docs/                ARCHITECTURE, SECURITY, MCP, SYNC, IMPORT_JOPLIN, WINDOWS, TESTING
└── portable/win/        output of the Windows builder (git-ignored)
```

## Licence

GPL-3.0-only. See `LICENSE`.
