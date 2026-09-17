# SPEC 00 — Secure Vault: overview, locked decisions, environment

> Read this file first. It overrides nothing in `SPEC/01..06`; those files are the detailed
> contracts. Where this file and a later one disagree, the later one wins (they are written
> to be consistent; if you find a contradiction, follow the more specific file and note it in
> your final report).

## 1. What we are building

**Secure Vault** — a personal, encrypted vault with a desktop GUI that replaces **Joplin**
(notes / markdown knowledge base) *and* **KeePass** (passwords / secrets) in one place, and is
**agent-aware**: agents reach the vault through an MCP server, and the vault can *withhold*
content from them while still letting them see names, structure and search filenames.

The authoritative product design is `docs/DESIGN.md` (Persian, 349 lines — it is the original
design document written with the user). `SPEC/01..06` are the implementation contracts that
refine it. If `docs/DESIGN.md` and a SPEC file disagree, follow the SPEC file.

One-line summary (from the design): *a personal encrypted vault with a GUI that manages all
agent access (via MCP) and the user's daily work (via a local API + UI); the most confidential
files are hidden from the agent or only "requestable for display"; everything is traceable
(full access log). It is the final replacement for Joplin.*

## 2. Environment (verified on the target machine — do not assume otherwise)

| fact | value |
|---|---|
| OS | Ubuntu 26.04.1 LTS, KDE Plasma, Wayland (user `maxv`) |
| System python | `/usr/bin/python3` = 3.14.4 (apt-managed; do **not** install into it) |
| Project venv | `/data/Codes/secure-vault/.venv` (created with `/usr/bin/python3 -m venv`) |
| PyPI | `pypi.org` is **unreachable**; use the mirror index already configured in `.venv/pip.conf`: `https://mirror-pypi.runflare.com/simple/` |
| GUI toolkit | **PySide6** (pip, in the venv; includes QtWebEngine + QtNetwork) |
| Crypto | `cryptography` (AES-256-GCM, HKDF) — available |
| KDF | **Argon2id via `argon2-cffi`** (available in the venv) with a PBKDF2-HMAC-SHA512 fallback |
| Tests | **stdlib `unittest`** (no pytest dependency); runner = `tests/run_tests.py` |
| No sudo | The session has no passwordless sudo — never call apt/sudo |
| Never | no network access at runtime (the app must work fully offline) |

The app must keep working when PyPI and the network are down. Runtime dependencies are only
what `requirements.txt` lists; the app must never import anything else at runtime.

## 3. Locked decisions (do not re-litigate these)

1. **Language / stack**: Python 3.11+ (target the venv's 3.14), Qt via **PySide6**. No web
   server framework, no ORM, no JSON-schema library — stdlib + PySide6 + `cryptography` +
   `argon2-cffi` + `markdown-it-py` only.
2. **Storage**: SQLite (one plaintext **metadata** DB, one **encrypted** content store blob)
   + a blob directory of AES-256-GCM files. Details in `SPEC/01`.
3. **Vault home (the user's data)**: default `/data/Cloud/SecureVault` (a cloud-synced
   directory), *configurable from Settings*. Nothing plaintext-secret may live there except
   the documented metadata DB (§4 below).
4. **Runtime scratch** (decrypted store, socket, token, pid) lives **outside** the vault home,
   in `$XDG_RUNTIME_DIR/secure-vault/` (fallback `/tmp/secure-vault-$UID/`), mode `0700`.
   Nothing from the runtime dir may ever be written into the vault home.
5. **Single key holder**: the GUI process *is* the daemon. It owns the master key and the
   session. External agents (the MCP bridge process) talk to it over a **Unix socket** with a
   token whose **role is `mcp`**; the role is bound to the token, never claimed by the client.
   The UI does not go through the socket — it calls the same service layer in-process.
6. **Three sensitivity levels**, exactly as `docs/DESIGN.md` §4: `normal`, `secret`,
   `secretfile`. Ordering `normal < secret < secretfile`. MCP may only raise, never lower.
7. **Three separate searches, never hybridized**: filenames (all files), literal content
   (FTS5, `normal` files only), semantic (opt-in local embeddings, `normal` files only).
8. **Importers**: Joplin first, from the existing markdown mirror
   `/data/Cloud/Documents/Notes/joplin-mirror` (see `SPEC/04`). **No KeePass/kdbx importer**
   (decided by the user in the original design): password material is stored as `secretfile`
   files, one file per credential entry or one note, not as a database migration.
9. **i18n**: bilingual **fa/en**, runtime switch, Persian RTL flip, Vazirmatn bundled font.
   All user-visible strings go through the translation layer — no literal UI strings in code.
10. **Licence**: GPL-3.0 (`LICENSE`). UI text Persian+English; code comments and docs English.
11. **Deviation from design, recorded**: the design asked for "a local API for the UI". We
    implement that service layer in-process for the UI (decision 5) *and* expose the same
    surface over the Unix socket for agents; this is strictly safer than a UI-over-socket API
    and is documented in `docs/SECURITY.md` and `docs/ARCHITECTURE.md`.
12. **Deviation, recorded**: the design's Qt UI uses QtWebEngine for markdown. We use
    QtWebEngine **only** for rendering `normal` files' preview (never `secret`/`secretfile`
    content) and the native plain-text viewer for secret content, exactly as designed.

## 4. Data-leak model (must be stated in docs/SECURITY.md and honoured by the code)

Readable **without** the master password (i.e. by anyone who can read the synced folder):
- file/folder **names** (logical paths), sizes, mtimes, sensitivity level, tags,
  and the access log — these live in the plaintext `meta.sqlite`;
- the KDF salt and parameters (needed to derive the key) and a password-verify canary.

Never readable without the password: every byte of file **content**, folder notes, the FTS
index, embeddings.

The design sanctions this: §12 "in locked mode only metadata/names/level are visible".

## 5. Repository layout (target)

```
secure-vault/
├── DESIGN.md -> docs/DESIGN.md            (original design, copied in, never edited)
├── LICENSE                                GPL-3.0 full text
├── README.md                              install / run / usage / MCP registration
├── TASK_SPEC.md                           master spec + phase prompts (this task)
├── SPEC/00..06-*.md                        implementation contracts
├── requirements.txt                       runtime deps (pinned >=)
├── requirements-semantic.txt              opt-in heavy extra (sentence-transformers)
├── bin/secure-vault                       launcher (exec .venv python -m vault)
├── assets/Vazirmatn-Regular.ttf           bundled font (downloaded by bootstrap)
├── assets/icon.svg                        app icon (hand-written SVG)
├── i18n/fa.json  i18n/en.json             UI catalogues (flat key → string)
├── src/vault/                             the package (see SPEC/01..03)
├── tests/                                 unittest suites + run_tests.py
├── tools/                                 bootstrap.sh, install-desktop.sh, importer CLIs,
│                                          build_windows_portable.py, smoke_e2e.py
├── portable/win/                          output of the Windows builder (git-ignored)
└── docs/                                  DESIGN.md, ARCHITECTURE.md, SECURITY.md, MCP.md,
                                           SYNC.md, IMPORT_JOPLIN.md, WINDOWS.md, TESTING.md
```

`src/vault/` is a real importable package (`src` on `sys.path`). The launcher and every CLI
insert `src/` into `sys.path`; the package must also work when `PYTHONPATH=src`.

## 6. Coding rules (enforced by review, and by the tests where stated)

- **Atomic writes** everywhere: write to `*.tmp` in the same directory, `fsync`, `os.replace`.
- **No plaintext content** may be written into the vault home outside `files/*.enc`. The tests
  assert this by scanning for known plaintext markers.
- **Every mutating operation** on the vault updates `meta.sqlite` and the encrypted store in
  one logical transaction, and calls `session.flush()` (re-encrypting the store) before it
  returns. Cheap for the expected size (≤ a few MB).
- **Every MCP call** (tool *and* resource) is appended to `access_log` with outcome
  `allow | deny | error`, including the deny reason code. Append-only.
- **Errors** are typed: `vault.errors.VaultError` subclasses with a stable `code`
  (`VAULT_LOCKED`, `VAULT_NOT_RUNNING`, `PERMISSION_DENIED`, `SENSITIVITY_DOWNGRADE_FORBIDDEN`,
  `NOT_FOUND`, `ALREADY_EXISTS`, `INVALID_PATH`, `TAMPER_DETECTED`, `BAD_REQUEST`,
  `UNAUTHORIZED`, `PROVIDER_UNAVAILABLE`). The MCP/API layers map codes to responses verbatim;
  never invent new codes.
- **Logging**: `logging` module only; never log secrets, passwords, keys or file *content*.
  Log paths and outcomes only. Default level INFO, `--debug` for DEBUG.
- **Type hints** on every public function; docstrings on every module and public class/function.
- **No global mutable state** except the module-level i18n catalogue and the logging config;
  the vault lives in objects created explicitly (this is what makes the tests possible).
- **Persian literals** are allowed only in `i18n/*.json` (UI strings) and in tests/importers
  where they are data under test. Everything else English.

## 7. Definition of done for the whole task

1. `./.venv/bin/python tests/run_tests.py` → **all suites pass** (SPEC/06 lists them).
2. `./.venv/bin/python tools/smoke_e2e.py` → prints `PASS` for every end-to-end step
   (create vault → unlock → write/read → search → mark secret → MCP denial → lock → unlock).
3. `QT_QPA_PLATFORM=offscreen ./.venv/bin/python tests/test_ui_smoke.py` passes.
4. The MCP server works against the real daemon: `tools/smoke_mcp.py` starts the GUI-less
   daemon (`vault.daemon` headless mode) with a scratch vault, unlocks it, then drives the MCP
   server over stdio through `initialize → tools/list → tools/call(list_folder) →
   tools/call(read_file) → denial of a secret file → resources/read`.
5. The Joplin importer has been run against the real mirror (888 notes) into a **scratch**
   vault and reported counts without errors (see SPEC/04 §7).
6. `README.md` quickstart is accurate: the exact commands in it work on this machine.
7. The Windows portable builder exists, is documented, and its `--check` (offline validation)
   mode passes; it is *not* expected to be run here.
