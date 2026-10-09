# Secure Vault

**Secure Vault** is a personal, offline-first encrypted vault for notes **and** credentials.
It is three interfaces over one folder — a Qt (PySide6) desktop app, a local browser web UI and
an MCP server — and it is **agent-aware**: an agent can see the structure and read ordinary
notes, but the content of `secret` and `secretfile` entries is never handed to it, and every
access is recorded in an append-only log.

It is the final replacement for Joplin (an importer reads the existing mirror), it keeps
passwords and one-time codes in the same vault as everything else, and its dependency set is
deliberately tiny: Python, PySide6, `cryptography`, `argon2-cffi`, `markdown-it-py` and Pygments.

> **The master password is never stored and there is no way to recover it.**

Other language: [فارسی](README.fa.md).

**Companions:** a read-only
[Android client](https://github.com/majidasgari/secure-vault-android) (گنجینه) and a
[Firefox add-on](https://github.com/majidasgari/secure-vault-firefox) use the same vault —
see [the family](#the-family--three-repositories) below.

---

## The family — three repositories

| repository | what it is |
| --- | --- |
| **secure-vault** ← this one | The vault itself: the storage format and crypto, the Qt desktop app, the browser web UI, the credential/one-time-code surface, the MCP bridge, two-way S3 sync, the importers and the packaging tools. |
| **[secure-vault-android](https://github.com/majidasgari/secure-vault-android)** | **گنجینه (Ganjineh)** — the read-only Android client. It pulls the encrypted vault from any S3-compatible bucket, unlocks it on the phone and gives you browsing, Persian-normalised literal search, one-time codes and per-field copy. It never writes: the desktop stays the single writer. |
| **[secure-vault-firefox](https://github.com/majidasgari/secure-vault-firefox)** | The Firefox add-on (MV3). While the vault is running it puts a small icon inside login fields and, **only when you click it**, fills the user name, password and one-time code of the entry you choose. Nothing is ever filled automatically. |

All three speak the **same on-disk format**, so the phone and the browser are *clients* of one
vault rather than copies of it. The add-on talks to this app's loopback bridge
([`docs/BROWSER-AUTOFILL.md`](docs/BROWSER-AUTOFILL.md)) and every value it reveals appends an
access-log row with `source=browser`; the Android app reads exactly the folder layout,
`meta.sqlite` and `secure.store` that this repository writes.

## What it is

Secure Vault is a personal, offline-first encrypted vault with a Qt (PySide6) desktop GUI. It
stores notes and secrets as AES-256-GCM blobs in a single folder you can sync with any cloud
drive, keeps a plaintext metadata index (names, levels, tags, access log) so locked-mode listing
still works, and exposes an MCP server so agents can see the structure and read `normal` files
while `secret`/`secretfile` content stays hidden.

## Status

* Core, socket API, MCP bridge, Qt UI, browser web UI (with Joplin-mirror parity),
  Joplin importer, KeePass migration tooling, tray shell, desktop integration and the Windows
  portable **builder** are implemented.
* Two-way S3 sync with a cooperative write lock, **restore-from-S3** (adopt the vault
  that is already in the bucket, `secure-vault-import` on headless machines) and safety
  rails that refuse to mirror one vault onto another (docs/SYNC.md §8/§9).
* The **tray is the always-on shell**: it starts the web UI automatically in-process,
  gates `secret`/`secretfile` reads with a Copy dialog, and always shows which file is
  being read right now (activity feed + tooltip + SSE). The Qt markdown editor is
  bidi-correct per block and can open the current note in the browser.
* The GUI has **not** been verified on a real screen yet — only headless/offscreen.
  Fonts, RTL, tray, notifications and the KDE menu icon must be checked by hand.
* **Windows is supported**: the same source tree runs on Windows 10+ (the daemon uses a
  loopback TCP endpoint where CPython has no `AF_UNIX`, the log/config/runtime dirs move to
  `%LOCALAPPDATA%`/`%APPDATA%`, and the GUI's single-instance guard is a named mutex). The
  suite is green there and the portable folder produced by the builder was verified by
  running `--self-test` **inside the built folder**. See `docs/WINDOWS.md`; the pieces that
  still need a human on Windows are listed in its last section (real-screen GUI, signing,
  fingerprint, a real S3 remote).
* S3 folder sync is opt-in and needs no extra package (boto3 is an optional alternative
  backend in `requirements-s3.txt`): a two-way mirror with a cooperative
  lock file, read-only mode plus a manual *Take write access* button, and a **Sync now**
  button on both the desktop app and the web UI. Only non-secret coordinates live in the
  vault; access keys are machine-local. Vectors and the embedding cache are never synced.
* Semantic search is opt-in and needs the extra in `requirements-semantic.txt`
  (`sentence-transformers` + the embedded `sqlite-vec` vector index); neither is installed
  by `bootstrap.sh`. Vectors live in a **separate, rebuildable cache** under the user's
  home (configurable in Settings) and are **never synced** (see `docs/SYNC.md`); a
  content-addressed embedding cache means a rebuild only embeds text it has never seen.
  The user picks the granularity — whole document, paragraph (default) or sentence — and
  can tick exactly which folders are included; inline `data:` URIs/base64 images are
  stripped before embedding.
* A live one-time code is generated **only inside the desktop UI**: there is deliberately no
  API, MCP or web route that can ask for one.

## Install

Requires Python ≥ 3.11. On a fresh checkout:

```bash
tools/bootstrap.sh
```

This creates `.venv`, writes `.venv/pip.conf` pointing at a PyPI mirror
(`PIP_INDEX_URL` / `PIP_TRUSTED_HOST` override it — the default is the mirror the author
uses), installs `requirements.txt`, downloads the optional Vazirmatn fonts (a failure is
only a warning), and prints the next commands. It is idempotent. Use `--skip-deps` when the
dependencies are already installed and `--desktop` to also install the desktop entry.

Windows (PowerShell/cmd; `docs/WINDOWS.md` has the full story):

```bat
uv venv --python 3.12 .venv
uv pip install --python .venv\Scripts\python.exe -r requirements.txt
bin\secure-vault.cmd
```

## First run

```bash
./bin/secure-vault
```

1. The first-run wizard asks for the vault home folder (a synced, user-visible folder;
   `SECURE_VAULT_HOME` overrides it at start-up and the choice is remembered) and for a
   master password.
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

* **Browser** (left dock): a tree of folders/files with a sensitivity label per entry and an
  optional emoji in front of every folder/file name (a `files.emoji` column; the shared
  palette lives in `core/emoji.py`, and the desktop list, the web rows and the Android app
  all show it).
* **Editor**: markdown source with a preview for `normal` files (off by default — View ▸
  preview or the toolbar button turns it on, and the choice is remembered), per-block
  RTL/LTR formatting (auto / RTL / LTR, `Ctrl+Shift+D`) and monospace fences. For
  `secret` files the preview is disabled; `secretfile` files never reach the editor
  at all. **Edit in browser** opens the current note in the web UI. Each file also has
  a one-line **note** field shown in the file list.
* **Version history**: every save keeps its own encrypted blob. The editor's *Version
  history* button lists all versions and shows a git-style colored diff between any two
  of them. History is UI-only — agents can never read old versions.
* **Sensitivity levels**: right-click a file → *Set level* → `normal`, `secret` or
  `secretfile`. Lowering requires confirmation and is only possible from the UI.
* **Secret viewer**: a native plain-text window (no web engine) for `secretfile`
  content, so it cannot leak into the markdown renderer. A credential body gets the actions
  its fields call for — see [credentials and one-time codes](#credentials-and-one-time-codes).
* **Picture viewer**: images open in a native viewer at every sensitivity level, never in
  the web view (`vault.read_file` can return bytes intact via `binary`).
* **Search** (right dock): three separate searches — filenames, literal content
  (FTS5) and semantic (opt-in) — never hybridized.
* **Log panel** (right dock): the append-only access log; every agent call is there.
* **Window arrangement**: whatever you set — geometry, which docks are open and how they are
  sized, the active right-dock tab, the source/preview split and the preview itself — is
  written to `ui.json` and restored on the next start (closing to the tray counts as setting it).
* **Appearance**: system / dark / light, applied as a real Fusion palette; the web preview
  and the picture canvas follow it.
* **Fingerprint quick unlock** (Linux, via `fprintd`): the master password can be replaced on
  the unlock screen by a finger, backed by a machine-local device secret; the password stays
  as the fallback and the record is dropped when you turn the option off.
* **Tray**: the always-on shell — open/copy the web UI link, lock, the last reads
  (with a 🔑 badge for recent secret reads), settings and quit. **No agent call is
  silent**: every MCP/socket access — a read, a write, a delete, a move, a folder
  listing, or a filename/text/semantic search — raises a desktop notification titled
  *Agent access (source)* that names the action and the path as it happens (for a search:
  the tool and the query, truncated to 160 characters), the tray's activity feed keeps the
  newest 200 of them and the tooltip names the file being read right now. A `secret` read
  gets its own notification naming the file and who asked for it, an agent
  `request_open_secret` pops a **Show & copy** dialog on your desktop, and identical events
  are collapsed within 1.5 s so a burst never becomes a wall of popups.

## Credentials and one-time codes

Credential entries live under the vault folder **`/رمزها`** — one file per entry, laid out as
`دسته/<site>/<entry>.md`, with a `# title` heading, one `سایت: … | دسته: …` line and one
`label: value` line per field (user name, password, URL, one-time code). The file bodies are
`secretfile`s: their names are visible in the structure (and in locked mode), their content is
not readable without the master password, and an agent can only *ask you* to display one.

Opening such an entry in the native viewer shows, above the text:

* a **one-time-code card** when the entry carries a code — a full `otpauth://totp/…` URI, a
  bare base32 seed, or a code you pasted by hand (a backup code, shown as stored and never
  regenerated). `core/totp.py` is RFC 6238 (HMAC-SHA1/256/512), the digits are grouped for the
  eye (3+3, 4+4, 3+3+3), and a countdown with a progress bar shows when the next code arrives;
* **per-field copy buttons** — one for the code, one for the user name and one for the
  password, each copying only its own value and unformatted. A field the entry does not have
  gets no button, and a copy never puts the value in a notification or a log line.

`core/totp.py` is deliberately pure Python with **no API or MCP surface at all**, so a live code
cannot be requested by anything but the person in front of the desktop UI (the self-test asserts
`web_views_for_otp = 0` as a regression guard). The Android app and the Firefox add-on generate
their codes themselves, on the device, from the value they are allowed to read.

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
      "command": "/path/to/secure-vault/bin/secure-vault-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

Or with the CLI:

```bash
hermes config set mcp_servers.secure-vault.command "/path/to/secure-vault/bin/secure-vault-mcp"
hermes config set mcp_servers.secure-vault.args "[]"
```

Some clients spell the key `mcpServers`; use whichever your Hermes version expects.
Set `SECURE_VAULT_DEBUG=1` in the server environment for diagnostics on stderr
(stdout stays pure JSON-RPC).

What agents can do: list names/structure, read/write `normal` files, search filenames and
the content of `normal` files (scoped with `path_prefix`), read/write **folder and file
notes**, get a one-call `digest` of a folder, list tags (`all_tags`/`files_by_tag`), read
the semantic status and trigger a scoped `semantic_reindex`, **raise** a level (never
lower), set a folder/file **emoji**, and ask you to display a `secretfile`. What they can
**never** do: read `secret`/`secretfile` content, search it, lower a level, or receive the
content of a `request_open_secret` call. See `docs/MCP.md` for the full tool reference.

**Nothing an agent does is silent on your side.** Every call reaches the tray's activity feed
(newest 200 events) and raises a desktop notification — *Agent access (mcp)*, then the action
and the path, or the tool and the query when it was a search — at the moment it happens;
identical events are collapsed within 1.5 s. A refused call notifies as well, and a read of a
`secret`/`secretfile` file always notifies and is always in the feed, whichever source made it
(a call that ended in an error stays in the feed without a popup).

The repository also carries a small worked example of a *second* MCP server on the same
session — `tools/max_profile_mcp.py` serves one vault subtree read-only, with no storage of
its own — as a template for narrow, purpose-built bridges.

## Using it from a browser (web UI)

The same vault is also usable from any browser on the machine (or, explicitly
opted in, the LAN). The web process owns the session; the keys never leave it.

```bash
./bin/secure-vault-web --home /path/to/vault --port 8788
# or: PYTHONPATH=src ./.venv/bin/python -m vault.web --port 0
```

It prints the URL and a one-time **access token** on stderr. Open the URL, paste the
token and the master password. Every `/api/*` request needs the token in the
`X-Vault-Token` header — the cookie set by the `/?token=…` link is deliberately
*not* enough to authorise a call. Persian-first, RTL, responsive down to a phone,
and fully offline (no CDN, no build step). The SPA has the same features as the
Joplin-mirror browser — dark theme with a light toggle, one global search box, a
collapsible folder tree with per-subtree note counts, tag chips, folder/note/raw/
edit views with a formatting toolbar, and a parity `/api/index` + `/api/search` +
`/api/raw` surface. `--allow-lan` is required to bind a non-loopback host. See
`docs/WEBUI.md` for the token flow, the API and the security caveats.

**Printing** is part of the note view: the pane head has a **Print** button (a bare
`window.print()` — no export endpoint, no server call) and a paper-orientation select. The
printed page is the note *alone*: in `@media print` the shell (header, folder tree, status
bar, action row, breadcrumb, tag chips, note editors, modals) is dropped, the page turns
paper-white with dark text, long code lines wrap instead of being clipped and tables repeat
their header row — without that the note was silently cut off at the fold. The orientation is
injected into the document as an `@page` rule, so `Ctrl+P` honours it too, and the choice is
kept in `sessionStorage` (`docs/WEBUI.md` §3d).

**You normally do not start it by hand.** The Qt app is the shell: after unlock it
starts the same `WebServer` in-process on the same session (`web.enabled`, default
true) and the tray menu opens/copies the token URL. If another instance already owns
the port/token, the app does not take over the vault and points the tray at the
already-running instance instead.

## Browser autofill (the Firefox add-on)

The vault can hand a login form the user name and password of an entry under `/رمزها`, the way
a password-manager add-on does — but only to a browser holding a **narrow, separate token**:
`/api/autofill/*` is the entire surface that token opens (`vault.browser_status`,
`vault.browser_match`, `vault.browser_reveal`), it can never call `read_file` or `write_file`,
every path it may name has to live under the credential root, an entry is only handed over to
**its own host**, and every reveal writes one access-log row with `source=browser` (plus an
activity event, so the tray shows it). Matching answers metadata only — never a password.

The client is the Firefox add-on in
**[secure-vault-firefox](https://github.com/majidasgari/secure-vault-firefox)**: it puts an
icon inside the fields, shows the entries for the page's host when you click it, fills them
only on your click (into a closed shadow DOM, so the page's own scripts cannot click for you),
reads one-time codes in its popup, and adds nothing automatic. The switch is in the desktop
app: **Settings → Web UI → browser autofill**. `docs/BROWSER-AUTOFILL.md` is the contract of
the bridge.

## Android client — گنجینه (Ganjineh)

**[secure-vault-android](https://github.com/majidasgari/secure-vault-android)** is the
read-only phone client, written in Kotlin/Compose. It pulls `meta.sqlite`, `secure.store` and
the `files/<aa>/<blob>.enc` blobs from a bucket prefix (GET only — it never PUTs, never DELETEs
and never touches the write lock), derives the key with the same Argon2id parameters as this
app, and then offers browsing, folder notes, file notes and tags, Persian-normalised literal
search (names of *all* files, text of the ones on the device), markdown rendering with the
per-line RTL rule, one-time codes with per-field copy, an optional fingerprint unlock, and a
local "recently opened" list. Its unit tests build their fixtures **with this repository's own
desktop implementation** (`tools/make_test_fixture.py`, `tools/make_totp_fixture.py`), so a
format drift here turns its tests red. What it deliberately does not do: write, edit, delete,
change levels or tags, semantic search, version history, sharing, MCP, access-log panel.

## Firefox add-on — fill logins from the vault

**[secure-vault-firefox](https://github.com/majidasgari/secure-vault-firefox)** is the MVP
add-on described under [browser autofill](#browser-autofill-the-firefox-add-on). It claims a
browser-scoped token from the loopback bridge, keeps no password of its own (only the port and
a revocable token), never fills anything without a click, and memoises a one-time code seed for
at most five minutes in the event page's memory so the countdown does not become one vault read
per second. It works against the vault running in this repository — the two are versioned
together through `docs/BROWSER-AUTOFILL.md`.

## Importing

**From Joplin.** The importer reads the existing markdown mirror **read-only** and writes into a
vault:

```bash
printf '%s' 'your-master-password' > /tmp/sv.pw && chmod 600 /tmp/sv.pw
./.venv/bin/python tools/import_joplin.py \
    --home /tmp/scratch-vault --unlock-file /tmp/sv.pw --dry-run
./.venv/bin/python tools/import_joplin.py \
    --home /tmp/scratch-vault --unlock-file /tmp/sv.pw \
    --report docs/reports/joplin-real.md
```

It is idempotent (a second run is a no-op), rewrites `:/<id>` resource references to
`vault:/attachments/<file>` links, and never modifies the mirror. See
`docs/IMPORT_JOPLIN.md`.

**From KeePass/Bitwarden.** `tools/keepass-migration/` is a plan-then-apply pipeline
(`extract.py` → `plan.py`/`curate.py` → `apply.py`, with `verify.py` at the end) that turns an
export into the `/رمزها` tree: one `secretfile` per entry, `دسته/<site>/<entry>.md`, no secret
value ever leaving the 0600 working files or reaching an agent transcript. `apply.py` is
idempotent and pushes over the local socket (each entry is created `normal`, then raised to
`secretfile`, then given its note — raising a level drops the note, so the order matters).
`tools/label_folders.py` can then emoji-label a live vault in bulk without the master key.

## Syncing

The whole vault folder can be mirrored to any S3-compatible bucket with a built-in
two-way sync (**Settings → S3 sync**; no extra package needed — requests are signed
in-process with AWS SigV4, and `requirements-s3.txt` offers boto3 as an optional
alternative backend). A lock object in the bucket makes the design single-writer:
if another device holds the lock, this session opens **read-only** and every write is
refused until you press **Take write access**; the lock is released on lock/quit.
**Sync now** lives on the app Tools menu, the tray and the web header; it runs in a
background thread and both UIs show live progress (uploaded/downloaded counts), so the
app never freezes. **Settings → S3 sync → Test connection** verifies the endpoint,
bucket and credentials without transferring anything. The web UI shows a read-only
banner with the take-control button. Semantic vectors and the
embedding cache live outside the vault and are **never synced**; Settings refuses a
vector-cache path inside the vault. You can also sync the folder with
Dropbox/OneDrive/Google Drive as before — never sync the runtime directory
(`$XDG_RUNTIME_DIR/secure-vault`, which holds `store.*.dec`, the socket and the tokens)
or `semantic.db`, and do not run two daemons against the same synced folder at once.
See `docs/SYNC.md`.

The Android client pulls from the same bucket (read-only), and **restore-from-S3** lets a new
machine adopt the vault that is already there instead of overwriting it.

## Security notes

Names, sizes, mtimes, sensitivity levels, tags and the access log are readable
without the password (they live in the plaintext `meta.sqlite`). File content, folder
notes, the FTS index and embeddings are never readable without the password. Files
strictly larger than 10 MB are stored **unencrypted** (a deliberate user decision);
keep secrets in small files. The master password is never stored. A one-time code is
generated only in the desktop UI. See `docs/SECURITY.md` for the full threat model and the
sensitivity matrix, and `docs/BROWSER-AUTOFILL.md` for the browser token's exact reach.

## Tests

Everything runs offline with the stdlib `unittest` runner:

```bash
./.venv/bin/python tests/run_tests.py                              # all suites
./.venv/bin/python tests/run_tests.py --only test_session          # one suite
./.venv/bin/python tests/run_tests.py --only test_web              # the web UI suite
./.venv/bin/python tests/run_tests.py --only test_activity         # the activity feed
./.venv/bin/python tests/run_tests.py --only test_bidi             # editor bidi rules
QT_QPA_PLATFORM=offscreen ./.venv/bin/python tests/test_ui_smoke.py
./.venv/bin/python tools/smoke_e2e.py
./.venv/bin/python tools/smoke_mcp.py
./.venv/bin/python tools/build_windows_portable.py --check         # prints CHECK OK
```

On Windows the same commands run with `.venv\Scripts\python.exe`, and the portable build is
verified from inside its own folder:

```bat
set PYTHONPATH=
set QT_QPA_PLATFORM=offscreen
cd portable\win && python.exe -m vault --self-test               :: SELFTEST OK
```

The semantic-search suites need the opt-in extra (`pip install -r requirements-semantic.txt`,
or at least `sqlite-vec`, which is the small half of it); everything else runs with
`requirements.txt` alone.

The Joplin real-mirror run is opt-in and read-only (see `docs/TESTING.md`). See that
file for the scratch-vault recipe and the list of things you must verify by hand.

## Repository layout

```
secure-vault/
├── bin/                 secure-vault, secure-vault-mcp, secure-vault-web launchers
├── assets/              icon.svg + Vazirmatn fonts
├── i18n/                fa.json, en.json UI catalogues
├── src/vault/           the package (core, api, ui, web, webui, importers)
├── tests/               unittest suites + run_tests.py
├── tools/               bootstrap, desktop install, importers (Joplin + keepass-migration),
│                        smoke scripts, label_folders, max_profile_mcp, Windows builder
├── docs/                ARCHITECTURE, SECURITY, MCP, SYNC, BROWSER-AUTOFILL,
│                        IMPORT_JOPLIN, WINDOWS, TESTING, WEBUI
└── portable/win/        output of the Windows builder (git-ignored)
```

## Related repositories

* [secure-vault-android](https://github.com/majidasgari/secure-vault-android) — the read-only
  Android client (گنجینه).
* [secure-vault-firefox](https://github.com/majidasgari/secure-vault-firefox) — the Firefox
  log-in autofill add-on.

## Licence

GPL-3.0-only. See `LICENSE`.
