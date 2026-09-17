# SPEC 07 — Web UI (P7): browser client for the vault

Goal: the vault usable from a browser — comfortable, Persian-first (RTL), responsive down to a
phone, offline (no CDN, no build step), and **without weakening the security model**: the master
password is typed in the browser but the keys never leave the daemon process.

Read `SPEC/00-overview.md`, `SPEC/01-core.md`, `SPEC/02-interfaces.md` first: this phase reuses
`Service.dispatch` and the existing `VaultSession` unchanged.

## 1. Process model

New entry point `python -m vault.web` (`bin/secure-vault-web` launcher), which:

1. loads/creates the vault at `--home` (default: the same resolution order as `vault.daemon`),
2. owns the `VaultSession` (**the web process is the key holder** — same rule as the GUI),
3. serves an HTTP JSON API + the SPA on `--host 127.0.0.1 --port 8788` (port 0 = pick a free
   one and print it),
4. **refuses to bind a non-loopback host unless `--allow-lan` is given**, and prints a warning
   with the URL + access token when it does — the token is the only thing standing between the
   network and the vault.

`--unlock-file PATH` (0600) unlocks at startup, exactly like the daemon (used by the tests and
by anyone who wants an unattended read-only-ish web vault). Without it the vault starts locked.

Threading: `ThreadingHTTPServer` with `daemon_threads = True`; all vault work happens under a
single `threading.RLock` held by the API layer (SQLite + the encrypted store are not
concurrency-safe for writes), so requests serialise without blocking the event stream.

## 2. Auth (the contract)

* At startup generate `token = secrets.token_hex(32)`, write `{"token": ..., "created_at": ...}`
  to `runtime_dir()/web.token` (mode `0600`), and print it **once** to stderr (never stdout,
  never the log file, never the access log).
* Every API request must carry the token in the **`X-Vault-Token`** header. Additionally:

  | path | behaviour |
  |---|---|
  | `GET /` and static assets (`/static/*`, `/favicon.ico`) | served **without** a token (they contain no vault data) |
  | `GET /?token=<t>` | sets an `HttpOnly; SameSite=Strict; Path=/` cookie `vault_token` and 302-redirects to `/` — the "click the printed link" flow |
  | `POST /api/session/login {"token": t}` | same cookie, returns `{"ok": true}` |
  | every `/api/*` call | **requires the header**; the cookie alone is *not* enough (CSRF defence) |
  | wrong/absent token | `401 {"error": {"code": "UNAUTHORIZED"}}`, one `deny` row in the access log with `source="web"` |

* `POST /api/session/unlock {"password": ...}` verifies the master password in-process;
  `POST /api/session/lock` locks. Wrong password → `401 {"code": "UNAUTHORIZED", "details":
  {"reason": "bad_password"}}` with an escalating delay (5 s × failures, capped at 60 s,
  in-memory, per-IP), and a `deny` row. The password is never logged, echoed or stored.
* The token is never written into the access log, an HTML page, or an error message. The SPA
  keeps it in memory + `sessionStorage` only.

## 3. API

`POST /api/call` — body `{"method": "vault.list_folder", "params": {...}}`, response
`{"ok": true, "result": {...}}` or `{"ok": false, "error": {"code": ..., "message": ...,
"details": {...}}}`. The method/param/result shapes are **exactly** `SPEC/02 §1`; the call is
`Service.dispatch(method, params, role="ui", session_id="web-<n>")`. Unknown method → `400`
with `code="BAD_REQUEST"`. `vault.unlock`/`vault.lock` are reachable only through the
`/api/session/*` endpoints, not through `/api/call`.

Convenience endpoints:

| endpoint | purpose |
|---|---|
| `GET /api/session` | `{"locked", "home", "language", "auto_lock_seconds", "counts", "version", "ui": {...}}` |
| `GET /api/i18n?lang=fa\|en` | the catalogue as JSON (single source of truth = `i18n/*.json`) |
| `GET /api/events` | Server-Sent Events: `{"event": "log"\|"lock"\|"unlock"\|"secret_request"\|"data_changed"\|"ping", ...}` every ≤ 15 s (keepalive) |
| `GET /api/fonts/Vazirmatn-Regular.ttf` | the bundled font (from `assets/`), `Cache-Control: max-age=86400` |
| `GET /api/export/access-log.csv` | the CSV export (`Index.export_access_log_csv`) |
| `GET /api/blob?path=…` | raw bytes of a **normal** file (for images/attachments in the preview); `secret`/`secretfile` → `403` |

## 4. SPA (`src/vault/webui/`) — no build step, no CDN, works offline

Files: `index.html`, `app.js`, `styles.css`, `icons.svg` (inline symbols), all plain ES2020 in
one script (no imports), ~1500 lines max — it must be readable and maintainable.

**Layout (desktop)**: header (vault name, language switch, lock button, status pill) · left
column: filter box + folder tree + file list of the selected folder (name, level badge 🔓/🔒/🔑,
size, mtime) · centre: editor (markdown) with a preview toggle · right column: tabs
**Search | Log | Settings** · footer/status bar: lock state, file count, agents connected,
auto-lock countdown.
**Mobile (≤ 760 px)**: single column; the tree/log/search become full-screen panels that slide
over; the toolbar collapses to icons; tap targets ≥ 40 px. Persian-first typography (Vazirmatn,
`dir="rtl"` on `<html>` for `fa`, 16 px base, generous line-height).

**Features that must work** (this is the "comfortable to use" bar):

1. **Unlock screen** — token field (pre-filled from the URL fragment/cookie when possible) and
   master password; Enter submits; inline error text; lockout countdown shown when throttled.
2. **Browse** — lazy folder tree, file list with the filter box (instant), breadcrumbs,
   double-click to open, right-click context menu (open, open in plain viewer for
   secretfile, rename, delete, copy path, set level, tags).
3. **Edit** — load a file, edit as text, live markdown preview (rendered client-side with a
   small built-in renderer: headings, lists, links, code fences, tables, blockquotes,
   images via `/api/blob`), `Ctrl/Cmd+S` saves, dirty indicator, unsaved-changes guard on
   navigation/close (`beforeunload`).
4. **Sensitivity** — a level selector per file; `secret`/`secretfile` show a coloured badge in
   the list; changing the level is explicit (a confirm for `→ normal` = downgrade);
   **the markdown preview is disabled for `secret`/`secretfile`** and `secretfile` opens in a
   plain-text modal (monospace, no HTML rendering, Copy button, "copied" toast) — the same rule
   as `SPEC/03 §2.4`, enforced in the render path, not in the template.
5. **Search** — the three separate kinds in three tabs (Filnames / Text / Semantic), each with
   its own query box and result list, clicking a hit opens the file; semantic shows the
   "extra not installed" state from `ProviderUnavailable`.
6. **Folder notes** — show under the file list, edit inline, autosave with debounce.
7. **Log tab** — live table (SSE-refreshed) with source/outcome filters, "load more", CSV link.
8. **Settings tab** — language, auto-lock minutes, default sensitivity, semantic enable/index,
   importer (mirror path + globs + **Run import** with the same report dialog content), and a
   read-only view of the vault home + plain-threshold.
9. **Secret requests** — when an agent requests a `secretfile`, a modal appears (SSE) with the
   path and Show / Deny; Show opens the plain viewer and resolves the request.
10. **Toasts** for every action outcome (saved, level changed, import finished, error codes
    translated through `error.<CODE>`), and a **busy overlay** during imports/indexing.
11. **Keyboard**: `Ctrl+S` save, `Ctrl+L` lock, `Ctrl+F` focus filter, `Esc` close modal,
    `↑/↓` navigate the file list. Full keyboard reachability (no mouse-only controls).
12. **Auto-lock** countdown in the status bar; on lock everything hides (no cached content left
    in the DOM: the editor, tree and results are cleared and the unlock screen is shown).

## 5. What must NOT happen

* No vault content (file bodies, folder notes, search results, secret material) may be written
  to `localStorage`, the URL, or any cache header; `Cache-Control: no-store` on all `/api/*`.
* The token may never appear in an HTML response, a JS file, or a log line.
* The SPA must not load anything from the network (no CDN, no Google Fonts, no analytics) —
  offline is a requirement, verified by a test that greps the assets for `http://`/`https://`.
* `secret`/`secretfile` content must never reach an HTML-rendering path (the preview renders
  only `normal` files).

## 6. Tests (`tests/test_web.py`, headless, plus my black-box verifier)

Serve on port 0 against a scratch vault and drive it with `urllib.request`:

* static: `GET /` → 200 + `text/html`; `GET /static/app.js` → 200; unknown static → 404
* auth: no token → 401 · wrong token → 401 · `?token=` sets the cookie and redirects ·
  `POST /api/session/login` with the right token → 200 · cookie alone (no header) → 401
* `GET /api/session` → locked true, no counts leaked while locked
* unlock: wrong password → 401 + `bad_password` + a `deny` log row + the throttle kicks in on
  the 5th attempt; right password → 200 and `locked: false`
* `/api/call` round-trip: list_folder, write_file, read_file, write_lines, mkdir, file_ops,
  set_tags, folder notes, set_sensitivity (up allowed, down refused with
  `SENSITIVITY_DOWNGRADE_FORBIDDEN`), search_filenames/text/semantic (provider unavailable),
  stats, access_log
* locked again → content calls → `VAULT_LOCKED`, `search_filenames` still 200
* `vault.read_secret` is **not** reachable through `/api/call` (only the SPA's own path via a
  UI-only method is; assert the 400/denied behaviour of any method outside the allow-list)
* `/api/blob` on a `secret` file → 403; on a normal file → 200 with the bytes
* `/api/export/access-log.csv` → `text/csv` with a header row
* `/api/events` → the first line arrives within 2 s and is valid JSON with `event`
* traversal: `path=../../etc/passwd` in a call → `INVALID_PATH`, nothing read
* `--host 0.0.0.0` without `--allow-lan` → exits non-zero with a clear message
* no-network check: `src/vault/webui/*` contains no `http://` or `https://` literal
* i18n: `/api/i18n?lang=fa` returns the same key set as `i18n/fa.json`; every `data-i18n`
  attribute used in `index.html` exists in both catalogues

## 7. Deliverables

* `src/vault/web/{__init__,server,auth,api,events}.py`
* `src/vault/webui/{index.html,app.js,styles.css}`
* `bin/secure-vault-web` (launcher, same pattern as `bin/secure-vault`)
* `tests/test_web.py`
* `docs/WEBUI.md` (how to run it, the token flow, LAN/mobile notes, what is *not* protected)
* README + `docs/HANDOFF-fa.md` + `docs/SECURITY.md` updated with the web UI section
* `i18n/fa.json` / `i18n/en.json`: the few extra web-only strings (login, token, lockout,
  plain viewer, mobile hints) — identical key sets, no literals in the JS
