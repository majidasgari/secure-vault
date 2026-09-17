# Secure Vault — Web UI

The web UI (`python -m vault.web`, launcher `bin/secure-vault-web`) serves a
browser SPA and a small JSON API from a process that **owns the vault session** —
the web process is the key holder, exactly like the Qt GUI. The master password is
typed in the browser, but the derived keys never leave the daemon process and the
browser never receives the decrypted content store.

## 1. Running it

```bash
# scratch vault (never your real one), pick a free port and print the token
printf '%s' 'correct horse battery staple' > /tmp/sv.pw && chmod 600 /tmp/sv.pw
PYTHONPATH=src ./.venv/bin/python -m vault.web \
    --home /tmp/scratch-vault --port 8788 --unlock-file /tmp/sv.pw

# or with the launcher
./bin/secure-vault-web --home /path/to/vault
```

Options:

| flag | meaning |
|---|---|
| `--home PATH` | vault home; default resolution order is the same as `vault.daemon` (`--home` → `SECURE_VAULT_HOME` → `ui.json:last_vault_home` → `DEFAULT_VAULT_HOME`) |
| `--host ADDR` | bind address, default `127.0.0.1` |
| `--port N` | TCP port, default `8788`; `0` picks a free one and prints it |
| `--allow-lan` | required to bind a non-loopback host (see §4) |
| `--unlock-file PATH` | `0600` file with the master password; unlocks at startup |
| `--no-mcp` | do not start the local MCP Unix socket server |
| `--json-events` | print a machine-readable `{"event":"ready", ...}` line on **stdout** |
| `--debug` | verbose logging on stderr |

Without `--unlock-file` the vault starts **locked**; unlock it from the browser.
The token is printed **once to stderr** when the server starts; it is never written
to stdout, an HTML page, a JS file, or the access log.

By default the web process also starts the local MCP socket server (so agents can
reach the same session). If another process already owns the socket, the web server
logs a warning and continues serving the browser. Use `--no-mcp` to skip it.

## 2. The token flow

1. Start the server; stderr shows:

   ```
   Secure Vault web UI: http://127.0.0.1:8788/
   Access token: <64 hex chars>
   ```

2. Open the URL. The login screen asks for the **access token** (paste the printed
   one) and the **master password**. Both are submitted to the server; the password
   is verified in-process against the vault canary and is never stored or logged.

3. `GET /?token=<token>` (the "click the printed link" flow) sets a cookie
   `vault_token` (`HttpOnly; SameSite=Strict; Path=/`) and 302-redirects to `/`.
   `POST /api/session/login {"token": …}` does the same. The SPA also accepts the
   token in the URL fragment (`/#<token>`), which it strips from the address bar.

**The cookie is never used to authorise anything.** Every `/api/*` request must
carry the token in the `X-Vault-Token` header. That is deliberate: a cookie would
be sent automatically by the browser and would open the door to CSRF; the header
cannot be set cross-origin without a CORS preflight, which the server never allows.

Wrong or missing token → `401 {"error": {"code": "UNAUTHORIZED"}}` plus a `deny` row
in the access log (`source="web"`). Wrong master password → `401` with
`details.reason = "bad_password"`, a `deny` row, and an in-memory per-IP delay
(`5 s × failures` past the fifth attempt, capped at `60 s`). The password is never
logged, echoed or stored.

## 3. API

* `POST /api/call` — `{"method": "vault.list_folder", "params": {…}}` →
  `{"ok": true, "result": {…}}` or `{"ok": false, "error": {"code", "message",
  "details"}}`. The method/param/result shapes are exactly `SPEC/02 §1`; the call is
  `Service.dispatch(…, role="ui", session_id="web-<n>", source="web")`.
  `vault.unlock` and `vault.lock` are **not** reachable through `/api/call`. A plain
  `vault.read_file` on a `secret`/`secretfile` path is refused with
  `PERMISSION_DENIED` + `details.requires_approval: true`; after the SPA's confirm
  step it calls the UI-only `vault.read_secret` (same access-log rows as the desktop
  viewer). See §6.
* `GET /api/index` — `{"tree": […], "tags": [{name, count}], "counts": {…}}` in one
  round-trip for the sidebar (parity with the mirror browser).
* `GET /api/search?q=&tag=&limit=` — one-box search over title, tags and (normal)
  bodies, with a matching-line snippet; `tag:<name>` inside `q` filters too. Secret
  files may match by name/tag but never by body.
* `GET /api/raw?path=…` — a `normal` file as `text/plain` (traversal-checked; 403
  for secret levels), used by the SPA's «متن خام» button.
* `GET /api/session` — locked state, home, language, auto-lock seconds, version,
  and counts **only while unlocked** (locked mode leaks no counts).
* `GET /api/i18n?lang=fa|en` — the catalogue (`i18n/*.json`, single source of truth).
* `GET /api/events` — Server-Sent Events (`log`, `lock`, `unlock`,
  `secret_request`, `data_changed`, `ping` keepalive ≤ 10 s). The browser consumes
  it with `fetch()` streaming because `EventSource` cannot send the token header.
* `GET /api/fonts/Vazirmatn-Regular.ttf` — the bundled font (token-protected).
* `GET /api/export/access-log.csv` — the CSV export (`text/csv`).
* `GET /api/blob?path=…` — raw bytes of a **normal** file; `secret`/`secretfile`
  → `403`. The SPA fetches blobs with the token and turns them into object URLs.

All `/api/*` responses are `Cache-Control: no-store`. `GET /` and `/static/*` are
served without a token because they contain no vault data.

## 3a. The SPA at a glance (Joplin-mirror parity)

The single page mirrors the standalone mirror browser and adds the vault's levels:

* **Dark by default** with the mirror palette, plus a light/dark toggle persisted in
  `sessionStorage` (never vault data). Persian/RTL first, Vazirmatn, `dir="auto"` on
  names and titles, LTR code blocks and plain-text viewer.
* **Sticky header** with one global search box (focused by `/` or `Ctrl+F`) and a
  status line: lock state · file count · agents · auto-lock countdown.
* **Sidebar**: a collapsible folder tree from `/api/index` where every row shows the
  note count of its whole subtree and a 🔓/🔒/🔑 level badge; tag chips below it carry
  counts and run `tag:<name>` on click.
* **Views**: welcome state; folder view with breadcrumbs, sub-notebooks **with
  counts**, notes with their updated date; note view with title, `📅 ویرایش` /
  `🕓 ساخت` dates, clickable tag chips, `🔗 منبع` when `source:` metadata exists, and
  rendered markdown (headings, emphasis, strike, inline/fenced LTR code, quotes,
  bullet/numbered/**task** lists with disabled checkboxes, tables, rules, links with
  `rel=noopener`, and images resolved through `/api/blob`); a «متن خام» button that
  opens `/api/raw` as plain text in a new tab; and an edit view with a formatting
  toolbar (bold, italic, strike, code, heading, quote, bullet, numbered, link, image,
  rule), Save/Cancel, `Ctrl+S` and a dirty guard.
* Secret/secretfile files never reach the markdown renderer: a plain read is refused
  and the content is shown only in the plain-text modal (or opened natively by the
  desktop UI), exactly as before.

## 3b. The tray shell starts the web UI automatically

The Qt app (`python -m vault`, `bin/secure-vault`) is now the always-on shell: after
unlock it starts the same `WebServer` **in-process on the same `VaultSession`** (never
a second process/key holder) unless `web.enabled` is false. The effective port is
`VaultApplication.web.port`. The tray menu is:

* **باز کردن رابط وب** — opens the token URL in the default browser;
* **کپی لینک رابط وب** — copies `http://host:port/?token=…` (never logged);
* **قفل فوری** (`Ctrl+L`) — locks the vault; the web UI falls back to its unlock
  screen (the token/port stay up so the browser can unlock);
* **آخرین خواندهها** — the last reads; clicking one opens it in the browser;
* **تنظیمات / خروج**.

The tray tooltip always shows the last read path and its age, and gets a 🔑 badge
when a `secret`/`secretfile` was read in the last 60 s. The same metadata-only
activity feed is streamed to the browser as `{"event":"activity", …}` SSE frames
(path/level/source/outcome/bytes only — never content) and shown as a live banner
plus an "Activity" section in the Log tab.

If the configured port is taken or another instance already owns
`runtime_dir()/secure-vault/web.token`, the app does **not** take over the vault: it
logs a warning, leaves its web server off, and the tray's open/copy items point at
the already-running instance (the token file now also records the port).

### Editing in the browser from the app

The Qt editor toolbar has **«ویرایش در مرورگر»** (and the File menu has the same
item). For a `normal` note it opens
`http://127.0.0.1:<port>/#/note/<url-encoded path>`; it is disabled while the vault
is locked. In offscreen/self-test mode only `EditorPanel.browser_url` is computed and
nothing is launched. The token is never printed into the app log.

## 3c. Layout: two columns, search and language in the header

The browser is the primary interface, so the shell stays deliberately small:

* **One search path.** The header form calls `runSearch()` → `vault.search_filenames|text|semantic`
  only. The older `GET /api/search` route (names + tags + bodies) is still served for other clients
  but is **not** used by the SPA: both ran on submit and printed two different counts («۲ نتیجه» above
  «۱ نتیجه»). The heading is a label; a single `#search-status` line carries the count.
* **Row actions.** Folder rows, note rows (folder view and tag page) and the open note carry a trash
  button (`.row-action`, quiet until hover). Deleting goes through a modal `confirmDialog` (never
  `window.confirm`) and `vault.file_ops {op:"delete", recursive:true}`; deleting the open note returns
  to the welcome view *after* the folder reload, because `loadFolder()` ends with `showView("folder")`.
* **Header** (one row on desktop, wraps to two on a phone): the tree toggle (`☰`, mobile
  only), the brand, then the search group — a kind `<select>` (`filenames` / `text` /
  `semantic`), the query input and the submit button — and finally the language
  `<select>`, the theme toggle and **قفل**.
  The search group and the language select are the *only* search/language surfaces: the old
  right-hand panel (search tab, access log, settings form) is gone from the web UI. Access
  logs, sensitivity defaults, the mirror path and the index rebuild live in the desktop app;
  the transient agent activity line sits in the status bar.
* **Left panel**: the name filter (+ refresh), the two creation buttons (`یادداشت جدید`,
  `پوشه جدید`, both modal dialogs, never `window.prompt`), the folder tree with note counts,
  and the tag area — the eight most used tags plus **همهٔ برچسبها (N)**, which opens a
  searchable browser for the full list. Picking a tag anywhere opens `#/tag/<name>`: the
  centre pane lists the notes carrying it (`vault.files_by_tag`).
* **Centre**: breadcrumbs as chips (`ریشه › الف › ب` — every non-current chip navigates, the
  last one is `aria-current` and disabled; in a note's breadcrumb the trailing file is the
  current chip), then the folder / note / editor / search / tag view.
* The language select is built from the catalogues the server reports (`_languages` in
  `GET /api/i18n`, i.e. the `i18n/*.json` files) — dropping in `i18n/de.json` is enough for
  it to appear.
* **Mobile** (`≤ 860px`): a single column; the left panel becomes a drawer
  (`#btn-menu` toggles `.open`, `#mobile-backdrop` closes it, choosing a folder closes it),
  the search group moves to its own header row, the editor stacks above the preview, and the
  status bar keeps `env(safe-area-inset-*)` padding.

## 4. LAN / mobile access

Binding a non-loopback host is refused unless you explicitly opt in:

```bash
./bin/secure-vault-web --host 0.0.0.0 --port 8788 --allow-lan
```

The server then prints a warning. The token is the **only** thing standing between
the network and the vault, so treat it like a password and prefer a trusted LAN or
an SSH tunnel. On a phone, open the printed URL and paste the token; the layout is
responsive (single column, slide-over panels, ≥ 40 px tap targets) and Persian
(`dir="rtl"`) first.

## 5. What the web UI does **not** protect against

* Anyone who has the token **and** the master password. Keep the token secret.
* The token in your terminal scrollback or shell history if you copy it around.
* A compromised browser or OS (malware, extensions, a keylogger, screen capture).
* Plain files above the 10 MB threshold — they are stored unencrypted by design
  (`docs/SECURITY.md §6`).
* Traffic sniffing on a plain-HTTP LAN. Put a TLS reverse proxy in front if you
  expose it beyond loopback; the server itself speaks HTTP only (stdlib).
* Multi-user machines: the token file lives in `runtime_dir()/web.token` (mode
  `0600`), so any process running as your user can read it.

## 6. Content rules

- **`GET /api/i18n` is public on purpose.** The unlock screen must label its own fields before a
  token exists; the endpoint returns only the UI catalogue from `i18n/*.json`, never vault
  content. Every other `/api/*` route still requires `X-Vault-Token` (verified: `/api/session`,
  `/api/index` and `/api/raw` answer `401` without it).
- **`POST /api/session/claim` gives the token to a loopback client that asks for it.** A browser
  cannot read `runtime_dir()/web.token` (0600), so the SPA claims the token instead of asking the
  user to copy 64 hex characters. Two guards: the client address must be loopback, and the
  request must carry `X-Vault-Claim: 1` — a cross-origin page cannot read the reply (no CORS
  headers are ever sent) and the non-simple header needs a preflight this server never approves.
  Both allow and deny are written to the access log as `session.claim`; no content is returned.

The browser follows the same sensitivity rules as the desktop UI:

* `normal` — editable, live markdown preview.
* `secret` / `secretfile` — a plain `vault.read_file` is refused with
  `requires_approval`; after the confirmation the SPA reads them through
  `vault.read_secret` and shows them only in the plain-text modal (`textContent`,
  monospace, Copy button). No markdown preview is ever rendered for these levels and
  `GET /api/blob` / `GET /api/raw` refuse them with 403.
* On lock, the SPA clears the editor, tree, results and log from the DOM and shows
  the login screen again; nothing vault-related is written to `localStorage` or the
  URL. The access token lives in memory + `sessionStorage` only.

## 7. Tests

```bash
PYTHONPATH=src ./.venv/bin/python -m unittest tests.test_web -v
./.venv/bin/python tests/run_tests.py --only test_web
```

`tests/test_web.py` serves on port `0` against a scratch vault and drives the API
with `http.client`: static files, the token/cookie contract, unlock throttling and
the `deny` row, the `/api/call` round-trip, locked-mode behaviour, the blob 403, the
CSV export, the SSE first frame, path traversal, the non-loopback guard, the
no-network check and the i18n key sets.

The SPA itself is exercised in a real browser by `tools/ui_probe.py` (a throwaway
vault + headless Chrome over CDP): breadcrumb navigation, the folder/note dialogs,
header search, the tag browser and the phone layout (`PROBE_W=390 PROBE_H=844`).
It needs the system `python3` with `websockets` and `google-chrome-stable`; it is a
verification aid, not part of the unit suite.
