# SPEC 09 — Tray as the always-on shell: web UI auto-available, secret gate, live read indicator

User's words (this is the priority order for the next phase):

> «رابط qt هم زیادی بیروح هست. البته مهم نیست. کاربر بیشتر از همه قرار هست از همون رابط وب
> استفاده کنه. ولی وقتی tray بالا میاد باید رابط کاربری وب هم در دسترس باشه کاملا خودکار. اون
> tray رو بیشتر در نظر گرفته بودم برای وقتی که طرف میخواد به جاهای رمز یا secure دسترسی پیدا
> کنه. که یهو دیالوگ نشون بده برای کپی. و همینطور همیشه بنویسه کدوم فایل (چه رمز چه غیر رمز)
> الان داره خونده میشه.»

So: **the web UI is the primary interface**; the Qt window stops being the centre of the product
(no visual-polish work needed) and the **tray becomes a small always-on shell** that
(1) makes the web UI available automatically, (2) is the gate for secret material (a dialog with
a Copy button), and (3) always shows which file is being read right now.

## A. One process, two faces (no second key holder)

1. `VaultApplication` (the Qt process) starts the **web server in-process** after unlock, using
   the same `vault/web` components (`WebServer`), on the **same `VaultSession`** — never a second
   process opening the same vault. Settings (persisted in the vault settings, edited in both the
   Qt settings dialog and the web settings tab):
   ```json
   "web": {"enabled": true, "host": "127.0.0.1", "port": 8788, "allow_lan": false,
           "open_browser_on_start": false}
   ```
   `enabled` defaults to **true** ("وقتی tray بالا میاد باید رابط وب در دسترس باشه").
   `port` 0 = pick a free port; the effective port is exposed as `VaultApplication.web.port`.
2. **Conflicts are handled, never guessed**: if the configured port is taken or another process
   already owns the vault socket / `web.token`, the app does **not** try to take over the vault.
   It logs a warning, keeps its own session locked, and offers the tray item «باز کردن رابط وب»
   pointing at the already-running instance (reading `runtime_dir()/secure-vault/web.token` for
   the URL/port). Documented in `docs/WEBUI.md`.
3. Tray menu (this is the shell's whole surface):
   * **باز کردن رابط وب** — opens the token URL in the default browser (starts the server if it is
     somehow off, waits for the token file, then `QDesktopServices.openUrl`);
   * **کپی لینک رابط وب** — copies `http://host:port/?token=…` to the clipboard (toast), one-time
     convenience, never logged;
   * **قفل فوری** (`Ctrl+L`) — locks the vault and stops serving content (the web UI falls back to
     its unlock screen; the token and port stay up so the browser can unlock);
   * **آخرین خواندهها** — the live read list (see §C);
   * **تنظیمات / خروج**.
   Tooltip: `🔓 باز — آخرین خواندن: <path> — <n> ثانیه پیش` (or `🔒 قفل`).

## B. The secret gate (tray dialog with Copy)

4. Every read/attempt on a `secret`/`secretfile` path from **any** source — an MCP tool call, a
   web API call, an importer — triggers, in this order:
   1. an entry in the activity feed (§C),
   2. a **tray notification**: «<path> — <source> درخواست خواندن کرد»,
   3. for `secretfile`: the existing **request dialog** (`SecretRequestDialog`) but with the
      buttons **«نمایش و کپی» / «رد»**, and the viewer it opens is the native plain-text dialog
      **with a Copy button** (already implemented; keep it as the only path that shows content),
   4. for `secret`: the confirmation dialog before the content is opened by the user.
5. The **web UI may not bypass the gate**: a web `vault.read_file` on `secret`/`secretfile`
   requires the same confirm/show step — implementation: the API returns
   `PERMISSION_DENIED` + `details.requires_approval: true` for those levels, and the SPA then
   calls the dedicated UI-only methods `vault.read_secret` / `vault.request_open_secret` after
   the user clicks «تأیید میکنم» (the same flow as the desktop app, same access-log rows).
   *(The exact request/approve shapes are already defined in `SPEC/02 §1`; reuse them.)*
6. No new way to see content is introduced: the plain-text viewer + Copy is the single endpoint.

## C. Live "which file is being read right now"

7. **Activity feed** (`src/vault/core/session.py` + `api/service.py`):
   ```python
   session.on_activity: Callable[[dict], None] | None      # same pattern as on_secret_request
   # event: {"ts", "source": "mcp"|"web"|"gui"|"importer", "tool", "path", "sensitivity",
   #         "outcome": "allow"|"deny", "bytes": int|None, "session": str|None}
   ```
   Emitted **before** the content is returned (so the indicator is live, not historical) for
   every read of a *file* (not for listings/searches — those are `search`/`list` events which the
   feed also carries but marks as `kind: "list"|"search"|"read"`), and for every deny.
   The Qt thread marshals it with the existing `Signal` pattern.
8. **Tray / desktop app**:
   * tray tooltip = the last `read` event (path + age, refreshed every second while recent);
   * the tray menu's **آخرین خواندهها** submenu lists the last 10 events
     (`زمان — منبع — مسیر — سطح`), clicking an entry opens that file in the web UI;
   * the main window's status bar shows the same last-read line (replacing the vague
     "MCP: n connected" text — keep the count but add the file);
   * if a `secret`/`secretfile` was read in the last 60 s, the tray icon gets an overlay/badge
     (🔑) and the tooltip says so.
9. **Web UI**: `/api/events` (SSE) gains `{"event":"activity", ...}` frames and the SPA shows a
   small **live banner** («الان: خواندن کاری/… توسط mcp») plus an "Activity" section at the top of
   the Log tab (newest first, auto-scroll, filterable). The log tab keeps the full history.
10. **Never** put content in an activity event, only the path/level/source/outcome/byte count.
    The indicator must work while the vault is locked too (denied reads are the most interesting
    ones) — the feed is metadata-only.

## D. Tests to WRITE (the user runs the tests manually; do not loop on running suites)

* `tests/test_activity.py`: reads from `mcp`/`web`/`gui` emit `read` events with path+level+source;
  a denied read emits `deny`; no event carries content; the feed keeps ≤ 200 entries;
  `search`/`list` events are `kind="search"`/`"list"`.
* tray: tooltip contains the last read path and `قفل`/`باز`; the menu builds 10 entries from the
  feed; a `secret` read within 60 s sets the badge flag (`tray.secret_recent`).
* app: `VaultApplication.web` is not None after unlock when `web.enabled` is true; the effective
  port is exposed; `web.open_url()` returns the token URL; `web.copy_link()` puts it on the
  clipboard (clipboard assertion via `QGuiApplication.clipboard()`);
  with `web.enabled=false` no server is started.
* web: `vault.read_file` on `secret` → `PERMISSION_DENIED` with `requires_approval: true`;
  after `vault.read_secret` (UI-only) the SPA path works and two access-log rows exist.
* SSE: an activity event arrives on the stream within 2 s of a read.
