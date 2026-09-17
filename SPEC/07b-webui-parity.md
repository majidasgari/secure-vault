# SPEC 07b — Web UI parity with the Joplin mirror browser (`browser.py`)

The user's requirement: *the vault's web UI must have at least the features of the existing
mirror browser UI*. That reference implementation is
`/data/Cloud/Documents/Notes/joplin-mirror/browser.py` (924 lines, self-contained: one
`BaseHTTPRequestHandler` + one embedded HTML/CSS/JS page, dark, RTL Persian). Every item below
was read out of that file and must be present in `src/vault/webui/` — with the vault's extra
security model (levels, tokens, locked mode) on top, never instead.

## 1. Theme and layout (browser.py `:root`, `header`, `main`, `#side`, `#view`)

* Dark theme **by default**, same palette family:
  `--bg #17181c · --panel #1e2026 · --panel2 #262932 · --border #33363f · --text #d6d8de ·
  --muted #8a8f9a · --accent #5b9dff · --note #2a2d36 · --code #121318`, plus a light theme
  toggle that persists in `sessionStorage` (the vault's own preference, not vault data).
* `dir="rtl"` + `lang="fa"` by default, switched with the language toggle; note/file titles get
  `dir="auto"`; code blocks and the plain-text viewer are forced LTR.
* Header: app title with icon, **one global search box** (`type="search"`, placeholder
  «جستجو در همهٔ یادداشتها…», focused with `/` or `Ctrl+F`), and a status text on the right
  (lock state · file count · agents · auto-lock countdown).
* Body: sidebar (≈320 px, resizable is a bonus, collapsible on mobile) + content area
  (`max-width: 860px` for reading, 980 px in edit mode) with `::scrollbar` styling.
* Reading view = rendered markdown; code blocks scroll, `img{max-width:100%}`.

## 2. Sidebar (`#tree`, `#tags`)

* **Collapsible folder tree** rendered from real folders, each row: caret ▸/▾, name, and the
  **note count for the whole subtree** (`note_count`, not just direct children); the active row
  is highlighted; clicking navigates (hash route so Back/Forward work).
* **Tag chips** under the tree: every tag with its count, e.g. `منتورینگ 12`; clicking a chip
  runs the search `tag:<name>`; chips also appear in a note's meta line and are clickable there.
* A level badge per file row (🔓 normal / 🔒 secret / 🔑 secretfile) — the vault addition.

## 3. Views

* **Welcome/empty state** («یک نوتبوک یا یادداشت را از کنار انتخاب کن») when nothing is open.
* **Folder view**: breadcrumbs (`ریشه / … / نام`), a «نوتبوکها» block listing sub-folders with
  counts, then «یادداشتها (n)» listing notes with their last-updated date (YYYY-MM-DD).
* **Note view**: breadcrumb · title (H1) · meta line with `📅 ویرایش` and `🕓 ساخت` dates, tag
  chips, `🔗 منبع` when `source_url` exists (the vault stores it as a tag/metadata; render when
  present, otherwise omit) · the rendered markdown body.
* **Rendered markdown must cover** what `renderMarkdown()` there covers: `#`–`######`
  headings, bold/italic/strikethrough, inline code, fenced code (LTR, scrollable), blockquotes,
  bullet and numbered lists, **task lists with disabled checkboxes and `done` styling**, tables,
  `---` rules, links (new tab, `rel=noopener`), images via `/api/blob?path=…` (relative image
  links resolve inside the vault; `vault:/attachments/…` links from the importer resolve too),
  and inline HTML must be escaped (no raw HTML passthrough).
* **Raw view**: a «متن خام» button opens the file as plain text in a new tab
  (`GET /api/raw?path=…` → `text/plain`, traversal-checked, 403 for `secret`/`secretfile`).
* **Edit view**: split textarea (LTR-safe for code, `resize: vertical`) + live preview,
  a formatting toolbar with exactly these actions — **bold, italic, strike, code, heading,
  quote, bullet list, numbered list, link, image, horizontal rule** — plus **Save (💾)** and
  **Cancel**, a busy state while saving, `Ctrl/Cmd+S`, and a dirty guard.

## 4. Search (`/api/search`) — parity behaviour

One box that searches **title, tags and body** in a single pass and returns, per hit, the note
path/title plus a **snippet = the first matching body line (≤ 220 chars)**, rendered with
`direction: auto`. Supporting syntax: `tag:<name>` filters by tag (and still allows a free-text
part). Limit parameter (default 200 in the reference). The vault's three search *kinds* stay
available as their own tabs (`Filnames` / `Text` / `Semantic`) — the global box is the extra
convenience layer, and it must not leak `secret`/`secretfile` bodies (they may match by name/
tag only; body matches are restricted to `normal` files).

## 5. HTTP surface additions required by the above

* `GET /api/raw?path=…` → `text/plain` bytes of a `normal`/`secret`? → **normal only**
  (like `/api/blob`); secret levels → 403.
* `GET /api/index` → `{"tree": [...], "tags": [{"name", "count"}], "counts": {...}}` so the tree
  and chips render in one round-trip (the reference does exactly this).
* `GET /api/search?q=&tag=&limit=` → the parity search above.
* The vault's existing `/api/call` surface stays as-is for everything else.
* New **UI-only** service methods are allowed for these aggregates (add them to
  `src/vault/api/service.py` alongside the existing table, role `_UI_ONLY`/`_BOTH`):
  `vault.tree` (folders + counts), `vault.all_tags` (name + count), `vault.files_by_tag`.

## 6. Reminder of the vault rules that stay on top

Sensitivity badges, the confirmation gate for `secret`, the plain-text-only viewer for
`secretfile`, the agent secret-request modal, the access-log tab, the settings tab, the token
auth, `no-store` on `/api/*`, no `localStorage` for content, no external URLs, offline.

## 7. Tests to add (extend `tests/test_web.py` and the orchestrator verifier)

* `/api/index` returns the tree with counts and tags with counts for a scratch vault.
* `/api/search?q=` finds a title match, a tag match and a body match, each with a snippet for
  body hits; a `secret` file matches by name/tag but never by body.
* `/api/search?tag=` filters; `tag:` inside `q` works.
* `/api/raw?path=` returns `text/plain` for a normal file; 403 for `secret`/`secretfile`;
  traversal → error.
* the SPA contains the toolbar actions, the tag chips and the tree renderer (static assertions
  over `app.js`: the action names exist, `note_count`/`count` are used, `dir="auto"` present,
  no `http(s)://`, no `localStorage` for content).
