# SPEC 08 — Markdown editor: correct RTL/LTR, and "edit in the browser" (P8)

Two complaints from the user, both about the editor in the middle of the desktop app:

> «وضعیت markdown editor وسط اپ هم میتونه خیلی بهتر باشه به نظرم. حداقل راستچین و چپچینش درست
> باشه. یا حتی توی براوزر نشون بده و ادیت بشه.»

So: (1) bidi must be right — a Persian paragraph must be RTL and right-aligned, a code block or
an English paragraph must stay LTR; and (2) editing must be possible in the browser too, from
the app.

## Part A — bidi-correct editing (`src/vault/ui/editor.py` + new `src/vault/ui/bidi.py`)

1. **`bidi.py`** (pure, no Qt, unit-testable):
   ```python
   def needs_rtl(text: str) -> bool          # ≥1 visible Persian/Arabic letter (Script=Arabic,
                                             # incl. Persian digits) and the FIRST strong char is
                                             # Persian/Arabic -> RTL. Reuse the same rules the
                                             # farsi-helper addon uses (documented there).
   def block_direction(text: str, *, in_fence: bool) -> str   # "rtl" | "ltr"
   def split_blocks(markdown: str) -> list[tuple[str, bool]]  # (block_text, in_fence)
   ```
   Rules: a line inside a ```/~~~ fence is always LTR; a block whose text is ≥ 60 % ASCII
   letters/digits and contains no Persian letter is LTR; a heading/list/quote whose *content*
   is Persian is RTL (the marker stays at the visual right in RTL); empty/whitespace blocks
   inherit the previous block's direction.
2. **Per-block formatting in `EditorPanel`**: after loading a document, and on each edit
   (debounced 150 ms, only the edited block), apply a `QTextBlockFormat` with
   `setTextDirection(Qt.RightToLeft|LeftToRight)` and the matching alignment
   (`AlignRight` for rtl, `AlignLeft` for ltr) using a `QTextCursor`, guarded by
   `beginEditBlock/endEditBlock` so undo stays sane and the document is not marked dirty by the
   formatting pass. Code-fence blocks additionally get a **monospace** `QTextCharFormat`
   (family from the theme: `ui-monospace, DejaVu Sans Mono, Consolas, monospace`) so code looks
   like code while typing; other blocks get the UI font (Vazirmatn for `fa`).
3. **Mode control**: a small segmented control in the editor toolbar — **خودکار / راستبهچپ /
   چپبهراست** (`Ctrl+Shift+D` cycles). `auto` = the per-block pass above; `rtl`/`ltr` = one
   direction for the whole document (still keeping fences monospace). The choice persists in
   `~/.config/secure-vault/ui.json` (`editor_direction`).
4. **Status line** under the editor: current block direction + line/column + "کد" when inside a
   fence — so the behaviour is visible, not magic.
5. **Preview**: the markdown → HTML path must set `dir="auto"` on every block element
   (`p, li, td, th, h1-h6, blockquote`) and `dir="ltr"` on `pre/code`, so the preview is also
   correct for mixed Persian/Latin content; `vault:/attachments/…` links resolve to
   `/api/blob`-style file URLs only in the web UI (in the desktop preview they keep the current
   behaviour and render as links).
6. **Secret rules are unchanged**: preview stays disabled for `secret`/`secretfile`; the plain
   viewer for `secretfile` remains the only place its text is shown, and it gets the same
   per-block bidi treatment *without* any markdown rendering.

## Part B — "show/edit in the browser" from the app

7. A toolbar button and a menu item: **«ویرایش در مرورگر»** (and «نمایش در مرورگر» when the file
   is `normal`): opens `http://127.0.0.1:<port>/#/note/<url-encoded logical path>` in the user's
   default browser via `QDesktopServices.openUrl`.
   * If the web server is not running, start it **detached** (`bin/secure-vault-web --home <the
     unlocked vault>`, no token on the command line) and wait up to 10 s for
     `runtime_dir()/secure-vault/web.token` + the port file, then open the token URL
     (`/?token=…` → sets the cookie → SPA deep-links to the note). Never print the token into
     the app log.
   * While the vault is locked the button is disabled (a locked vault cannot be served).
   * Offscreen/self-test mode: the button only computes the URL (`EditorPanel.browser_url`)
     instead of launching anything.
8. `docs/WEBUI.md` and the README get a short "editing in the browser from the app" paragraph.

## Tests (extend the UI suites; headless under `QT_QPA_PLATFORM=offscreen`)

* `tests/test_bidi.py`: `needs_rtl` / `block_direction` / `split_blocks` tables — Persian
  paragraph → rtl, `English only` → ltr, a Persian paragraph that *starts* with a Latin word →
  ltr, a Persian paragraph starting with a Persian digit → **rtl**, fenced code with Persian
  comments → ltr, empty line inherits the previous block.
* `tests/test_ui_smoke.py` additions: load a note with a Persian paragraph + a fence; assert the
  first block's direction is RTL and its alignment is right, the fence block is LTR **and**
  monospace, an English block is LTR; cycling the mode control with `Ctrl+Shift+D` sets the
  document direction uniformly; the preview HTML of a Persian note contains `dir="auto"` and a
  `dir="ltr"` pre; `editor.browser_url` for a note equals
  `http://127.0.0.1:<port>/#/note/<encoded>` and is `None` while locked.
* `tests/test_ui_import.py`-style isolation: the formatting pass must not mark the document
  dirty (`editor.is_dirty()` stays False after a load+format) — a regression that would bug the
  user immediately.
