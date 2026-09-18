"""Markdown editor with a side preview (SPEC/03 §2.3, SPEC/08 §A).

The preview is a :class:`QWebEngineView` when QtWebEngine imports, otherwise a
:class:`QTextBrowser`. ``preview_enabled`` is False for ``secret``/``secretfile`` files
and secret text is never handed to the preview widget.

SPEC/08 adds bidi-correct editing: every block gets its own text direction/alignment
(``auto`` follows :mod:`vault.ui.bidi`, ``rtl``/``ltr`` force the whole document) and
fenced code is rendered monospace. The formatting pass never marks the document dirty.
"""

from __future__ import annotations

import html
import logging
import re
from typing import Any
from urllib.parse import quote

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QKeySequence, QShortcut, QTextBlockFormat, QTextCursor
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from . import bidi, i18n
from .highlight import MarkdownHighlighter, pick_palette

_LOG = logging.getLogger(__name__)

web_views_created = 0
"""Count of :class:`QWebEngineView` instances created (used by the smoke test)."""

_PREVIEW_DEBOUNCE_MS = 400
_BIDI_DEBOUNCE_MS = 150
_MONOSPACE = "ui-monospace, DejaVu Sans Mono, Consolas, monospace"
_DIRECTIONS = ("auto", "rtl", "ltr")
#: How long to wait before checking that the web preview actually painted something.
_PREVIEW_CHECK_MS = 1500
#: A rendered page shorter than this means the engine produced nothing usable.
_PREVIEW_MIN_HTML = 200
#: How often to read a web preview's scroll position (it has no Qt scrollbar).
_SCROLL_POLL_MS = 180
#: Ignore the other pane's scroll events for this long after driving it.
_SCROLL_LOCK_MS = 120
_MODE_KEYS = {"auto": "editor.mode_auto", "rtl": "editor.mode_rtl", "ltr": "editor.mode_ltr"}
_DIRECTION_KEYS = {"rtl": "editor.direction_rtl", "ltr": "editor.direction_ltr"}

_BLOCK_TAG = re.compile(r"<(p|li|td|th|h[1-6]|blockquote)(\s|>)")
_CODE_TAG = re.compile(r"<(code)(\s|>)")


_RTL_LETTERS = re.compile(r"[\u0590-\u05ff\u0600-\u06ff\u0750-\u077f\ufb50-\ufdff\ufe70-\ufeff]")
_LATIN_LETTERS = re.compile(r"[A-Za-z]")


def is_rtl_text(text: str) -> bool:
    """True when ``text`` contains at least one RTL letter (the user's rule).

    Any Persian/Arabic character makes the document RTL; per-block ``dir="auto"`` still keeps
    Latin blocks left-aligned inside it. Text with no letters at all follows the UI language.
    """
    rtl = len(_RTL_LETTERS.findall(text))
    latin = len(_LATIN_LETTERS.findall(text))
    if rtl == latin == 0:
        return i18n.lang == "fa"
    return rtl > 0


def preview_css(direction: str, palette: dict[str, str] | None = None) -> str:
    """Return the Kate-like stylesheet used by the preview, for ``direction``."""
    colors = dict(palette or pick_palette())
    mono = _MONOSPACE
    return f"""
    html, body {{ margin: 0; padding: 10px 14px; }}
    body {{
      direction: {direction};
      background: {colors['bg']};
      color: {colors['text']};
      font-family: "Vazirmatn", "Noto Sans Arabic", sans-serif;
      font-size: 15px; line-height: 1.8;
    }}
    h1, h2, h3, h4, h5, h6 {{ color: {colors['heading']}; margin: 1.1em 0 .45em; line-height: 1.4; }}
    h1 {{ font-size: 1.65em; border-bottom: 1px solid {colors['border']}; padding-bottom: .2em; }}
    h2 {{ font-size: 1.35em; }}
    h3 {{ font-size: 1.15em; }}
    p, li, td, th, blockquote {{ direction: auto; }}
    strong {{ color: {colors['text']}; font-weight: 700; }}
    em {{ color: {colors['quote']}; }}
    a {{ color: {colors['link']}; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    code {{
      background: {colors['code_bg']}; color: {colors['code']}; border-radius: 4px;
      padding: 1px 4px; font-family: {mono}; font-size: .92em;
      direction: ltr; unicode-bidi: embed;
    }}
    pre {{
      background: {colors['code_bg']}; border: 1px solid {colors['border']};
      border-radius: 6px; padding: 10px 12px; overflow-x: auto;
      direction: ltr; text-align: left;
    }}
    pre code {{ background: none; padding: 0; font-size: .9em; }}
    blockquote {{
      margin: .8em 0; padding: .1em .9em; color: {colors['quote']};
      border-{ 'right' if direction == 'rtl' else 'left' }: 3px solid {colors['accent']};
    }}
    hr {{ border: 0; border-top: 1px solid {colors['border']}; margin: 1.2em 0; }}
    ul, ol {{ padding-{ 'right' if direction == 'rtl' else 'left' }: 1.6em; }}
    li {{ margin: .18em 0; }}
    li.task-list-item {{ list-style: none; margin-{ 'right' if direction == 'rtl' else 'left' }: -1.2em; }}
    input[type=checkbox] {{ margin-{ 'left' if direction == 'rtl' else 'right' }: .45em; }}
    table {{ border-collapse: collapse; margin: .8em 0; }}
    th, td {{ border: 1px solid {colors['border']}; padding: 5px 9px; }}
    th {{ background: {colors['code_bg']}; color: {colors['heading']}; }}
    img {{ max-width: 100%; }}
    """


def render_markdown(text: str) -> str:
    """Render ``text`` as safe HTML (raw HTML disabled), with per-block direction.

    Every block element gets ``dir="auto"`` and ``pre``/``code`` get ``dir="ltr"`` so a
    mixed Persian/Latin document renders correctly (SPEC/08 §A.5). The stylesheet follows the
    application theme and gives markdown the colour coding the user liked in Kate
    (headings, inline code, fenced code blocks, quotes, tables, links).
    """
    try:
        from markdown_it import MarkdownIt

        md = MarkdownIt("commonmark", {"html": False})
        # GFM tables and strikethrough: commonmark alone renders ``|---|`` as plain text.
        md.enable("table")
        md.enable("strikethrough")
        body = md.render(text)
    except Exception:  # noqa: BLE001 - never fail to show something
        body = "<pre>" + html.escape(text) + "</pre>"
    body = _BLOCK_TAG.sub(lambda m: f"<{m.group(1)} dir=\"auto\"{m.group(2)}", body)
    body = body.replace("<pre>", '<pre dir="ltr">')
    body = _CODE_TAG.sub(lambda m: f'<code dir="ltr"{m.group(2)}', body)
    direction = "rtl" if is_rtl_text(text) else "ltr"
    lang = "fa" if direction == "rtl" else "en"
    return (
        "<!doctype html><html dir='{}' lang='{}'><head><meta charset='utf-8'/>"
        "<style>{}</style></head><body>{}</body></html>"
    ).format(direction, lang, preview_css(direction), body)


def _fence_flags(lines: list[str]) -> list[bool]:
    """Return a per-line flag marking fence delimiter lines and fence content."""
    flags: list[bool] = []
    fence = False
    for line in lines:
        stripped = line.strip()
        is_fence = stripped.startswith("```") or stripped.startswith("~~~")
        if is_fence:
            flags.append(True)
            fence = not fence
        else:
            flags.append(fence)
    return flags


class EditorPanel(QWidget):
    """The markdown source editor plus its preview pane."""

    save_requested = Signal(str, str)
    content_changed = Signal()
    open_in_browser = Signal(str)
    open_text_editor = Signal(str)
    direction_changed = Signal(str)
    #: ``(path, note)`` when the user edits the short note of the open file.
    note_changed = Signal(str, str)
    #: Emitted with the current path when the user asks for the version history.
    history_requested = Signal(str)

    def __init__(self, parent: Any = None) -> None:
        """Create an empty editor."""
        super().__init__(parent)
        self.current_path: str | None = None
        self.preview_enabled = True
        self.preview_kind = "text"
        self.web_port: int | None = None
        self.locked = True
        self._dirty = False
        self._loading = False
        self._formatting = False
        self._direction_mode = "auto"
        self._loading_note = False
        self._scroll_lock = False
        self._last_preview_fraction = 0.0
        self._preview_poll: QTimer | None = None
        self._preview_checked = False
        self._split_applied = False
        self._preview_load_ok: bool | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        self.direction_combo = QComboBox(self)
        for mode in _DIRECTIONS:
            self.direction_combo.addItem("", mode)
        self.direction_combo.currentIndexChanged.connect(self._on_direction_changed)
        self.direction_label = QLabel(self)
        self.browser_button = QPushButton(self)
        self.browser_button.clicked.connect(self._on_browser_clicked)
        self.text_editor_button = QPushButton(self)
        self.text_editor_button.clicked.connect(self._on_text_editor_clicked)
        self.history_button = QPushButton(self)
        self.history_button.clicked.connect(self._on_history_clicked)
        toolbar.addWidget(self.direction_label)
        toolbar.addWidget(self.direction_combo)
        toolbar.addStretch(1)
        toolbar.addWidget(self.history_button)
        toolbar.addWidget(self.text_editor_button)
        toolbar.addWidget(self.browser_button)
        layout.addLayout(toolbar)

        note_row = QHBoxLayout()
        self.note_label = QLabel(self)
        self.note_edit = QLineEdit(self)
        self.note_edit.setClearButtonEnabled(True)
        self.note_edit.editingFinished.connect(self._on_note_edited)
        note_row.addWidget(self.note_label)
        note_row.addWidget(self.note_edit, 1)
        layout.addLayout(note_row)

        self.splitter = QSplitter(Qt.Horizontal, self)
        self.source = QTextEdit(self)
        # ``QTextEdit`` and not ``QPlainTextEdit``: the plain-text layout engine
        # (``QPlainTextDocumentLayout``) ignores a block's alignment, so Persian lines stayed
        # hard against the left edge even though the block format said AlignRight (measured).
        # With rich text disabled it still behaves like a plain markdown editor.
        self.source.setAcceptRichText(False)
        self.source.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.source.setPlaceholderText(i18n.tr("editor.placeholder"))
        # Kate-like markdown colours (character formats) — the bidi pass owns block formats.
        self.highlighter = MarkdownHighlighter(self.source.document())
        self.preview = self._create_preview()
        self.preview.setMinimumWidth(260)
        self.splitter.addWidget(self.source)
        self.splitter.addWidget(self.preview)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 1)
        # Without an explicit split the web view is handed 0 px and the whole lower area looks
        # empty (the "wasted space" bug): give both panes half of the width, and never let a
        # child collapse to nothing.
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setSizes([1, 1])
        layout.addWidget(self.splitter, 1)
        self._setup_scroll_sync()

        self.status_label = QLabel(self)
        layout.addWidget(self.status_label)

        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.setInterval(_PREVIEW_DEBOUNCE_MS)
        self._render_timer.timeout.connect(self._render_preview)

        self._bidi_timer = QTimer(self)
        self._bidi_timer.setSingleShot(True)
        self._bidi_timer.setInterval(_BIDI_DEBOUNCE_MS)
        self._bidi_timer.timeout.connect(self._apply_bidi)

        self.source.textChanged.connect(self._on_text_changed)
        self.source.cursorPositionChanged.connect(self._update_status)
        self._direction_shortcut = QShortcut(QKeySequence("Ctrl+Shift+D"), self)
        self._direction_shortcut.setContext(Qt.WidgetWithChildrenShortcut)
        self._direction_shortcut.activated.connect(self.cycle_direction)
        i18n.bind(self, self.retranslate)
        self.retranslate()

    # ------------------------------------------------------------------ preview
    def _create_preview(self) -> QWidget:
        """Create a web preview when possible, falling back to a text browser."""
        global web_views_created
        try:
            from PySide6.QtWebEngineWidgets import QWebEngineView

            self.preview_kind = "web"
            web_views_created += 1
            view = QWebEngineView(self)
            # A failed load means the engine cannot render here: swap to a text browser.
            view.loadFinished.connect(self._on_preview_loaded)
            return view
        except Exception:  # noqa: BLE001 - offscreen/no-engine fallback
            self.preview_kind = "text"
            return QTextBrowser(self)

    def _on_preview_loaded(self, ok: bool) -> None:
        """Remember whether the web engine managed to load the page."""
        self._preview_load_ok = bool(ok)
        if not ok:
            self._fallback_preview("load failed")

    def showEvent(self, event: Any) -> None:  # noqa: N802 - Qt API
        """Give both panes half of the width the first time the panel is shown."""
        super().showEvent(event)
        self._balance_split()

    def resizeEvent(self, event: Any) -> None:  # noqa: N802 - Qt API
        """Keep the initial 50/50 split when the panel is first laid out."""
        super().resizeEvent(event)
        if not self._split_applied:
            self._balance_split()

    def _balance_split(self) -> None:
        """Split the width evenly once (the web view otherwise collapses to 0 px)."""
        if self._split_applied:
            return
        self._split_applied = True
        half = max(self.splitter.width() or self.width(), 400) // 2
        QTimer.singleShot(0, lambda: self.splitter.setSizes([half, half]))

    def _render_preview(self) -> None:
        """Render the source into the preview (only when preview is enabled)."""
        if not self.preview_enabled:
            return
        self.preview.setHtml(render_markdown(self.source.toPlainText()))
        # Re-rendering resets the preview to the top; keep it aligned with the source.
        if self.preview_kind == "web":
            QTimer.singleShot(60, lambda: self._on_source_scroll(0))
        else:
            self._on_source_scroll(0)
        if not self._preview_checked:
            self._preview_checked = True
            # A web view that fails to paint (no GPU / broken sandbox) looks like a blank grey
            # panel: verify once and fall back to a text browser so the preview always shows.
            QTimer.singleShot(_PREVIEW_CHECK_MS, self._verify_preview)

    def _verify_preview(self) -> None:
        """Swap in a :class:`QTextBrowser` when the web engine never rendered anything."""
        if self.preview_kind != "web":
            return
        if self._preview_load_ok is None:
            # No loadFinished at all: the engine is not working here (no GPU/sandbox), so the
            # pane would stay blank forever. Do not wait for a callback that never comes.
            self._fallback_preview("no loadFinished")
            return
        if not self._preview_load_ok:
            self._fallback_preview("load failed")
            return
        view: Any = self.preview
        try:
            page = view.page()
        except Exception:  # noqa: BLE001 - defensive
            self._fallback_preview("no page")
            return

        def done(body: str) -> None:
            if len(body or "") < _PREVIEW_MIN_HTML:
                self._fallback_preview("empty render")

        try:
            page.toHtml(done)
        except Exception:  # noqa: BLE001
            self._fallback_preview("toHtml failed")

    def _fallback_preview(self, reason: str) -> None:
        """Replace the web view with a text browser and re-render the current document."""
        if self.preview_kind != "web":
            return
        _LOG.warning("preview web view produced nothing (%s); using a text browser", reason)
        index = self.splitter.indexOf(self.preview)
        old: Any = self.preview
        browser = QTextBrowser(self)
        browser.setOpenExternalLinks(False)
        try:
            old.page().deleteLater()
        except Exception:  # noqa: BLE001 - defensive
            pass
        old.setParent(None)
        old.deleteLater()
        self.preview = browser
        self.preview_kind = "text"
        self.preview.setMinimumWidth(260)
        if self._preview_poll is not None:
            self._preview_poll.stop()
            self._preview_poll = None
        self.preview.verticalScrollBar().valueChanged.connect(self._on_preview_scroll)
        self._last_preview_fraction = 0.0
        if index >= 0:
            self.splitter.insertWidget(index, browser)
        else:
            self.splitter.addWidget(browser)
        self.splitter.setSizes([1, 1])
        browser.setVisible(self.preview_enabled)
        if self.preview_enabled:
            self.preview.setHtml(render_markdown(self.source.toPlainText()))

    def _clear_preview(self) -> None:
        """Blank the preview without ever passing secret content to it."""
        try:
            self.preview.setHtml("")
        except Exception:  # noqa: BLE001 - defensive
            pass

    # -------------------------------------------------------------- scroll sync
    def _setup_scroll_sync(self) -> None:
        """Keep the source and the preview at roughly the same scroll position."""
        self.source.verticalScrollBar().valueChanged.connect(self._on_source_scroll)
        if self.preview_kind == "text":
            self.preview.verticalScrollBar().valueChanged.connect(
                self._on_preview_scroll
            )
        else:
            self._preview_poll = QTimer(self)
            self._preview_poll.setInterval(_SCROLL_POLL_MS)
            self._preview_poll.timeout.connect(self._poll_preview_scroll)
            self._preview_poll.start()

    def _source_fraction(self) -> float:
        """Return the source scrollbar position as a 0..1 fraction."""
        bar = self.source.verticalScrollBar()
        span = bar.maximum() - bar.minimum()
        return (bar.value() - bar.minimum()) / span if span > 0 else 0.0

    def _scroll_source_to(self, fraction: float) -> None:
        """Move the source scrollbar to ``fraction`` (clamped to 0..1)."""
        bar = self.source.verticalScrollBar()
        span = bar.maximum() - bar.minimum()
        bar.setValue(int(bar.minimum() + max(0.0, min(1.0, fraction)) * span))

    def _release_scroll_lock(self) -> None:
        """Allow the other pane to drive again after a programmatic sync."""
        self._scroll_lock = False

    def _on_source_scroll(self, _value: int) -> None:
        """Source scrolled: move the preview to the same fraction."""
        if self._scroll_lock:
            return
        fraction = self._source_fraction()
        self._scroll_lock = True
        self._last_preview_fraction = fraction
        if self.preview_kind == "text":
            bar = self.preview.verticalScrollBar()
            span = bar.maximum() - bar.minimum()
            bar.setValue(int(bar.minimum() + fraction * span))
        else:
            try:
                self.preview.page().runJavaScript(
                    "window.scrollTo(0, %f * Math.max(0, "
                    "document.documentElement.scrollHeight - window.innerHeight));"
                    % fraction
                )
            except Exception:  # noqa: BLE001 - sync is best effort
                pass
        QTimer.singleShot(_SCROLL_LOCK_MS, self._release_scroll_lock)

    def _on_preview_scroll(self, _value: int) -> None:
        """Text-browser preview scrolled: move the source to the same fraction."""
        if self._scroll_lock:
            return
        bar = self.preview.verticalScrollBar()
        span = bar.maximum() - bar.minimum()
        fraction = (bar.value() - bar.minimum()) / span if span > 0 else 0.0
        self._scroll_lock = True
        self._scroll_source_to(fraction)
        QTimer.singleShot(_SCROLL_LOCK_MS, self._release_scroll_lock)

    def _poll_preview_scroll(self) -> None:
        """Read the web preview's scroll fraction (it has no Qt scrollbar)."""
        if self._scroll_lock or self.preview_kind != "web":
            return
        try:
            self.preview.page().runJavaScript(
                "(function(){var h=document.documentElement.scrollHeight-"
                "window.innerHeight;return h>0?window.scrollY/h:0;})()",
                self._on_preview_fraction,
            )
        except Exception:  # noqa: BLE001 - sync is best effort
            pass

    def _on_preview_fraction(self, value: Any) -> None:
        """Web preview scrolled (polled): move the source to the same fraction."""
        if self._scroll_lock or not isinstance(value, (int, float)):
            return
        fraction = max(0.0, min(1.0, float(value)))
        if abs(fraction - self._last_preview_fraction) < 0.002:
            return
        self._last_preview_fraction = fraction
        self._scroll_lock = True
        self._scroll_source_to(fraction)
        QTimer.singleShot(_SCROLL_LOCK_MS, self._release_scroll_lock)

    # ------------------------------------------------------------------ content
    def set_content(self, path: str, text: str, *, preview_enabled: bool) -> None:
        """Load ``text`` for ``path``; the preview is disabled for secret levels."""
        self.current_path = path
        self.preview_enabled = bool(preview_enabled)
        self._loading = True
        try:
            self.source.setPlainText(text)
        finally:
            self._loading = False
        self._dirty = False
        try:
            self._apply_bidi()
        except Exception as exc:  # noqa: BLE001 - a formatting problem must not hide content
            _LOG.warning("bidi pass failed while loading %s: %s", path, exc)
        if self.preview_enabled:
            self.preview.setVisible(True)
            self._render_preview()
        else:
            self._clear_preview()
            self.preview.setVisible(False)
        self._refresh_actions()
        self._update_status()

    def set_note(self, text: str) -> None:
        """Show the short note of the currently open file."""
        self._loading_note = True
        try:
            self.note_edit.setText(text or "")
        finally:
            self._loading_note = False

    def _on_note_edited(self) -> None:
        """Emit the edited note for the open file."""
        if self._loading_note or not self.current_path:
            return
        self.note_changed.emit(str(self.current_path), self.note_edit.text())

    def _on_history_clicked(self) -> None:
        """Ask for the version history of the open file."""
        if self.current_path:
            self.history_requested.emit(str(self.current_path))

    def clear(self) -> None:
        """Empty the editor."""
        self._loading = True
        try:
            self.source.setPlainText("")
        finally:
            self._loading = False
        self.current_path = None
        self._dirty = False
        self.set_note("")
        self._clear_preview()
        self._refresh_actions()

    def set_preview_enabled(self, enabled: bool) -> None:
        """Toggle the preview pane (used by the View menu)."""
        self.preview_enabled = bool(enabled)
        self.preview.setVisible(self.preview_enabled)
        if self.preview_enabled:
            self._render_preview()
        else:
            self._clear_preview()

    # ------------------------------------------------------------------- bidi
    def direction_mode(self) -> str:
        """Return the active bidi mode (``auto``/``rtl``/``ltr``)."""
        return self._direction_mode

    def set_direction_mode(self, mode: str) -> None:
        """Set the bidi mode and re-apply the per-block formatting."""
        if mode not in _DIRECTIONS:
            mode = "auto"
        self._direction_mode = mode
        index = self.direction_combo.findData(mode)
        if index >= 0 and self.direction_combo.currentIndex() != index:
            self.direction_combo.blockSignals(True)
            self.direction_combo.setCurrentIndex(index)
            self.direction_combo.blockSignals(False)
        self._apply_bidi()

    def _on_direction_changed(self) -> None:
        """Handle a mode change from the combo and notify listeners."""
        mode = str(self.direction_combo.currentData() or "auto")
        self._direction_mode = mode
        self._apply_bidi()
        self.direction_changed.emit(mode)

    def cycle_direction(self) -> str:
        """Cycle auto → rtl → ltr (``Ctrl+Shift+D``) and return the new mode."""
        order = {"auto": "rtl", "rtl": "ltr", "ltr": "auto"}
        mode = order.get(self._direction_mode, "auto")
        self.set_direction_mode(mode)
        self.direction_changed.emit(mode)
        return mode

    def _block_direction(self, text: str, in_fence: bool, previous: str | None = None) -> str:
        """Resolve the direction for one block under the active mode."""
        if self._direction_mode == "rtl":
            return "rtl"
        if self._direction_mode == "ltr":
            return "ltr"
        return bidi.block_direction(text, in_fence=in_fence, previous=previous)

    def _apply_bidi(self) -> None:
        """Apply per-block direction/alignment (SPEC/08 §A.2).

        Character formats are owned by :class:`~vault.ui.highlight.MarkdownHighlighter`; this
        pass only sets each block's layout direction and alignment, so the two never fight.
        ``QTextBlockFormat`` has ``setLayoutDirection`` (there is no ``setTextDirection`` in
        Qt6/PySide6 — calling it raised ``AttributeError`` and silently disabled RTL).
        """
        if self._formatting:
            return
        self._formatting = True
        try:
            document = self.source.document()
            lines = self.source.toPlainText().split("\n")
            flags = _fence_flags(lines)
            cursor = QTextCursor(document)
            cursor.beginEditBlock()
            block = document.begin()
            previous: str | None = None
            while block.isValid():
                number = block.blockNumber()
                text = block.text()
                in_fence = flags[number] if number < len(flags) else False
                direction = self._block_direction(text, in_fence, previous)
                previous = direction
                fmt = QTextBlockFormat()
                fmt.setLayoutDirection(
                    Qt.LayoutDirection.RightToLeft
                    if direction == "rtl"
                    else Qt.LayoutDirection.LeftToRight
                )
                # AlignAbsolute keeps the alignment from being mirrored by the widget's own
                # layout direction, which is what left the Persian text on the wrong side.
                fmt.setAlignment(
                    (
                        Qt.AlignmentFlag.AlignRight
                        if direction == "rtl"
                        else Qt.AlignmentFlag.AlignLeft
                    )
                    | Qt.AlignmentFlag.AlignAbsolute
                )
                cursor.setPosition(block.position())
                cursor.setBlockFormat(fmt)
                block = block.next()
            cursor.endEditBlock()
        except Exception as exc:  # noqa: BLE001 - formatting must never hide the text
            _LOG.warning("bidi pass failed: %s", exc)
        finally:
            self._formatting = False
            self._dirty = False
            try:
                self.source.document().setModified(False)
            except Exception:  # noqa: BLE001 - defensive
                pass

    def _update_status(self) -> None:
        """Show the current block direction, line/column and code state."""
        cursor = self.source.textCursor()
        block = cursor.block()
        line = block.blockNumber() + 1
        column = cursor.positionInBlock() + 1
        lines = self.source.toPlainText().split("\n")
        flags = _fence_flags(lines)
        in_fence = flags[block.blockNumber()] if block.blockNumber() < len(flags) else False
        direction = self._block_direction(block.text(), in_fence)
        text = i18n.tr(
            "editor.status",
            direction=i18n.tr(_DIRECTION_KEYS.get(direction, "editor.direction_ltr")),
            line=line,
            column=column,
        )
        if in_fence:
            text += " · " + i18n.tr("editor.code")
        self.status_label.setText(text)

    # ----------------------------------------------------------------- browser
    @property
    def browser_url(self) -> str | None:
        """Return the web note URL, or None while locked / without a web port."""
        if self.locked or not self.current_path or not self.web_port:
            return None
        return (
            f"http://127.0.0.1:{int(self.web_port)}/#/note/"
            + quote(str(self.current_path), safe="")
        )

    def _on_browser_clicked(self) -> None:
        """Emit the browser request for the current path."""
        if self.current_path:
            self.open_in_browser.emit(str(self.current_path))

    def _on_text_editor_clicked(self) -> None:
        """Emit the external-text-editor request for the current path."""
        if self.current_path:
            self.open_text_editor.emit(str(self.current_path))

    def set_locked(self, locked: bool) -> None:
        """Enable the two "open elsewhere" buttons only while the vault is unlocked."""
        self.locked = bool(locked)
        self._refresh_actions()

    def _refresh_actions(self) -> None:
        """Re-evaluate the enablement of the two "open elsewhere" buttons.

        Called whenever the lock state *or* the current path changes: refreshing only on lock
        changes left both buttons disabled forever (opening a file never re-enabled them).
        """
        enabled = self.current_path is not None and not self.locked
        for button in (self.browser_button, self.text_editor_button, self.history_button):
            button.setEnabled(enabled)

    # ------------------------------------------------------------------ signals
    def _on_text_changed(self) -> None:
        """Track dirty state and schedule preview + bidi refreshes."""
        if self._loading or self._formatting:
            return
        self._dirty = True
        self.content_changed.emit()
        self._bidi_timer.start()
        if self.preview_enabled:
            self._render_timer.start()
        self._update_status()

    def is_dirty(self) -> bool:
        """Return True when there are unsaved changes."""
        return self._dirty

    def save(self) -> None:
        """Emit :attr:`save_requested` for the current content."""
        if self.current_path is not None:
            self.save_requested.emit(self.current_path, self.source.toPlainText())

    def mark_saved(self) -> None:
        """Clear the dirty flag after a successful save."""
        self._dirty = False

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.source.setPlaceholderText(i18n.tr("editor.placeholder"))
        self.note_label.setText(i18n.tr("editor.file_note"))
        self.note_edit.setPlaceholderText(i18n.tr("editor.file_note_placeholder"))
        self.history_button.setText(i18n.tr("editor.history"))
        self.direction_label.setText(i18n.tr("editor.direction"))
        for index, mode in enumerate(_DIRECTIONS):
            self.direction_combo.setItemText(index, i18n.tr(_MODE_KEYS[mode]))
        self.browser_button.setText(i18n.tr("editor.edit_in_browser"))
        self.text_editor_button.setText(i18n.tr("editor.open_text_editor"))
        # The highlighter rewrites character formats and Qt reports that as a text
        # change; highlighting must never mark the document as unsaved.
        dirty = self._dirty
        self.highlighter.refresh()
        self._dirty = dirty
        self._update_status()


__all__ = ["EditorPanel", "render_markdown", "web_views_created"]
