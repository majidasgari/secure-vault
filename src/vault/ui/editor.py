"""Markdown editor with a side preview (SPEC/03 §2.3, §2.4).

The preview is a :class:`QWebEngineView` when QtWebEngine imports, otherwise a
:class:`QTextBrowser`. ``preview_enabled`` is False for ``secret``/``secretfile`` files
and secret text is never handed to the preview widget.
"""

from __future__ import annotations

import html
from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QPlainTextEdit,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from . import i18n

web_views_created = 0
"""Count of :class:`QWebEngineView` instances created (used by the smoke test)."""

_PREVIEW_DEBOUNCE_MS = 400


def render_markdown(text: str) -> str:
    """Render ``text`` as safe HTML (raw HTML disabled), with the current direction."""
    try:
        from markdown_it import MarkdownIt

        body = MarkdownIt("commonmark", {"html": False}).render(text)
    except Exception:  # noqa: BLE001 - never fail to show something
        body = "<pre>" + html.escape(text) + "</pre>"
    direction = "rtl" if i18n.lang == "fa" else "ltr"
    return (
        "<html><head><meta charset='utf-8'/>"
        f"<style>body{{direction:{direction};font-family:sans-serif;"
        "line-height:1.5;padding:8px;}}</style></head>"
        f"<body>{body}</body></html>"
    )


class EditorPanel(QWidget):
    """The markdown source editor plus its preview pane."""

    save_requested = Signal(str, str)
    content_changed = Signal()

    def __init__(self, parent: Any = None) -> None:
        """Create an empty editor."""
        super().__init__(parent)
        self.current_path: str | None = None
        self.preview_enabled = True
        self.preview_kind = "text"
        self._dirty = False
        self._loading = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.splitter = QSplitter(Qt.Horizontal, self)
        self.source = QPlainTextEdit(self)
        self.source.setPlaceholderText(i18n.tr("editor.placeholder"))
        self.preview = self._create_preview()
        self.splitter.addWidget(self.source)
        self.splitter.addWidget(self.preview)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 1)
        layout.addWidget(self.splitter)

        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.setInterval(_PREVIEW_DEBOUNCE_MS)
        self._render_timer.timeout.connect(self._render_preview)

        self.source.textChanged.connect(self._on_text_changed)
        i18n.bind(self, self.retranslate)

    # ------------------------------------------------------------------ preview
    def _create_preview(self) -> QWidget:
        """Create a web preview when possible, falling back to a text browser."""
        global web_views_created
        try:
            from PySide6.QtWebEngineWidgets import QWebEngineView

            self.preview_kind = "web"
            web_views_created += 1
            return QWebEngineView(self)
        except Exception:  # noqa: BLE001 - offscreen/no-engine fallback
            self.preview_kind = "text"
            return QTextBrowser(self)

    def _render_preview(self) -> None:
        """Render the source into the preview (only when preview is enabled)."""
        if not self.preview_enabled:
            return
        self.preview.setHtml(render_markdown(self.source.toPlainText()))

    def _clear_preview(self) -> None:
        """Blank the preview without ever passing secret content to it."""
        try:
            self.preview.setHtml("")
        except Exception:  # noqa: BLE001 - defensive
            pass

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
        if self.preview_enabled:
            self.preview.setVisible(True)
            self._render_preview()
        else:
            self._clear_preview()
            self.preview.setVisible(False)

    def clear(self) -> None:
        """Empty the editor."""
        self._loading = True
        try:
            self.source.setPlainText("")
        finally:
            self._loading = False
        self.current_path = None
        self._dirty = False
        self._clear_preview()

    def set_preview_enabled(self, enabled: bool) -> None:
        """Toggle the preview pane (used by the View menu)."""
        self.preview_enabled = bool(enabled)
        self.preview.setVisible(self.preview_enabled)
        if self.preview_enabled:
            self._render_preview()
        else:
            self._clear_preview()

    def _on_text_changed(self) -> None:
        """Track dirty state and schedule a preview refresh."""
        if self._loading:
            return
        self._dirty = True
        self.content_changed.emit()
        if self.preview_enabled:
            self._render_timer.start()

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


__all__ = ["EditorPanel", "render_markdown", "web_views_created"]
