"""Markdown source editor (SPEC/03 §2.3, SPEC/08 §A).

There is no preview pane: the rendered note lives in the web UI (the browser), which is where
the user goes when they want to read the output. The editor is the source plus the version
history and the two "work on this file elsewhere" buttons.

SPEC/08 adds bidi-correct editing: every block gets its own text direction/alignment, decided
per block from :mod:`vault.ui.bidi` — there is no manual override, the direction is always
automatic. Fenced code is rendered monospace. Editing only reformats the block under the caret —
a full document pass on every keystroke re-laid out (and janked) large notes. The formatting pass
never marks the document dirty.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QTextBlockFormat, QTextCursor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from . import bidi, i18n
from .highlight import MarkdownHighlighter

_LOG = logging.getLogger(__name__)

_BIDI_DEBOUNCE_MS = 150
_DIRECTION_KEYS = {"rtl": "editor.direction_rtl", "ltr": "editor.direction_ltr"}

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
    """The markdown source editor (no preview pane — the browser renders the note)."""

    save_requested = Signal(str, str)
    content_changed = Signal()
    open_in_browser = Signal(str)
    open_text_editor = Signal(str)
    #: ``(path, note)`` when the user edits the short note of the open file.
    note_changed = Signal(str, str)
    #: Emitted with the current path when the user asks for the version history.
    history_requested = Signal(str)

    def __init__(self, parent: Any = None) -> None:
        """Create an empty editor."""
        super().__init__(parent)
        self.current_path: str | None = None
        self.web_port: int | None = None
        self.locked = True
        self._dirty = False
        self._loading = False
        self._formatting = False
        self._loading_note = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        self.browser_button = QPushButton(self)
        self.browser_button.clicked.connect(self._on_browser_clicked)
        self.text_editor_button = QPushButton(self)
        self.text_editor_button.clicked.connect(self._on_text_editor_clicked)
        self.history_button = QPushButton(self)
        self.history_button.clicked.connect(self._on_history_clicked)
        toolbar.addStretch(1)
        toolbar.addWidget(self.history_button)
        toolbar.addWidget(self.text_editor_button)
        toolbar.addWidget(self.browser_button)
        layout.addLayout(toolbar)

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
        layout.addWidget(self.source, 1)

        # The short note of the open file used to be a caption row above the text; it lives on the
        # bottom line now, next to the status, as one quiet field with only its placeholder.
        self.status_label = QLabel(self)
        self.note_edit = QLineEdit(self)
        self.note_edit.setClearButtonEnabled(True)
        self.note_edit.setPlaceholderText(i18n.tr("editor.file_note_placeholder"))
        self.note_edit.editingFinished.connect(self._on_note_edited)
        bottom = QHBoxLayout()
        bottom.addWidget(self.status_label)
        bottom.addSpacing(12)
        bottom.addWidget(self.note_edit, 1)
        layout.addLayout(bottom)

        self._bidi_timer = QTimer(self)
        self._bidi_timer.setSingleShot(True)
        self._bidi_timer.setInterval(_BIDI_DEBOUNCE_MS)
        self._bidi_timer.timeout.connect(self._apply_current_block_bidi)

        self.source.textChanged.connect(self._on_text_changed)
        self.source.cursorPositionChanged.connect(self._update_status)
        i18n.bind(self, self.retranslate)
        self.retranslate()
        self._refresh_actions()

    # ------------------------------------------------------------------ content
    def set_content(self, path: str, text: str) -> None:
        """Load ``text`` for ``path`` into the source editor."""
        self.current_path = path
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
        self._refresh_actions()

    # ------------------------------------------------------------------- bidi
    def _block_direction(self, text: str, in_fence: bool, previous: str | None = None) -> str:
        """Resolve the direction for one block — always automatic, never overridden."""
        return bidi.block_direction(text, in_fence=in_fence, previous=previous)

    def _format_block(
        self,
        cursor: QTextCursor,
        block: Any,
        previous: str | None,
        in_fence: bool,
    ) -> str:
        """Set one block's layout direction/alignment and return the chosen direction."""
        direction = self._block_direction(block.text(), in_fence, previous)
        fmt = QTextBlockFormat()
        fmt.setLayoutDirection(
            Qt.LayoutDirection.RightToLeft
            if direction == "rtl"
            else Qt.LayoutDirection.LeftToRight
        )
        # AlignAbsolute keeps the alignment from being mirrored by the widget's own layout
        # direction, which is what left the Persian text on the wrong side.
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
        return direction

    def _apply_bidi(self) -> None:
        """Apply per-block direction/alignment to the whole document (SPEC/08 §A.2).

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
                in_fence = flags[number] if number < len(flags) else False
                previous = self._format_block(cursor, block, previous, in_fence)
                block = block.next()
            cursor.endEditBlock()
        except Exception as exc:  # noqa: BLE001 - formatting must never hide the text
            _LOG.warning("bidi pass failed: %s", exc)
        finally:
            self._formatting = False
            try:
                self.source.document().setModified(False)
            except Exception:  # noqa: BLE001 - defensive
                pass

    def _apply_current_block_bidi(self) -> None:
        """Apply the direction format to the block under the caret only (SPEC/08 §A.2).

        The full-document pass is reserved for loading a note and mode changes. Re-running it
        on every keystroke re-laid out the whole note (over a second for a large file) and made
        the caret jump; an edit only ever changes the block being typed in. ``in_fence`` comes
        from the highlighter's block state, so no document-wide scan is needed.
        """
        if self._formatting:
            return
        self._formatting = True
        try:
            block = self.source.textCursor().block()
            if not block.isValid():
                return
            previous: str | None = None
            previous_block = block.previous()
            if previous_block.isValid():
                previous = (
                    "rtl"
                    if previous_block.blockFormat().layoutDirection()
                    == Qt.LayoutDirection.RightToLeft
                    else "ltr"
                )
            cursor = QTextCursor(block)
            cursor.beginEditBlock()
            self._format_block(cursor, block, previous, self.highlighter.in_fence(block))
            cursor.endEditBlock()
        except Exception as exc:  # noqa: BLE001 - formatting must never hide the text
            _LOG.warning("bidi pass failed: %s", exc)
        finally:
            self._formatting = False

    def _update_status(self) -> None:
        """Show the current block direction, line/column and code state."""
        cursor = self.source.textCursor()
        block = cursor.block()
        line = block.blockNumber() + 1
        column = cursor.positionInBlock() + 1
        in_fence = self.highlighter.in_fence(block)
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
        """Re-evaluate the enablement of the toolbar buttons.

        Called whenever the lock state *or* the current path changes: refreshing only on lock
        changes left both buttons disabled forever (opening a file never re-enabled them).
        """
        enabled = self.current_path is not None and not self.locked
        for button in (self.browser_button, self.text_editor_button, self.history_button):
            button.setEnabled(enabled)

    # ------------------------------------------------------------------ signals
    def _on_text_changed(self) -> None:
        """Track dirty state and re-apply the bidi format to the edited block."""
        if self._loading or self._formatting:
            return
        self._dirty = True
        self.content_changed.emit()
        self._bidi_timer.start()
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
        self.note_edit.setPlaceholderText(i18n.tr("editor.file_note_placeholder"))
        self.history_button.setText(i18n.tr("editor.history"))
        self.browser_button.setText(i18n.tr("editor.edit_in_browser"))
        self.text_editor_button.setText(i18n.tr("editor.open_text_editor"))
        # The highlighter rewrites character formats and Qt reports that as a text
        # change; highlighting must never mark the document as unsaved.
        dirty = self._dirty
        self.highlighter.refresh()
        self._dirty = dirty
        self._update_status()


__all__ = ["EditorPanel"]
