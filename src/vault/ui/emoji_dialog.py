"""The emoji picker for one path (SPEC/03 §2.3).

The palette is fetched from the service (``core/emoji.py``) so the desktop app and the browser
offer exactly the same choices — a vault whose folder map is labelled from two different sets
of glyphs stops being readable as a map. The free-text field covers everything else, including
sequences the palette has no room for.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from . import i18n
from ..core.emoji import WARNING

#: Keep in step with ``core/emoji.py`` — the API refuses a longer label anyway.
MAX_CODEPOINTS = 16

#: How many palette buttons fit on one row of the dialog.
COLUMNS = 8


class EmojiDialog(QDialog):
    """Pick (or clear) the emoji label of one folder or file."""

    def __init__(
        self,
        groups: list[dict[str, Any]],
        current: str | None,
        name: str,
        parent: Any = None,
    ) -> None:
        """Build the dialog for ``name``, pre-selecting ``current``."""
        super().__init__(parent)
        self.setWindowTitle(i18n.tr("dialog.emoji"))
        layout = QVBoxLayout(self)

        hint = QLabel(i18n.tr("emoji.hint", name=name), self)
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.preview = QLabel(self)
        self.preview.setObjectName("emoji-preview")
        self.preview.setAlignment(Qt.AlignCenter)
        preview_font = self.preview.font()
        preview_font.setPointSize(preview_font.pointSize() + 12)
        self.preview.setFont(preview_font)
        layout.addWidget(self.preview)

        self.field = QLineEdit(self)
        self.field.setPlaceholderText(i18n.tr("emoji.custom"))
        layout.addWidget(self.field)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        inner = QWidget(scroll)
        box = QVBoxLayout(inner)
        for group in groups:
            title = QLabel(i18n.tr(str(group.get("group", ""))), inner)
            title.setStyleSheet("color: palette(mid);")
            box.addWidget(title)
            grid = QGridLayout()
            grid.setSpacing(4)
            for index, glyph in enumerate(group.get("items") or []):
                button = QPushButton(str(glyph), inner)
                button.setFixedSize(40, 40)
                button.setFlat(True)
                button.setToolTip(str(glyph))
                button.clicked.connect(
                    lambda _checked=False, value=str(glyph): self.field.setText(value)
                )
                grid.addWidget(button, index // COLUMNS, index % COLUMNS)
            box.addLayout(grid)
        box.addStretch(1)
        scroll.setWidget(inner)
        layout.addWidget(scroll, 1)

        buttons = QDialogButtonBox(self)
        clear = buttons.addButton(i18n.tr("emoji.clear"), QDialogButtonBox.ResetRole)
        clear.clicked.connect(lambda: self.field.setText(""))
        buttons.addButton(QDialogButtonBox.Ok)
        buttons.addButton(QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.field.textChanged.connect(lambda _text: self._refresh_preview())
        self.field.setText((current or "").strip())
        self._refresh_preview()
        self.resize(440, 560)

    # ------------------------------------------------------------------ values
    def value(self) -> str | None:
        """Return the chosen label, or ``None`` for "no emoji"."""
        return self.field.text().strip() or None

    # ------------------------------------------------------------------ internals
    def _refresh_preview(self) -> None:
        """Show the current choice large, or a dash when there is none."""
        self.preview.setText(self.field.text().strip() or "—")

    def _on_accept(self) -> None:
        """Refuse an over-long label before the API has to."""
        if len(self.field.text().strip()) > MAX_CODEPOINTS:
            self.field.setToolTip(i18n.tr("emoji.too_long", max=MAX_CODEPOINTS))
            self.preview.setText(WARNING)
            return
        self.accept()


__all__ = ["COLUMNS", "MAX_CODEPOINTS", "EmojiDialog"]
