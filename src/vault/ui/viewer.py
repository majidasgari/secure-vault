"""Native plain-text viewer for ``secret``/``secretfile`` content (SPEC/03 §2.4, §9).

This dialog deliberately uses only :class:`QPlainTextEdit`: secret content must never
reach a web engine. The module exposes ``last_text`` (and ``uses_web_engine``) so the UI
smoke test can assert the native path was taken.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

from . import i18n, notifications

last_text: str | None = None
"""Content of the most recently opened native viewer (module-level for the tests)."""

last_path: str | None = None
"""Path of the most recently opened native viewer."""

uses_web_engine = False
"""Always False: the native viewer never imports or creates a web view."""

web_views_created = 0
"""Number of web views ever created by this module (always 0)."""


class SecretViewer(QDialog):
    """Read-only native viewer for a single secret file."""

    def __init__(
        self, parent: Any, path: str, text: str, *, tray: Any = None
    ) -> None:
        """Build the viewer for ``path`` showing ``text``."""
        super().__init__(parent)
        self.path = path
        self.text = text
        self._tray = tray
        self.setModal(False)
        self.resize(680, 460)

        layout = QVBoxLayout(self)
        self.path_label = QLabel(path, self)
        self.path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.path_label)

        self.edit = QPlainTextEdit(self)
        self.edit.setReadOnly(True)
        self.edit.setPlainText(text)
        layout.addWidget(self.edit, 1)

        self.buttons = QDialogButtonBox(self)
        self.copy_button = QPushButton(i18n.tr("viewer.copy"), self)
        self.copy_button.clicked.connect(self.copy_all)
        self.buttons.addButton(self.copy_button, QDialogButtonBox.ActionRole)
        self.buttons.addButton(QDialogButtonBox.Close)
        self.buttons.rejected.connect(self.close)
        self.buttons.clicked.connect(self._on_clicked)
        layout.addWidget(self.buttons)

        self.retranslate()
        i18n.bind(self, self.retranslate)

    def _on_clicked(self, button: Any) -> None:
        """Close the dialog when the Close button is pressed."""
        if self.buttons.standardButton(button) == QDialogButtonBox.Close:
            self.close()

    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.setWindowTitle(i18n.tr("viewer.title"))
        self.copy_button.setText(i18n.tr("viewer.copy"))

    def copy_all(self) -> None:
        """Copy the whole content to the clipboard and notify."""
        QApplication.clipboard().setText(self.text)
        notifications.notify(
            i18n.tr("notification.copied"),
            i18n.tr("viewer.copied_body", path=self.path),
            tray=self._tray,
        )


def open_viewer(parent: Any, path: str, text: str, *, tray: Any = None) -> SecretViewer:
    """Open (non-modally) the native viewer and remember the last content."""
    global last_text, last_path
    last_text = text
    last_path = path
    dialog = SecretViewer(parent, path, text, tray=tray)
    dialog.show()
    return dialog


__all__ = [
    "SecretViewer",
    "open_viewer",
    "last_text",
    "last_path",
    "uses_web_engine",
    "web_views_created",
]
