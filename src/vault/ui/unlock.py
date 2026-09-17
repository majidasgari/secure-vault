"""Unlock screen shown before the vault is opened (SPEC/03 §2.1)."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from . import i18n

_BACKOFF_AFTER = 5
_BACKOFF_STEP_SECONDS = 5


class UnlockScreen(QMainWindow):
    """The pre-unlock window: password entry, language switch and vault actions."""

    unlock_requested = Signal(str)
    open_vault_requested = Signal()
    create_vault_requested = Signal()
    language_selected = Signal(str)

    def __init__(self, parent: Any = None) -> None:
        """Create the unlock screen."""
        super().__init__(parent)
        self.failed_attempts = 0
        self._locked_until = 0
        self.setObjectName("unlock-screen")

        central = QWidget(self)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(32, 32, 32, 32)

        self.title_label = QLabel(self)
        self.title_label.setObjectName("unlock-title")
        font = self.title_label.font()
        font.setPointSize(font.pointSize() + 6)
        font.setBold(True)
        self.title_label.setFont(font)
        layout.addWidget(self.title_label)

        self.path_label = QLabel(self)
        self.path_label.setWordWrap(False)
        layout.addWidget(self.path_label)
        layout.addSpacing(12)

        form = QFormLayout()
        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.Password)
        self.password.returnPressed.connect(self._submit)
        self.password_label = QLabel(self)
        form.addRow(self.password_label, self.password)
        layout.addLayout(form)

        self.error_label = QLabel(self)
        self.error_label.setObjectName("unlock-error")
        self.error_label.setStyleSheet("color: #b00020;")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)
        layout.addSpacing(8)

        self.unlock_button = QPushButton(self)
        self.unlock_button.clicked.connect(self._submit)
        layout.addWidget(self.unlock_button)

        actions = QHBoxLayout()
        self.open_button = QPushButton(self)
        self.open_button.clicked.connect(self.open_vault_requested.emit)
        self.create_button = QPushButton(self)
        self.create_button.clicked.connect(self.create_vault_requested.emit)
        actions.addWidget(self.open_button)
        actions.addWidget(self.create_button)
        layout.addLayout(actions)

        layout.addStretch(1)
        self.language_combo = QComboBox(self)
        self.language_combo.addItem("", "fa")
        self.language_combo.addItem("", "en")
        self.language_combo.currentIndexChanged.connect(self._on_language)
        self.setCentralWidget(central)

        self._backoff_timer = QTimer(self)
        self._backoff_timer.setSingleShot(True)
        self._backoff_timer.timeout.connect(self._end_backoff)

        self.retranslate()
        i18n.bind(self, self.retranslate)
        self.password.setFocus()

    # ------------------------------------------------------------------ state
    def set_vault_info(self, title: str, path: str) -> None:
        """Show the vault title and an elided home path."""
        self.title_label.setText(title)
        self.path_label.setText(path)
        self._full_path = path
        self._elide_path()

    def _elide_path(self) -> None:
        """Elide the stored path to the label width."""
        path = getattr(self, "_full_path", "")
        metrics = QFontMetrics(self.path_label.font())
        self.path_label.setText(
            metrics.elidedText(path, Qt.ElideMiddle, max(120, self.width() - 80))
        )

    def resizeEvent(self, event: Any) -> None:  # noqa: N802 - Qt naming
        """Keep the path elided on resize."""
        super().resizeEvent(event)
        self._elide_path()

    def show_error(self, message: str) -> None:
        """Show an inline error (never a modal)."""
        self.error_label.setText(message)

    def clear_error(self) -> None:
        """Clear the inline error."""
        self.error_label.setText("")

    def notify_failure(self) -> None:
        """Record a failed attempt and start the backoff once the threshold is hit."""
        self.failed_attempts += 1
        if self.failed_attempts >= _BACKOFF_AFTER:
            seconds = _BACKOFF_STEP_SECONDS * self.failed_attempts
            self._locked_until = self.failed_attempts
            self.unlock_button.setEnabled(False)
            self.password.setEnabled(False)
            self.show_error(i18n.tr("unlock.locked_out", seconds=seconds))
            self._backoff_timer.start(seconds * 1000)

    def _end_backoff(self) -> None:
        """Re-enable input after the backoff window."""
        self.unlock_button.setEnabled(True)
        self.password.setEnabled(True)
        self.password.setFocus()
        self.clear_error()

    def reset_failures(self) -> None:
        """Forget failed attempts after a successful unlock."""
        self.failed_attempts = 0
        self._locked_until = 0

    # ------------------------------------------------------------------ actions
    def _submit(self) -> None:
        """Emit the entered password when input is enabled."""
        if not self.unlock_button.isEnabled():
            return
        self.unlock_requested.emit(self.password.text())

    def _on_language(self, index: int) -> None:
        """Switch the UI language live and notify listeners."""
        lang = self.language_combo.itemData(index)
        if not lang:
            return
        i18n.set_language(str(lang))
        self.language_selected.emit(str(lang))

    def set_language(self, lang: str) -> None:
        """Reflect the active language in the combo without re-emitting."""
        index = self.language_combo.findData(lang)
        if index >= 0 and index != self.language_combo.currentIndex():
            self.language_combo.blockSignals(True)
            self.language_combo.setCurrentIndex(index)
            self.language_combo.blockSignals(False)

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.setWindowTitle(i18n.tr("unlock.window_title"))
        self.title_label.setText(i18n.tr("unlock.title"))
        self.password_label.setText(i18n.tr("unlock.password"))
        self.password.setPlaceholderText(i18n.tr("unlock.password_placeholder"))
        self.unlock_button.setText(i18n.tr("unlock.unlock"))
        self.open_button.setText(i18n.tr("unlock.open_another"))
        self.create_button.setText(i18n.tr("unlock.create_new"))
        self.language_combo.setItemText(0, i18n.tr("language.fa"))
        self.language_combo.setItemText(1, i18n.tr("language.en"))


__all__ = ["UnlockScreen"]
