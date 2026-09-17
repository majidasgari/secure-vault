"""New-vault wizard dialog (SPEC/03 §2.2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from ..config import DEFAULT_VAULT_HOME
from . import i18n, theme


class NewVaultDialog(QDialog):
    """Choose a folder and a password for a new vault (one page, three steps)."""

    def __init__(self, parent: Any = None) -> None:
        """Create the wizard with the default vault home pre-filled."""
        super().__init__(parent)
        self.setModal(True)
        layout = QVBoxLayout(self)

        form = QFormLayout()
        folder_row = QHBoxLayout()
        self.folder_edit = QLineEdit(str(DEFAULT_VAULT_HOME), self)
        self.browse_button = QPushButton(self)
        self.browse_button.clicked.connect(self._browse)
        folder_row.addWidget(self.folder_edit, 1)
        folder_row.addWidget(self.browse_button)
        self.folder_label = QLabel(self)
        form.addRow(self.folder_label, folder_row)

        self.password_edit = QLineEdit(self)
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.textChanged.connect(self._update_strength)
        self.password_label = QLabel(self)
        form.addRow(self.password_label, self.password_edit)

        self.confirm_edit = QLineEdit(self)
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.confirm_label = QLabel(self)
        form.addRow(self.confirm_label, self.confirm_edit)
        layout.addLayout(form)

        self.strength_label = QLabel(self)
        layout.addWidget(self.strength_label)

        self.structure_check = QCheckBox(self)
        self.structure_check.setChecked(True)
        layout.addWidget(self.structure_check)

        self.error_label = QLabel(self)
        self.error_label.setStyleSheet("color: #b00020;")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        self.buttons = QDialogButtonBox(self)
        self.create_button = self.buttons.addButton(
            i18n.tr("newvault.create"), QDialogButtonBox.AcceptRole
        )
        self.buttons.addButton(QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self._on_accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.retranslate()
        i18n.bind(self, self.retranslate)
        self._update_strength()

    # ------------------------------------------------------------------ actions
    def _browse(self) -> None:
        """Pick a vault folder."""
        chosen = QFileDialog.getExistingDirectory(
            self, i18n.tr("newvault.choose_folder"), self.folder_edit.text()
        )
        if chosen:
            self.folder_edit.setText(chosen)

    def _update_strength(self) -> None:
        """Refresh the password-strength hint."""
        password = self.password_edit.text()
        if not password:
            self.strength_label.setText(i18n.tr("newvault.strength.hint"))
            return
        self.strength_label.setText(
            i18n.tr("newvault.strength.label", strength=i18n.tr(theme.strength_key(password)))
        )

    def _on_accept(self) -> None:
        """Validate and accept, or show an inline error."""
        if not self.folder_edit.text().strip():
            self.error_label.setText(i18n.tr("newvault.error.folder"))
            return
        password = self.password_edit.text()
        if not password:
            self.error_label.setText(i18n.tr("newvault.error.password"))
            return
        if password != self.confirm_edit.text():
            self.error_label.setText(i18n.tr("newvault.error.mismatch"))
            return
        self.error_label.setText("")
        self.accept()

    def values(self) -> tuple[Path, str, bool]:
        """Return ``(home, password, create_structure)`` for the accepted dialog."""
        return (
            Path(self.folder_edit.text().strip()),
            self.password_edit.text(),
            bool(self.structure_check.isChecked()),
        )

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.setWindowTitle(i18n.tr("newvault.window_title"))
        self.folder_label.setText(i18n.tr("newvault.folder"))
        self.browse_button.setText(i18n.tr("newvault.browse"))
        self.password_label.setText(i18n.tr("newvault.password"))
        self.confirm_label.setText(i18n.tr("newvault.confirm"))
        self.structure_check.setText(i18n.tr("newvault.structure"))
        if self.create_button is not None:
            self.create_button.setText(i18n.tr("newvault.create"))
        self._update_strength()


__all__ = ["NewVaultDialog"]
