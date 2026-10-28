"""A new credential entry: one small form, and the body the desktop's parser reads back.

The phone writes the same body (``CredentialTemplate.kt``); a test in each repo keeps the two in step.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from . import i18n

#: Field id -> i18n key, in the order the form shows them.
FIELDS = (
    ("site", "credential.site"),
    ("category", "credential.category"),
    ("username", "credential.username"),
    ("password", "credential.password"),
    ("url", "credential.url"),
    ("otp", "credential.otp"),
)


class CredentialDialog(QDialog):
    """Ask for the fields of a standard credential entry."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(i18n.tr("credential.new_title"))
        self.edits: dict[str, QLineEdit] = {}
        layout = QVBoxLayout(self)
        form = QFormLayout()
        for field, key in FIELDS:
            edit = QLineEdit(self)
            if field in ("password", "otp"):
                edit.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow(i18n.tr(key), edit)
            self.edits[field] = edit
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.edits["site"].textChanged.connect(self._sync_ok)
        self._sync_ok()

    def _sync_ok(self) -> None:
        """The site is the file name: without it there is nothing to create."""
        box = self.findChild(QDialogButtonBox)
        if box is not None:
            box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(
                bool(self.edits["site"].text().strip())
            )

    def values(self) -> dict[str, str]:
        """The entered values, ready for :func:`vault.core.credentials.build_body`."""
        return {field: edit.text() for field, edit in self.edits.items()}


def prompt_credential(parent: QWidget | None = None) -> dict[str, str] | None:
    """Show the form; ``None`` when it was dismissed (nothing is written then)."""
    dialog = CredentialDialog(parent)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None
    return dialog.values()
