"""A new bank card: the Shetab fields, and the body the desktop's parser reads back.

Same shape as :mod:`credential_dialog` on purpose — a card is a credential whose fields are the
card's, so one viewer, one search index and one phone template serve both.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from ..core.credentials import digits_only
from . import i18n

#: Field id -> i18n key, in the order a Shetab card presents them.
FIELDS = (
    ("bank", "card.bank"),
    ("number", "card.number"),
    ("expiry", "card.expiry"),
    ("cvv2", "card.cvv2"),
    ("pin2", "card.pin2"),
    ("account", "card.account"),
    ("sheba", "card.sheba"),
    ("holder", "card.holder"),
)

#: Fields hidden while typing (the echo mode the credential form uses for a password).
SECRET_FIELDS = frozenset({"cvv2", "pin2"})


class CardDialog(QDialog):
    """Ask for the fields of a Shetab card."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(i18n.tr("card.new_title"))
        self.edits: dict[str, QLineEdit] = {}
        layout = QVBoxLayout(self)
        form = QFormLayout()
        for field, key in FIELDS:
            edit = QLineEdit(self)
            if field in SECRET_FIELDS:
                edit.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow(i18n.tr(key), edit)
            self.edits[field] = edit
        layout.addLayout(form)
        hint = QLabel(i18n.tr("card.hint"), self)
        hint.setWordWrap(True)
        hint.setEnabled(False)
        layout.addWidget(hint)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.edits["number"].textChanged.connect(self._sync_ok)
        self._sync_ok()

    def _sync_ok(self) -> None:
        """The card number names the entry: without it there is nothing to create."""
        box = self.findChild(QDialogButtonBox)
        if box is not None:
            box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(
                bool(digits_only(self.edits["number"].text()))
            )

    def values(self) -> dict[str, str]:
        """The entered values, ready for :func:`vault.core.credentials.build_card_body`."""
        return {field: edit.text() for field, edit in self.edits.items()}


def prompt_card(parent: QWidget | None = None) -> dict[str, str] | None:
    """Show the form; ``None`` when it was dismissed (nothing is written then)."""
    dialog = CardDialog(parent)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None
    return dialog.values()
