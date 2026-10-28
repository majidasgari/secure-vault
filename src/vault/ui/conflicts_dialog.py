"""The conflict dialog: a sync conflict is the user's decision, never a heuristic's.

One conflict at a time, three answers. Closing the dialog leaves the rest pending — nothing is ever
picked automatically, and a path with an open conflict is simply held back while the rest of the
vault syncs.
"""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from . import i18n

_KIND_KEYS = {
    "put": "conflicts.kind_put",
    "delete": "conflicts.kind_delete",
    "rename": "conflicts.kind_rename",
}


class ConflictsDialog(QDialog):
    """Ask, one conflict at a time, which version wins."""

    def __init__(
        self,
        conflicts: list[dict[str, Any]],
        resolve: Callable[[int, str], dict[str, Any]],
        parent: QWidget | None = None,
    ) -> None:
        """Show ``conflicts``; ``resolve(conflict_id, choice)`` answers one."""
        super().__init__(parent)
        self._conflicts = list(conflicts)
        self._resolve = resolve
        self._index = 0
        self.resolved = 0
        self._failed: list[str] = []

        layout = QVBoxLayout(self)
        self.counter = QLabel(self)
        layout.addWidget(self.counter)
        self.path = QLabel(self)
        self.path.setWordWrap(True)
        layout.addWidget(self.path)
        self.kind = QLabel(self)
        self.kind.setWordWrap(True)
        layout.addWidget(self.kind)
        self.detail = QLabel(self)
        self.detail.setWordWrap(True)
        layout.addWidget(self.detail)

        self.mine_button = QPushButton(self)
        self.mine_button.clicked.connect(lambda: self._answer("mine"))
        layout.addWidget(self.mine_button)
        self.theirs_button = QPushButton(self)
        self.theirs_button.clicked.connect(lambda: self._answer("theirs"))
        layout.addWidget(self.theirs_button)
        self.both_button = QPushButton(self)
        self.both_button.clicked.connect(lambda: self._answer("both"))
        layout.addWidget(self.both_button)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Close, self)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        i18n.bind(self, self.retranslate)
        self.retranslate()
        self._show_current()

    # ------------------------------------------------------------------ state
    def _current(self) -> dict[str, Any] | None:
        """The conflict being shown (None once the list is exhausted)."""
        if 0 <= self._index < len(self._conflicts):
            return self._conflicts[self._index]
        return None

    def _show_current(self) -> None:
        """Render the current conflict, or close when there is nothing left."""
        current = self._current()
        if current is None:
            self.accept()
            return
        self.counter.setText(
            i18n.tr(
                "conflicts.counter",
                index=self._index + 1,
                total=len(self._conflicts),
            )
        )
        self.path.setText(str(current.get("path") or ""))
        self.kind.setText(i18n.tr(_KIND_KEYS.get(str(current.get("kind")), "conflicts.kind_put")))
        self.detail.setText(
            i18n.tr(
                "conflicts.detail",
                client=str(current.get("their_client") or "—"),
                mine=int(current.get("my_rev") or 0),
                theirs=int(current.get("their_rev") or 0),
            )
        )

    def _answer(self, choice: str) -> None:
        """Answer the current conflict and move on (asking again if the answer failed)."""
        current = self._current()
        if current is None:
            return
        try:
            self._resolve(int(current["id"]), choice)
            self.resolved += 1
            self._index += 1
        except Exception as exc:  # noqa: BLE001 - keep the conflict open and say why
            self._failed.append(str(exc))
            self.detail.setText(i18n.tr("conflicts.failed", reason=str(exc)))
            return
        self._show_current()

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.setWindowTitle(i18n.tr("conflicts.title"))
        self.mine_button.setText(i18n.tr("conflicts.mine"))
        self.theirs_button.setText(i18n.tr("conflicts.theirs"))
        self.both_button.setText(i18n.tr("conflicts.both"))
        self._show_current()


__all__ = ["ConflictsDialog"]
