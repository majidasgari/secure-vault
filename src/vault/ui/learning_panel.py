"""Learning panel: the notes in their spaced-repetition cycle (SPEC/03 §2.3).

The cycle itself lives in the metadata index (``core/learning.py`` + ``vault.learning_*``); this
panel is only a view: what is due today (and what was missed), what comes next, and the four
actions that move a card along. It reaches the vault through the same ``dispatch_ui`` callable the
search and log panels use, so a locked vault simply shows an empty list.
"""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core import learning
from ..util import now_ms
from . import bidi, i18n


class LearningPanel(QWidget):
    """The due/upcoming cards and their actions (review, restart, leave, open)."""

    open_requested = Signal(str)

    def __init__(self, call: Callable[[str, dict], dict], parent: Any = None) -> None:
        """Build the panel against ``call(method, params)`` (the UI dispatch)."""
        super().__init__(parent)
        self._call = call
        self._message = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        top = QHBoxLayout()
        self.status = QLabel(self)
        self.status.setWordWrap(True)
        self.refresh_button = QPushButton(self)
        self.refresh_button.clicked.connect(self.refresh)
        top.addWidget(self.status, 1)
        top.addWidget(self.refresh_button)
        layout.addLayout(top)

        self.due_heading = QLabel(self)
        layout.addWidget(self.due_heading)
        self.due_list = self._make_list()
        layout.addWidget(self.due_list, 1)

        self.ahead_heading = QLabel(self)
        layout.addWidget(self.ahead_heading)
        self.ahead_list = self._make_list()
        layout.addWidget(self.ahead_list, 1)

        # Two rows of two: this dock is a sidebar, and four labelled buttons in one line clip.
        actions = QGridLayout()
        self.seen_button = QPushButton(self)
        self.seen_button.clicked.connect(self.mark_seen)
        self.reset_button = QPushButton(self)
        self.reset_button.clicked.connect(self.reset)
        self.stop_button = QPushButton(self)
        self.stop_button.clicked.connect(self.stop)
        self.open_button = QPushButton(self)
        self.open_button.clicked.connect(self.open_selected)
        for position, button in enumerate(
            (self.seen_button, self.reset_button, self.stop_button, self.open_button)
        ):
            actions.addWidget(button, position // 2, position % 2)
        layout.addLayout(actions)

        self.retranslate()
        i18n.bind(self, self.retranslate)
        self._sync_actions()

    # ------------------------------------------------------------------ lists
    def _make_list(self) -> QListWidget:
        """One card list; both lists share the selection handler."""
        widget = QListWidget(self)
        widget.setUniformItemSizes(True)
        widget.itemSelectionChanged.connect(self._on_selection)
        #: A row is a shortcut to the note: double-click opens it (the four buttons act on it too).
        widget.itemDoubleClicked.connect(lambda _item: self.open_selected())
        return widget

    def selected_card(self) -> dict | None:
        """Return the card the user picked in either list (or None)."""
        for widget in (self.due_list, self.ahead_list):
            items = widget.selectedItems()
            if items:
                card = items[0].data(Qt.UserRole)
                return card if isinstance(card, dict) else None
        return None

    def _on_selection(self) -> None:
        """Keep one current card: picking in one list clears the other."""
        for source, other in ((self.due_list, self.ahead_list), (self.ahead_list, self.due_list)):
            if not source.selectedItems():
                continue
            other.blockSignals(True)
            other.clearSelection()
            other.setCurrentRow(-1)
            other.blockSignals(False)
            break
        self._sync_actions()

    def _sync_actions(self) -> None:
        """Only a picked card enables the four actions."""
        has_card = self.selected_card() is not None
        for button in (self.seen_button, self.reset_button, self.stop_button, self.open_button):
            button.setEnabled(has_card)

    def _fill(self, widget: QListWidget, cards: list[dict], *, due: bool) -> None:
        """Replace one list's rows (signals off: this is not a user selection)."""
        widget.blockSignals(True)
        widget.clear()
        for card in cards:
            item = QListWidgetItem(self._label(card, due=due))
            item.setData(Qt.UserRole, dict(card))
            item.setToolTip(str(card.get("path") or ""))
            widget.addItem(item)
        widget.blockSignals(False)

    @staticmethod
    def _label(card: dict, *, due: bool) -> str:
        """``📝 name — 3 روز عقب · مرحلهٔ ۲ از ۶`` in one line."""
        name = str(card.get("name") or "")
        emoji = card.get("emoji")
        stage = i18n.tr(
            "learn.stage_of",
            stage=int(card.get("stage") or 0) + 1,
            total=int(card.get("total") or learning.TOTAL_STAGES),
        )
        if due:
            late = int(card.get("overdue_days") or 0)
            when = i18n.tr("learn.overdue", days=late) if late else i18n.tr("learn.due_today")
        else:
            left = learning.days_left(int(card.get("due") or 0), now_ms())
            when = i18n.tr("learn.in_days", days=left)
        prefix = f"{emoji} " if emoji else ""
        # The name is usually Latin: isolate it, or the Persian part of the line reorders around it.
        return f"{prefix}{bidi.ltr_isolate(name)} — {when} · {stage}"

    # ------------------------------------------------------------------ data
    def refresh(self) -> list[dict]:
        """Reload both lists and return the cards due now."""
        try:
            data = self._call("vault.learning_list", {}) or {}
        except Exception:  # noqa: BLE001 - a locked or absent vault is an empty panel
            data = {}
        due = [dict(card) for card in (data.get("due") or [])]
        ahead = [dict(card) for card in (data.get("upcoming") or [])]
        self._fill(self.due_list, due, due=True)
        self._fill(self.ahead_list, ahead, due=False)
        self._message = ""
        self.status.setText(self._summary(len(due)))
        self._sync_actions()
        return due

    def _summary(self, due_count: int) -> str:
        """One line above the lists: how many cards wait today."""
        if due_count:
            return i18n.tr("learn.status_due", count=due_count)
        return i18n.tr("learn.status_empty")

    def showEvent(self, event: Any) -> None:  # noqa: N802 - Qt API
        """Reload whenever the tab is opened: a due date may have passed meanwhile."""
        super().showEvent(event)
        self.refresh()

    # ------------------------------------------------------------------ actions
    def _day(self, due: Any) -> str:
        """Render a due moment as a plain YYYY-MM-DD date."""
        try:
            from datetime import datetime

            return datetime.fromtimestamp(int(due) / 1000).strftime("%Y-%m-%d")
        except (TypeError, ValueError, OSError, OverflowError):
            return ""

    def _apply(self, method: str, card: dict) -> dict | None:
        """Call one learning action for ``card``; a failure lands in the status line."""
        try:
            return self._call(method, {"path": str(card.get("path") or "")}) or {}
        except Exception as exc:  # noqa: BLE001 - show it, never crash the panel
            self.status.setText(str(exc))
            return None

    def mark_seen(self) -> None:
        """Record a review: the card moves to its next interval."""
        card = self.selected_card()
        if card is None:
            return
        result = self._apply("vault.learning_seen", card)
        if result is None:
            return
        self.refresh()
        if result.get("completed"):
            self.status.setText(i18n.tr("learn.done_toast"))
        else:
            self.status.setText(i18n.tr("learn.seen_toast", date=self._day(result.get("due"))))
        # The next due card takes the selection, so a review session keeps moving.
        if self.due_list.count():
            self.due_list.setCurrentRow(0)

    def reset(self) -> None:
        """Restart the card's cycle from the first interval (after asking)."""
        card = self.selected_card()
        if card is None or not self._confirm(i18n.tr("learn.reset_confirm")):
            return
        result = self._apply("vault.learning_reset", card)
        if result is None:
            return
        self.refresh()
        self.status.setText(i18n.tr("learn.reset_toast", date=self._day(result.get("due"))))

    def stop(self) -> None:
        """Take the card out of the cycle (after asking)."""
        card = self.selected_card()
        if card is None or not self._confirm(i18n.tr("learn.stop_confirm")):
            return
        if self._apply("vault.learning_stop", card) is None:
            return
        self.refresh()
        self.status.setText(i18n.tr("learn.stopped_toast"))

    def open_selected(self) -> None:
        """Ask the window to open the picked card's note."""
        card = self.selected_card()
        if card is not None:
            self.open_requested.emit(str(card.get("path") or ""))

    def _confirm(self, message: str) -> bool:
        """Ask before a destructive schedule change, like every other delete in this app."""
        answer = QMessageBox.question(
            self,
            i18n.tr("learn.title"),
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return answer == QMessageBox.Yes

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated labels."""
        self.refresh_button.setText(i18n.tr("browser.refresh"))
        self.due_heading.setText(i18n.tr("learn.due_heading"))
        self.ahead_heading.setText(i18n.tr("learn.upcoming_heading"))
        self.seen_button.setText(i18n.tr("learn.seen"))
        self.reset_button.setText(i18n.tr("learn.reset"))
        self.stop_button.setText(i18n.tr("learn.stop"))
        self.open_button.setText(i18n.tr("learn.open_note"))
        self.status.setText(self._message or self._summary(self.due_list.count()))


__all__ = ["LearningPanel"]
