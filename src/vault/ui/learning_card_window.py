"""The learning card window: one due card at a time, opened by the MCP tool ``show_learning_card``.

Self-contained by design. It talks to the running daemon with the same client the MCP bridge uses,
so «کافی» records the review (``vault.learning_seen``) and the next card appears without another
agent turn; when nothing is left it congratulates and closes itself. The window keeps no state of
its own — every card comes from a fresh ``vault.learning_list``.
"""

from __future__ import annotations

import sys
from typing import Any, Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ..api.client import RefreshingClient
from ..config import user_config
from ..core import learning
from ..errors import VaultError, VaultLocked, VaultNotRunning
from ..learning_card import clear_pid, publish_pid
from ..util import now_ms
from . import bidi, i18n, theme

#: How long the congratulations stay on screen before the window closes itself.
CLOSE_AFTER_MS = 3000


class Cards:
    """The due cards and the one review action; ``call`` is ``VaultClient.call``."""

    def __init__(self, call: Callable[[str, dict], dict]) -> None:
        """Bind the session to the vault client call."""
        self._call = call
        self.due: list[dict[str, Any]] = []
        self.upcoming: list[dict[str, Any]] = []
        #: How many cards were due when the window opened — the "one of N" the counter shows.
        self.opened = 0
        #: The daemon's clock for the last list, so "in N days" is not computed from a stale one.
        self.now = now_ms()

    def reload(self) -> list[dict[str, Any]]:
        """Re-read the cycle from the daemon and return the cards due now."""
        payload = self._call("vault.learning_list", {}) or {}
        self.due = [card for card in payload.get("due") or [] if isinstance(card, dict)]
        self.upcoming = [card for card in payload.get("upcoming") or [] if isinstance(card, dict)]
        self.now = int(payload.get("now") or now_ms())
        self.opened = max(self.opened, len(self.due))
        return self.due

    @property
    def current(self) -> dict[str, Any] | None:
        """The card to show now (the daemon sends them most-overdue first)."""
        return self.due[0] if self.due else None

    def mark_seen(self) -> None:
        """Record the review of the current card."""
        card = self.current
        if card is not None:
            self._call("vault.learning_seen", {"path": card.get("path")})

    def read(self, card: dict[str, Any]) -> str:
        """Return the card's text, or the one line saying why it cannot be shown."""
        try:
            payload = self._call("vault.read_file", {"path": card.get("path")}) or {}
        except VaultLocked:
            return i18n.tr("lcard.locked")
        except VaultNotRunning:
            return i18n.tr("lcard.daemon")
        except VaultError as exc:
            return i18n.tr("lcard.unreadable", reason=exc.code)
        return str(payload.get("content") or "")

    def when_next(self) -> str:
        """Return «{days} روز دیگر» for the nearest upcoming card, or an empty string."""
        moments = [int(card.get("due") or 0) for card in self.upcoming]
        moments = [moment for moment in moments if moment]
        if not moments:
            return ""
        days = learning.days_left(min(moments), self.now)
        return i18n.tr("learn.in_days", days=days) if days else i18n.tr("learn.due_today")


class CardWindow(QWidget):
    """Shows one card, records it with «کافی», and closes on an empty queue."""

    def __init__(self, cards: Cards) -> None:
        """Build the window around ``cards``."""
        super().__init__()
        self.cards = cards
        self.setWindowTitle(i18n.tr("lcard.title"))
        self.resize(560, 640)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(8)

        self.counter = _label(self, "lcCounter")
        self.title = _label(self, "lcTitle")
        self.folder = _label(self, "lcPath")
        self.meta = _label(self, "lcMeta")
        self.congrats = _label(self, "lcCongrats")
        self.notice = _label(self, "lcNotice")
        self.body = QTextBrowser(self)
        self.body.setObjectName("lcBody")
        for widget in (self.counter, self.title, self.folder, self.meta, self.congrats):
            root.addWidget(widget)
        root.addWidget(self.body, 1)
        root.addWidget(self.notice)

        row = QHBoxLayout()
        self.kafi_button = QPushButton(i18n.tr("lcard.kafi"), self)
        self.kafi_button.setObjectName("lcKafi")
        self.kafi_button.clicked.connect(self.mark_seen)
        self.reveal_button = QPushButton(i18n.tr("learn.reveal"), self)
        self.reveal_button.clicked.connect(self.toggle_reveal)
        self.close_button = QPushButton(i18n.tr("lcard.close"), self)
        self.close_button.clicked.connect(self.close)
        row.addWidget(self.kafi_button)
        row.addWidget(self.reveal_button)
        row.addStretch(1)
        row.addWidget(self.close_button)
        root.addLayout(row)

        self.refresh()

    # ------------------------------------------------------------------ actions
    def refresh(self) -> None:
        """Render the current card, or the closing screen when nothing is due."""
        self.notice.setText("")
        self.notice.hide()
        try:
            self.cards.reload()
        except VaultNotRunning:
            self._fail(i18n.tr("lcard.daemon"))
            return
        except VaultError as exc:
            self._fail(i18n.tr("lcard.unreadable", reason=exc.code))
            return
        card = self.cards.current
        if card is None:
            self._finish()
            return

        self.kafi_button.setEnabled(True)
        self.reveal_button.setEnabled(True)
        self.congrats.hide()
        for widget in (self.counter, self.title, self.folder, self.meta, self.body,
                       self.reveal_button, self.kafi_button):
            widget.show()
        self.body.hide()
        self.reveal_button.setText(i18n.tr("learn.reveal"))

        total = self.cards.opened or 1
        self.counter.setText(
            i18n.tr("lcard.counter", index=max(1, total - len(self.cards.due) + 1), total=total)
        )
        self.title.setText(f"{card.get('emoji') or ''} {card.get('name') or ''}".strip())
        folder = _folder_name(str(card.get("path") or ""))
        self.folder.setText(folder)
        self.folder.setVisible(bool(folder))
        overdue = int(card.get("overdue_days") or 0)
        when = i18n.tr("learn.overdue", days=overdue) if overdue else i18n.tr("learn.due_today")
        self.meta.setText(" · ".join([
            when,
            i18n.tr("learn.stage_of", stage=int(card.get("stage") or 0) + 1,
                    total=int(card.get("total") or 0)),
        ]))
        self._set_body("")

    def toggle_reveal(self) -> None:
        """Show the card's text, or hide it again."""
        card = self.cards.current
        if card is None:
            return
        if self.body.isVisible():
            self.body.hide()
            self.reveal_button.setText(i18n.tr("learn.reveal"))
            return
        self._set_body(self.cards.read(card))
        self.body.show()
        self.reveal_button.setText(i18n.tr("learn.hide"))

    def mark_seen(self) -> None:
        """Record the review and move to the next card (or the closing screen)."""
        if self.cards.current is None:
            return
        try:
            self.cards.mark_seen()
        except VaultNotRunning:
            self._fail(i18n.tr("lcard.daemon"))
            return
        except VaultError as exc:
            self._fail(i18n.tr("lcard.seen_failed", reason=exc.code))
            return
        self.refresh()

    # ------------------------------------------------------------------ internal
    def _finish(self) -> None:
        """Congratulate, say when the next card comes, and close shortly after."""
        for widget in (self.counter, self.title, self.folder, self.meta, self.body,
                       self.reveal_button, self.kafi_button, self.notice):
            widget.hide()
        text = i18n.tr("lcard.congrats")
        when = self.cards.when_next()
        if when:
            text = f"{text}\n{i18n.tr('lcard.next_card', when=when)}"
        self.congrats.setText(text)
        self.congrats.show()
        QTimer.singleShot(CLOSE_AFTER_MS, self.close)

    def _fail(self, message: str) -> None:
        """Show why the card could not be read or recorded."""
        self.kafi_button.setEnabled(False)
        self.reveal_button.setEnabled(False)
        self.notice.setText(message)
        self.notice.show()

    def _set_body(self, text: str) -> None:
        """Put ``text`` in the reader with one direction per line (Persian rule).

        Plain text, not markdown: the lines are what the note says, and markdown would join
        soft line breaks and take the per-line direction with them.
        """
        document = self.body.document()
        document.setPlainText(text)
        for number in range(document.blockCount()):
            block = document.findBlockByNumber(number)
            block_format = block.blockFormat()
            block_format.setLayoutDirection(
                Qt.LayoutDirection.RightToLeft if bidi.needs_rtl(block.text())
                else Qt.LayoutDirection.LeftToRight
            )
            QTextCursor(block).setBlockFormat(block_format)


def _label(parent: QWidget, name: str) -> QLabel:
    """Build a word-wrapped label carrying the stylesheet's object name."""
    label = QLabel(parent)
    label.setObjectName(name)
    label.setWordWrap(True)
    return label


def _folder_name(path: str) -> str:
    """Return the note's folder name («$پر استفاده»), or "" at the root.

    Only the folder is shown: a full path is a left-to-right string with Persian in it, and the
    bidi algorithm re-orders it into something the reader has to decode.
    """
    parent = path.rsplit("/", 1)[0]
    return "" if parent in ("", "/") else parent.rsplit("/", 1)[-1]


def _stylesheet(colors: dict[str, str], dark: bool) -> str:
    """Colours only — a font-family here would break Persian shaping."""
    on_accent = colors["bg"] if dark else "#ffffff"
    return f"""
QLabel#lcCounter, QLabel#lcPath, QLabel#lcMeta {{ color: {colors['muted']}; }}
QLabel#lcTitle {{ font-size: 16pt; font-weight: 600; }}
QLabel#lcCongrats {{ font-size: 15pt; font-weight: 600; }}
QLabel#lcNotice {{ color: {colors['heading']}; }}
QTextBrowser#lcBody {{ background: {colors['bg']}; border: 1px solid {colors['border']};
                       border-radius: 10px; padding: 10px; }}
QPushButton {{ border: 1px solid {colors['border']}; border-radius: 8px; padding: 8px 14px; }}
QPushButton#lcKafi {{ background: {colors['accent']}; color: {on_accent}; border: none;
                      padding: 8px 20px; font-weight: 600; }}
"""


def main() -> int:
    """Open the window and run it (``python -m vault.ui.learning_card_window``)."""
    app = QApplication(["secure-vault-learning-card"])
    config = user_config()
    theme.set_preference(config.data.get("theme", "system"))
    i18n.set_language(config.language)
    theme.apply(app, config.language)
    app.setStyleSheet(_stylesheet(theme.colors(app), theme.is_dark(app)))

    window = CardWindow(Cards(RefreshingClient().call))
    publish_pid()
    app.aboutToQuit.connect(clear_pid)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
