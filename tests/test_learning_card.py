"""The learning-card window's data layer: next card, review, and the launcher's pid file.

No Qt window is built here — ``Cards`` is what the window renders, and it is the part that could
silently show the wrong card or record the wrong one.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from support import scratch_home

from vault import learning_card
from vault.errors import PermissionDenied, VaultLocked
from vault.ui.learning_card_window import Cards

DAY = 24 * 60 * 60 * 1000
NOW = 1_792_400_000_000


class FakeVault:
    """Answers the three methods the window calls, and remembers the writes."""

    def __init__(self, due, upcoming=(), content="متن کارت\n", error=None):
        self.due = [dict(card) for card in due]
        self.upcoming = [dict(card) for card in upcoming]
        self.content = content
        self.error = error
        self.seen: list[str] = []
        self.reads: list[str] = []

    def call(self, method: str, params: dict | None = None) -> dict:
        params = params or {}
        if method == "vault.learning_list":
            return {"due": list(self.due), "upcoming": list(self.upcoming), "now": NOW,
                    "count": len(self.due), "intervals": [1, 2, 4, 8, 16, 32]}
        if method == "vault.learning_seen":
            self.seen.append(str(params.get("path")))
            self.due = [c for c in self.due if c.get("path") != params.get("path")]
            return {"path": params.get("path")}
        if method == "vault.read_file":
            self.reads.append(str(params.get("path")))
            if self.error is not None:
                raise self.error
            return {"content": self.content}
        raise AssertionError(f"unexpected call {method}")


def card(path: str, *, stage: int = 0, overdue: int = 0) -> dict:
    """One due card as the daemon shapes it."""
    return {"name": path.rsplit("/", 1)[-1], "path": path, "stage": stage, "total": 6,
            "due": NOW - overdue * DAY, "overdue_days": overdue, "completed": False}


class CardsTest(unittest.TestCase):
    """What the window shows, and what «کافی» touches."""

    def test_most_overdue_card_is_first_and_survives_one_review(self) -> None:
        vault = FakeVault([card("/a.md", overdue=9), card("/b.md", overdue=1)])
        cards = Cards(vault.call)
        self.assertEqual([c["path"] for c in cards.reload()], ["/a.md", "/b.md"])
        self.assertEqual(cards.opened, 2)
        first = cards.current
        self.assertIsNotNone(first)
        self.assertEqual(first["path"], "/a.md")

        cards.mark_seen()
        self.assertEqual(vault.seen, ["/a.md"])
        cards.reload()
        second = cards.current
        self.assertIsNotNone(second)
        self.assertEqual(second["path"], "/b.md")
        self.assertEqual(cards.opened, 2, "the counter must keep the count the window opened with")

    def test_empty_queue_has_no_current_card_and_keeps_the_next_date(self) -> None:
        cards = Cards(FakeVault([], [{"path": "/later.md", "due": NOW + 4 * DAY}]).call)
        self.assertEqual(cards.reload(), [])
        self.assertIsNone(cards.current)
        self.assertEqual(cards.when_next(), "4 روز دیگر")
        cards.mark_seen()  # nothing to record: no call, no crash

    def test_when_next_says_today_for_a_card_that_just_fell_due(self) -> None:
        cards = Cards(FakeVault([], [{"path": "/now.md", "due": NOW - 1}]).call)
        cards.reload()
        self.assertEqual(cards.when_next(), "امروز")

    def test_when_next_is_empty_without_upcoming_cards(self) -> None:
        cards = Cards(FakeVault([]).call)
        cards.reload()
        self.assertEqual(cards.when_next(), "")

    def test_read_returns_the_note_text(self) -> None:
        vault = FakeVault([card("/a.md")], content="# کدپستی\nمتن")
        cards = Cards(vault.call)
        cards.reload()
        current = cards.current
        assert current is not None
        self.assertEqual(cards.read(current), "# کدپستی\nمتن")
        self.assertEqual(vault.reads, ["/a.md"])

    def test_read_explains_a_locked_vault_instead_of_raising(self) -> None:
        cards = Cards(FakeVault([card("/a.md")], error=VaultLocked("locked")).call)
        cards.reload()
        current = cards.current
        assert current is not None
        self.assertEqual(cards.read(current), "گنجینه قفل است؛ اول بازش کن.")

    def test_read_names_the_failing_code(self) -> None:
        cards = Cards(FakeVault([card("/a.md")], error=PermissionDenied("denied")).call)
        cards.reload()
        current = cards.current
        assert current is not None
        self.assertEqual(cards.read(current), "متن کارت خوانده نشد (PERMISSION_DENIED).")


class LauncherTest(unittest.TestCase):
    """The pid file the MCP tool reads to answer "did the window open?"."""

    def setUp(self) -> None:
        self.runtime = scratch_home()
        self.env = patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(self.runtime)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(learning_card.clear_pid)

    def test_publish_then_running_then_clear(self) -> None:
        self.assertIsNone(learning_card.running())
        learning_card.publish_pid()
        self.assertEqual(learning_card.running(), os.getpid())
        learning_card.clear_pid()
        self.assertIsNone(learning_card.running())

    def test_a_dead_pid_is_not_a_window(self) -> None:
        learning_card.state_path().parent.mkdir(parents=True, exist_ok=True)
        learning_card.state_path().write_text('{"pid": 999999999}', encoding="utf-8")
        self.assertIsNone(learning_card.running())

    def test_a_broken_state_file_is_not_a_window(self) -> None:
        learning_card.state_path().parent.mkdir(parents=True, exist_ok=True)
        learning_card.state_path().write_text("{", encoding="utf-8")
        self.assertIsNone(learning_card.running())


if __name__ == "__main__":
    unittest.main()
