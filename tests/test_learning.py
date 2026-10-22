"""The learning cycle: intervals, the due/upcoming split, and the four actions (SPEC/06)."""

from __future__ import annotations

import unittest

from support import tmp_vault

from vault.core import learning
from vault.errors import BadRequest, NotFound, VaultLocked

DAY = learning.DAY_MS


class ScheduleTest(unittest.TestCase):
    """The arithmetic alone — no vault, so the rules are pinned independently of storage."""

    def test_intervals_double(self) -> None:
        self.assertEqual(learning.INTERVALS_DAYS, (1, 2, 4, 8, 16, 32))
        self.assertEqual(learning.TOTAL_STAGES, 6)

    def test_first_card_is_tomorrow(self) -> None:
        stage, due = learning.started(1000)
        self.assertEqual((stage, due), (0, 1000 + DAY))

    def test_six_reviews_walk_the_intervals_and_finish(self) -> None:
        now = 0
        stage, _due = learning.started(now)
        gaps = []
        while True:
            stage, due = learning.reviewed(now, stage)
            if not due:
                break
            gaps.append((due - now) // DAY)
        self.assertEqual(gaps, [2, 4, 8, 16, 32])
        self.assertTrue(learning.is_complete(stage))

    def test_due_and_overdue(self) -> None:
        due = 10 * DAY
        self.assertFalse(learning.is_due(due, due - 1))
        self.assertTrue(learning.is_due(due, due))
        self.assertEqual(learning.days_overdue(due, due), 0)
        self.assertEqual(learning.days_overdue(due, due + 2 * DAY + 5), 2)
        # A finished cycle (due 0) is never due again, whatever the clock says.
        self.assertFalse(learning.is_due(0, 10**12))
        self.assertEqual(learning.days_overdue(0, 10**12), 0)


class LearningSessionTest(unittest.TestCase):
    """Start / seen / reset / stop on a real (scratch) vault."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.session.write_file("notes/card.md", b"body")
        self.session.write_file("notes/other.md", b"other")
        self.session.mkdir("folder")

    def tearDown(self) -> None:
        self.session.close()

    def _card(self, path: str = "/notes/card.md", now: int | None = None) -> dict:
        listing = self.session.learning_list(now=now)
        for entry in listing["due"] + listing["upcoming"]:
            if entry["path"] == path:
                return entry
        raise AssertionError(f"{path} not in the learning list")

    def test_start_puts_tomorrow_in_upcoming(self) -> None:
        entry = self.session.learning_start("notes/card.md")
        self.assertEqual(entry["stage"], 0)
        self.assertEqual(entry["path"], "/notes/card.md")
        listing = self.session.learning_list()
        self.assertEqual(listing["due"], [])
        self.assertEqual([card["path"] for card in listing["upcoming"]], ["/notes/card.md"])
        self.assertEqual(listing["intervals"], list(learning.INTERVALS_DAYS))

    def test_start_is_idempotent(self) -> None:
        first = self.session.learning_start("notes/card.md")
        second = self.session.learning_start("notes/card.md")
        self.assertEqual(first["due"], second["due"])
        self.assertEqual(len(self.session.learning_list()["upcoming"]), 1)

    def test_card_is_due_after_its_day_and_counts_its_lateness(self) -> None:
        entry = self.session.learning_start("notes/card.md")
        self.assertEqual(self.session.learning_list(now=entry["due"] - 1)["due"], [])
        due = self.session.learning_list(now=entry["due"])["due"]
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0]["overdue_days"], 0)
        late = self.session.learning_list(now=entry["due"] + 3 * DAY)["due"]
        self.assertEqual(late[0]["overdue_days"], 3)

    def test_seen_advances_the_stage_and_the_due_date(self) -> None:
        self.session.learning_start("notes/card.md")
        entry = self.session.learning_seen("notes/card.md")
        self.assertEqual(entry["stage"], 1)
        self.assertFalse(entry["completed"])
        self.assertGreater(entry["due"], entry["seen"] + DAY)
        self.assertEqual(entry["path"], "/notes/card.md")

    def test_six_reviews_finish_the_cycle_and_leave_the_list(self) -> None:
        self.session.learning_start("notes/card.md")
        result: dict = {}
        for _ in range(learning.TOTAL_STAGES):
            result = self.session.learning_seen("notes/card.md")
        self.assertTrue(result["completed"])
        self.assertEqual(result["due"], 0)
        listing = self.session.learning_list()
        self.assertEqual(listing["due"] + listing["upcoming"], [])

    def test_reset_restarts_from_the_first_interval(self) -> None:
        self.session.learning_start("notes/card.md")
        self.session.learning_seen("notes/card.md")
        self.session.learning_seen("notes/card.md")
        reset = self.session.learning_reset("notes/card.md")
        self.assertEqual(reset["stage"], 0)
        self.assertEqual(reset["seen"], 0)
        self.assertEqual(reset["due"] - reset["started"], DAY)

    def test_stop_removes_the_card(self) -> None:
        self.session.learning_start("notes/card.md")
        self.assertTrue(self.session.learning_stop("notes/card.md")["removed"])
        self.assertFalse(self.session.learning_stop("notes/card.md")["removed"])
        self.assertEqual(self.session.learning_list()["upcoming"], [])

    def test_actions_need_a_card_or_a_note(self) -> None:
        with self.assertRaises(NotFound):
            self.session.learning_seen("notes/other.md")
        with self.assertRaises(NotFound):
            self.session.learning_reset("notes/other.md")
        with self.assertRaises(BadRequest):
            self.session.learning_start("folder")
        with self.assertRaises(NotFound):
            self.session.learning_start("notes/missing.md")

    def test_deleting_the_note_drops_its_card(self) -> None:
        self.session.learning_start("notes/card.md")
        self.session.delete("notes/card.md")
        self.assertEqual(self.session.learning_list()["upcoming"], [])

    def test_listing_is_metadata_only_and_works_while_locked(self) -> None:
        self.session.learning_start("notes/card.md")
        self.session.lock()
        listing = self.session.learning_list()
        self.assertEqual(len(listing["upcoming"]), 1)
        with self.assertRaises(VaultLocked):
            self.session.learning_seen("notes/card.md")


if __name__ == "__main__":
    unittest.main()
