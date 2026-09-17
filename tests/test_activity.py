"""Tests for the metadata-only activity feed (SPEC/09 §C, §D).

The feed must carry path/level/source/outcome/byte-count only — never content — and
must work for reads from every source, including denied and locked reads.
"""

from __future__ import annotations

import json
import unittest

from support import tmp_vault
from vault.api.service import ACTIVITY_LIMIT, ActivityFeed, Service


class ActivityEmissionTest(unittest.TestCase):
    """Reads, searches and lists emit the documented activity events."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.service = Service(self.session)
        self.events: list[dict] = []
        self.session.on_activity = self.events.append
        self.service.dispatch(
            "vault.write_file",
            {"path": "/notes/a.md", "content": "alpha body"},
            role="ui",
            session_id="ui",
        )
        self.service.dispatch(
            "vault.write_file",
            {"path": "/notes/s.md", "content": "secret body token", "sensitivity": "secret"},
            role="ui",
            session_id="ui",
        )

    def tearDown(self) -> None:
        self.session.close()

    def _reads(self) -> list[dict]:
        return [event for event in self.events if event.get("kind") == "read"]

    def test_gui_read_event(self) -> None:
        """A gui read emits a read event with path, level and source."""
        self.events.clear()
        self.service.dispatch(
            "vault.read_file", {"path": "/notes/a.md"}, role="ui", session_id="ui",
            source="gui",
        )
        read = self._reads()[-1]
        self.assertEqual(read["source"], "gui")
        self.assertEqual(read["path"], "notes/a.md")
        self.assertEqual(read["sensitivity"], "normal")
        self.assertEqual(read["outcome"], "allow")
        self.assertEqual(read["bytes"], len(b"alpha body"))

    def test_web_read_event(self) -> None:
        """A web read is tagged ``source=web``."""
        self.events.clear()
        self.service.dispatch(
            "vault.read_file", {"path": "/notes/a.md"}, role="ui", session_id="web-1",
            source="web",
        )
        self.assertEqual(self._reads()[-1]["source"], "web")

    def test_mcp_read_event(self) -> None:
        """An mcp read is tagged ``source=mcp``."""
        self.events.clear()
        self.service.dispatch(
            "vault.read_file", {"path": "/notes/a.md"}, role="mcp", session_id="mcp-1"
        )
        self.assertEqual(self._reads()[-1]["source"], "mcp")

    def test_denied_read_emits_deny(self) -> None:
        """An mcp read of a secret file emits a deny event."""
        self.events.clear()
        with self.assertRaises(Exception):
            self.service.dispatch(
                "vault.read_file", {"path": "/notes/s.md"}, role="mcp", session_id="mcp-1"
            )
        read = self._reads()[-1]
        self.assertEqual(read["outcome"], "deny")
        self.assertEqual(read["sensitivity"], "secret")

    def test_locked_read_emits_deny(self) -> None:
        """A read while locked emits a deny event (no content, no level)."""
        self.session.lock()
        self.events.clear()
        with self.assertRaises(Exception):
            self.service.dispatch(
                "vault.read_file", {"path": "/notes/a.md"}, role="ui", session_id="ui"
            )
        read = self._reads()[-1]
        self.assertEqual(read["outcome"], "deny")
        self.assertIsNone(read["sensitivity"])

    def test_search_and_list_kinds(self) -> None:
        """Search/list calls are marked with their own ``kind``."""
        self.events.clear()
        self.service.dispatch("vault.list_folder", {"path": "/"}, role="ui", session_id="ui")
        self.service.dispatch(
            "vault.search_filenames", {"query": "a"}, role="ui", session_id="ui"
        )
        self.assertIn("list", [event["kind"] for event in self.events])
        self.assertIn("search", [event["kind"] for event in self.events])

    def test_events_never_carry_content(self) -> None:
        """No activity event contains file content."""
        self.events.clear()
        self.service.dispatch(
            "vault.read_file", {"path": "/notes/s.md"}, role="ui", session_id="ui"
        )
        blob = json.dumps(self.events, ensure_ascii=False)
        self.assertNotIn("secret body token", blob)
        for event in self.events:
            self.assertNotIn("content", event)


class ActivityFeedTest(unittest.TestCase):
    """The bounded feed helper."""

    def test_feed_is_bounded(self) -> None:
        """The feed never keeps more than its limit."""
        feed = ActivityFeed(limit=ACTIVITY_LIMIT)
        for index in range(ACTIVITY_LIMIT + 50):
            feed.add({"ts": index, "kind": "read", "path": f"n{index}"})
        self.assertEqual(len(feed), ACTIVITY_LIMIT)
        self.assertEqual(feed.events()[0]["ts"], ACTIVITY_LIMIT + 49)

    def test_last_read(self) -> None:
        """``last_read`` skips list/search events."""
        feed = ActivityFeed()
        feed.add({"kind": "list", "path": "x"})
        feed.add({"kind": "read", "path": "y"})
        feed.add({"kind": "search", "path": None})
        self.assertEqual(feed.last_read()["path"], "y")


if __name__ == "__main__":  # pragma: no cover - manual run
    unittest.main()
