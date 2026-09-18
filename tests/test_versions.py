"""File version history and the git-style diff endpoint."""

from __future__ import annotations

import unittest

from support import tmp_vault


class VersioningTest(unittest.TestCase):
    """Every save keeps its own encrypted blob and stays diffable."""

    def setUp(self) -> None:
        """Create a scratch vault."""
        self.session = tmp_vault()

    def tearDown(self) -> None:
        """Release the vault."""
        self.session.close()

    def test_write_keeps_every_version(self) -> None:
        """Three saves produce three listable versions, oldest readable."""
        self.session.write_file("v.md", b"one\n")
        self.session.write_file("v.md", b"one\ntwo\n")
        self.session.write_file("v.md", b"one\ntwo\nthree\n")
        listing = self.session.versions("v.md")
        self.assertEqual(listing["count"], 3)
        self.assertEqual([v["version"] for v in listing["versions"]], [3, 2, 1])
        self.assertEqual(self.session.version_text("v.md", 1).strip(), "one")
        self.assertEqual(self.session.version_text("v.md", 2).strip(), "one\ntwo")

    def test_identical_write_does_not_add_a_version(self) -> None:
        """Re-saving identical content does not grow the history."""
        self.session.write_file("v.md", b"same")
        self.session.write_file("v.md", b"same")
        self.assertEqual(self.session.versions("v.md")["count"], 1)

    def test_diff_between_any_two_versions(self) -> None:
        """The diff reports the removed and added lines."""
        self.session.write_file("d.md", b"alpha\nbeta\n")
        self.session.write_file("d.md", b"alpha\ngamma\n")
        result = self.session.diff("d.md", 1, 2)
        self.assertIn("replace", {hunk["type"] for hunk in result["hunks"]})
        removed = "\n".join(
            line for hunk in result["hunks"] for line in hunk["a_lines"]
        )
        added = "\n".join(
            line for hunk in result["hunks"] for line in hunk["b_lines"]
        )
        self.assertIn("beta", removed)
        self.assertIn("gamma", added)

    def test_previous_blob_is_kept(self) -> None:
        """The old blob survives an update so history stays readable."""
        self.session.write_file("k.md", b"old")
        old = self.session.index.require_file("k.md")["blob_id"]
        self.session.write_file("k.md", b"new")
        self.assertTrue(self.session.fs.blob_path(old).exists())

    def test_delete_removes_versions_and_blobs(self) -> None:
        """Deleting a file erases its history too."""
        self.session.write_file("x.md", b"v1")
        self.session.write_file("x.md", b"v2")
        row = self.session.index.require_file("x.md")
        blobs = [v["blob_id"] for v in self.session.index.list_versions(int(row["id"]))]
        self.session.delete("x.md")
        for blob in blobs:
            self.assertFalse(self.session.fs.blob_path(blob).exists())

    def test_note_change_emits_activity(self) -> None:
        """Setting a file note emits an activity event (so the tray can notify)."""
        events: list[dict] = []
        self.session.on_activity = events.append
        self.session.write_file("n.md", b"body")
        self.session.set_file_note("n.md", "the note")
        self.assertTrue(any(e.get("tool") == "set_file_note" for e in events))


if __name__ == "__main__":
    unittest.main()
