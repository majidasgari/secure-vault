"""Adopting the operation log for an existing vault (phase 4)."""

from __future__ import annotations

import unittest

from support import tmp_vault
from vault.core import journal
from vault.errors import BadRequest, SyncError


class MigrationTest(unittest.TestCase):
    """What the upgrade must record, and what it must refuse."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.index = self.session.index
        self.session.write_file("notes/a.md", b"alpha")
        self.session.write_file("notes/b.md", b"beta")
        self.session.mkdir("empty")
        self.session.set_folder_note("notes", "یادداشت پوشه")
        self.session.set_file_note("notes/a.md", "یادداشت فایل")
        self.session.learning_start("notes/a.md")

    def tearDown(self) -> None:
        self.session.close()

    def test_the_mode_starts_legacy(self) -> None:
        self.assertEqual(self.session.sync_mode(), "legacy")

    def test_migration_seeds_one_op_per_entry_and_flips_the_mode(self) -> None:
        before = len(journal.pending(self.index))
        result = self.session.migrate_to_journal()
        after = len(journal.pending(self.index))

        self.assertFalse(result["already"])
        self.assertEqual(result["files"], 4, "two files and two folders (notes + empty)")
        self.assertEqual(result["notes"], 2)
        self.assertEqual(result["learning"], 1)
        self.assertEqual(self.session.sync_mode(), "journal")
        self.assertEqual(after - before, 7, "4 puts + 2 notes + 1 learning")

    def test_the_seeded_note_ops_carry_no_plaintext(self) -> None:
        self.session.migrate_to_journal()
        rows = self.index.conn.execute("SELECT json FROM journal_out").fetchall()
        blob = "\n".join(str(row["json"]) for row in rows)
        self.assertNotIn("یادداشت پوشه", blob)
        self.assertNotIn("یادداشت فایل", blob)

    def test_migrating_twice_changes_nothing(self) -> None:
        self.session.migrate_to_journal()
        count = len(journal.pending(self.index))
        again = self.session.migrate_to_journal()
        self.assertTrue(again["already"])
        self.assertEqual(len(journal.pending(self.index)), count, "a rerun must not duplicate ops")

    def test_the_journal_sync_refuses_before_migration(self) -> None:
        with self.assertRaises(BadRequest):
            self.session.sync_journal()

    def test_the_legacy_sync_refuses_after_migration(self) -> None:
        self.session.migrate_to_journal()
        manager = self.session.sync_manager()
        with self.assertRaises(SyncError) as raised:
            manager.start_sync()
        self.assertIn("sync_mode_journal", str(raised.exception), "the reason names the new mode")

    def test_the_seeded_ops_cover_every_path_in_the_index(self) -> None:
        self.session.migrate_to_journal()
        seeded = set()
        for op in journal.pending(self.index, limit=200):
            if op["kind"] == "put":
                seeded.add(op["path"])
        expected = {str(row["logical_path"]) for row in self.index.walk("/")}
        self.assertEqual(seeded, expected)


if __name__ == "__main__":
    unittest.main()
