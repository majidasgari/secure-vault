"""Every desktop mutation leaves an operation behind (phase 3 of multi-client sync)."""

from __future__ import annotations

import unittest

from support import tmp_vault
from vault.core import journal


class SessionJournalTest(unittest.TestCase):
    """The op log is written by the session, not by the UI — one hook per mutation."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.index = self.session.index
        self.client = self.session.client_id

    def tearDown(self) -> None:
        self.session.close()

    def _last_op(self) -> dict:
        rows = self.index.conn.execute(
            "SELECT json FROM journal_out ORDER BY seq DESC LIMIT 1"
        ).fetchall()
        self.assertTrue(rows, "no op was recorded")
        import json

        return json.loads(str(rows[0]["json"]))

    def test_a_write_records_a_put_with_its_blob(self) -> None:
        row = self.session.write_file("note.md", b"hello")
        op = self._last_op()
        self.assertEqual(op["kind"], "put")
        self.assertEqual(op["path"], "note.md")
        self.assertEqual(op["payload"]["blob_id"], row["blob_id"])
        self.assertEqual(op["payload"]["size"], 5)
        self.assertEqual(op["client"], self.client)
        self.assertEqual(journal.current_rev(self.index, "note.md"), op["rev"])

    def test_an_edit_bases_its_op_on_the_previous_revision(self) -> None:
        self.session.write_file("note.md", b"one")
        first = self._last_op()
        self.session.write_file("note.md", b"two")
        second = self._last_op()
        self.assertEqual(first["rev"], second["base_rev"])
        self.assertGreater(second["rev"], first["rev"])

    def test_mkdir_and_its_parents_record_puts(self) -> None:
        self.session.mkdir("a/b/c")
        ops = [
            self._last_op()
            for _ in range(3)
        ]  # noqa: F841 - the loop only documents intent; read the table instead
        rows = self.index.conn.execute(
            "SELECT json FROM journal_out ORDER BY seq"
        ).fetchall()
        paths = []
        import json

        for row in rows:
            op = json.loads(str(row["json"]))
            self.assertEqual(op["kind"], "put")
            self.assertTrue(op["payload"]["is_dir"])
            paths.append(op["path"])
        self.assertEqual(paths, ["a", "a/b", "a/b/c"])

    def test_move_records_a_rename_with_the_source(self) -> None:
        self.session.write_file("a.md", b"x")
        self.session.move("a.md", "b.md")
        op = self._last_op()
        self.assertEqual(op["kind"], "rename")
        self.assertEqual(op["path"], "b.md")
        self.assertEqual(op["payload"]["from"], "a.md")

    def test_copy_records_a_put_for_the_new_path(self) -> None:
        self.session.write_file("a.md", b"x")
        self.session.copy("a.md", "b.md")
        op = self._last_op()
        self.assertEqual((op["kind"], op["path"]), ("put", "b.md"))
        self.assertIn("blob_id", op["payload"])

    def test_delete_records_a_delete_and_a_tombstone(self) -> None:
        row = self.session.write_file("gone.md", b"x")
        self.session.delete("gone.md")
        op = self._last_op()
        self.assertEqual((op["kind"], op["path"]), ("delete", "gone.md"))
        tomb = self.index.conn.execute(
            "SELECT rev FROM tombstones WHERE path='gone.md'"
        ).fetchone()
        self.assertIsNotNone(tomb, "a deletion must leave a tombstone")
        self.assertGreaterEqual(int(tomb["rev"]), 1)
        self.assertIsNotNone(row)

    def test_a_level_change_records_the_new_blob_for_a_file(self) -> None:
        self.session.write_file("secret.md", b"x")
        self.session.set_sensitivity("secret.md", "secret")
        op = self._last_op()
        self.assertEqual(op["kind"], "put")
        self.assertEqual(op["payload"]["sensitivity"], "secret")
        self.assertIn("blob_id", op["payload"])

    def test_a_level_change_on_a_folder_records_a_level_op(self) -> None:
        self.session.mkdir("folder")
        self.session.set_sensitivity("folder", "secret")
        op = self._last_op()
        self.assertEqual((op["kind"], op["path"]), ("level", "folder"))

    def test_tags_and_emoji_record_metadata_ops(self) -> None:
        self.session.write_file("tagged.md", b"x")
        self.session.set_tags("tagged.md", ["کار", "مالی"])
        self.assertEqual(self._last_op()["payload"]["tags"], ["کار", "مالی"])
        self.session.set_emoji("tagged.md", "📌")
        op = self._last_op()
        self.assertEqual((op["kind"], op["payload"]["emoji"]), ("emoji", "📌"))

    def test_a_conflict_is_visible_and_answerable_through_the_session(self) -> None:
        """The session exposes the two calls the UI needs — list, then answer."""
        from vault.core import journal as journal_mod

        self.session.write_file("shared.md", b"mine")
        base = journal_mod.current_rev(self.index, "shared.md")
        # A peer's op based on an older revision arrives.
        peer = journal_mod.build_op(
            self.index,
            "put",
            "shared.md",
            client="desktop",
            seq=1,
            base_rev=base - 1,
            payload={"blob_id": "theirs", "size": 6},
        )
        peer["op_id"] = "desktop-000001"
        journal_mod.apply_ops(self.index, [peer])

        conflicts = self.session.conflicts()
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["path"], "shared.md")

        answer = self.session.resolve_conflict(int(conflicts[0]["id"]), "mine")

        self.assertEqual(answer["choice"], "mine")
        self.assertEqual(self.session.conflicts(), [])
        self.assertEqual(
            self.session.pending_ops(), 2, "the decision must travel as an outgoing op"
        )

    def test_a_folder_note_travels_sealed(self) -> None:
        """The note text never appears in the journal (plaintext metadata) — only its ciphertext."""
        self.session.mkdir("folder")
        self.session.set_folder_note("folder", "یادداشت محرمانهٔ من")
        op = self._last_op()
        self.assertEqual(op["kind"], "note")
        self.assertEqual(op["payload"]["scope"], "folder")
        raw = str(
            self.index.conn.execute(
                "SELECT json FROM journal_out ORDER BY seq DESC LIMIT 1"
            ).fetchone()["json"]
        )
        self.assertNotIn("یادداشت محرمانه", raw, "the note text leaked into the journal")
        self.assertEqual(self.session._open_note(op["payload"]), "یادداشت محرمانهٔ من")

    def test_a_peer_note_op_is_applied_through_the_handler(self) -> None:
        self.session.write_file("note.md", b"x")
        sealed = self.session._seal_note("از دستگاه دیگر")
        op = journal.build_op(
            self.index,
            "note",
            "note.md",
            client="desktop",
            seq=1,
            base_rev=journal.current_rev(self.index, "note.md"),
            payload={"scope": "file", **sealed},
        )
        op["op_id"] = "desktop-000001"

        result = journal.apply_ops(self.index, [op], handler=self.session.apply_journal_op)

        self.assertEqual(result["applied"], 1)
        self.assertEqual(self.session.file_note("note.md"), "از دستگاه دیگر")

    def test_a_stale_note_op_is_a_conflict(self) -> None:
        self.session.write_file("note.md", b"x")
        stale = self.session._seal_note("قدیمی")
        op = journal.build_op(
            self.index,
            "note",
            "note.md",
            client="desktop",
            seq=1,
            base_rev=0,
            payload={"scope": "file", **stale},
        )
        op["op_id"] = "desktop-000002"

        result = journal.apply_ops(self.index, [op], handler=self.session.apply_journal_op)

        self.assertEqual(result["conflicts"], 1)
        self.assertIsNone(self.session.file_note("note.md"))

    def test_answering_a_note_conflict_with_both_keeps_both_texts(self) -> None:
        self.session.write_file("note.md", b"x")
        self.session.set_file_note("note.md", "مال من")
        stale = self.session._seal_note("مال او")
        op = journal.build_op(
            self.index,
            "note",
            "note.md",
            client="desktop",
            seq=1,
            base_rev=0,
            payload={"scope": "file", **stale},
        )
        op["op_id"] = "desktop-000003"
        journal.apply_ops(self.index, [op], handler=self.session.apply_journal_op)
        conflict = self.session.conflicts()[0]

        self.session.resolve_conflict(int(conflict["id"]), "both")

        note = self.session.file_note("note.md") or ""
        self.assertIn("مال من", note)
        self.assertIn("مال او", note)
        self.assertEqual(self.session.conflicts(), [])

    def test_a_learning_mark_is_recorded_and_does_not_move_the_revision(self) -> None:
        self.session.write_file("card.md", b"x")
        before = journal.current_rev(self.index, "card.md")
        self.session.learning_start("card.md")
        op = self._last_op()
        self.assertEqual(op["kind"], "learning")
        self.assertIn("stage", op["payload"])
        self.assertEqual(
            journal.current_rev(self.index, "card.md"), before, "a review must not bump the entry"
        )

    def test_pending_ops_counts_what_is_not_published(self) -> None:
        self.assertEqual(self.session.pending_ops(), 0)
        self.session.write_file("a.md", b"x")
        self.session.write_file("b.md", b"y")
        self.assertEqual(self.session.pending_ops(), 2)
        ids = [op["op_id"] for op in journal.pending(self.index)]
        journal.mark_published(self.index, ids)
        self.assertEqual(self.session.pending_ops(), 0)


if __name__ == "__main__":
    unittest.main()
