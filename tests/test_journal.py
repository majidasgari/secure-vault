"""The operation log: apply-once, ask-on-conflict, deterministic order (SPEC/01 §10)."""

from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from support import tmp_vault
from vault.core import journal


def _remote_put(index, path, content, base_rev, client, seq):
    """Build one peer's ``put`` op with an explicit revision and identity."""
    op = journal.build_op(
        index,
        "put",
        path,
        payload={"blob_id": f"blob-{content}", "size": len(content), "encrypted": 1},
        base_rev=base_rev,
        client=client,
        seq=seq,
    )
    op["op_id"] = f"{client}-{seq:06d}"
    return op


def _local_edit(index, path, content):
    """What the app does when the user edits here: write the row and bump its revision."""
    index.upsert_file(path, blob_id=f"blob-{content}", size=len(content))
    index.conn.execute(
        "UPDATE files SET rev=COALESCE(rev,0)+1 WHERE logical_path=? COLLATE NOCASE", (path,)
    )
    index.conn.commit()


class JournalTest(unittest.TestCase):
    """Every rule that keeps two writers from losing each other's work."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.index = self.session.index
        self.index.upsert_file("note.md", blob_id="blob-base", size=4)
        self.index.conn.execute("UPDATE files SET rev=1 WHERE logical_path='note.md'")
        self.index.conn.commit()

    def tearDown(self) -> None:
        self.session.close()

    # ------------------------------------------------------------------ ordering
    def test_a_put_on_an_unchanged_path_applies(self) -> None:
        result = journal.apply_ops(self.index, [_remote_put(self.index, "note.md", "new", 1, "b", 1)])
        self.assertEqual(result["applied"], 1)
        self.assertEqual(result["conflicts"], 0)
        self.assertEqual(self.index.get_file("note.md")["blob_id"], "blob-new")
        self.assertEqual(journal.current_rev(self.index, "note.md"), 2)

    def test_an_edit_based_on_an_older_revision_asks_and_keeps_the_index(self) -> None:
        _local_edit(self.index, "note.md", "mine")  # the user edited here, revision now 2
        result = journal.apply_ops(
            self.index, [_remote_put(self.index, "note.md", "theirs", 1, "b", 1)]
        )

        self.assertEqual(result["conflicts"], 1)
        self.assertEqual(self.index.get_file("note.md")["blob_id"], "blob-mine")
        open_conflicts = journal.unresolved(self.index)
        self.assertEqual(len(open_conflicts), 1)
        self.assertEqual(open_conflicts[0]["path"], "note.md")

    def test_the_same_op_twice_applies_once(self) -> None:
        op = _remote_put(self.index, "once.md", "x", 0, "b", 1)
        journal.apply_ops(self.index, [op])
        result = journal.apply_ops(self.index, [op])
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["duplicates"], 1)

    def test_a_delete_on_a_changed_path_asks_instead_of_deleting(self) -> None:
        _local_edit(self.index, "note.md", "mine")  # revision 2, the peer saw revision 1
        op = journal.build_op(self.index, "delete", "note.md", base_rev=1, client="b", seq=1)
        op["op_id"] = "b-000001"
        result = journal.apply_ops(self.index, [op])
        self.assertEqual(result["conflicts"], 1)
        self.assertIsNotNone(self.index.get_file("note.md"))

    def test_a_create_after_our_delete_asks_instead_of_resurrecting(self) -> None:
        self.index.upsert_file("gone.md", blob_id="blob-old", size=3)
        self.index.conn.execute("UPDATE files SET rev=2 WHERE logical_path='gone.md'")
        self.index.conn.commit()
        kill = journal.build_op(self.index, "delete", "gone.md", base_rev=2, client="b", seq=1)
        kill["op_id"] = "b-000001"
        journal.apply_ops(self.index, [kill])
        self.assertIsNone(self.index.get_file("gone.md"))

        late = _remote_put(self.index, "gone.md", "zombie", 1, "c", 1)
        result = journal.apply_ops(self.index, [late])
        self.assertEqual(result["conflicts"], 1)
        self.assertIsNone(self.index.get_file("gone.md"), "a deleted file came back without asking")

    def test_a_rename_onto_an_existing_path_asks(self) -> None:
        self.index.upsert_file("a.md", blob_id="blob-a", size=1)
        self.index.upsert_file("b.md", blob_id="blob-b", size=1)
        op = journal.build_op(
            self.index, "rename", "b.md", payload={"from": "a.md"}, base_rev=0, client="b", seq=1
        )
        op["op_id"] = "b-000001"
        result = journal.apply_ops(self.index, [op])
        self.assertEqual(result["conflicts"], 1)
        self.assertEqual(self.index.get_file("a.md")["blob_id"], "blob-a")
        self.assertEqual(self.index.get_file("b.md")["blob_id"], "blob-b")

    # ------------------------------------------------------------------ metadata
    def test_metadata_ops_apply_without_asking(self) -> None:
        tag_op = journal.record(
            self.index, "tag", "note.md", client="me", payload={"tags": ["کار"]}
        )
        emoji_op = journal.record(
            self.index, "emoji", "note.md", client="me", payload={"emoji": "📌"}
        )
        result = journal.apply_ops(self.index, [tag_op, emoji_op])
        self.assertEqual(result["applied"], 2)
        self.assertEqual(self.index.get_tags("note.md"), ["کار"])
        self.assertEqual(self.index.get_file("note.md")["emoji"], "📌")

    # ------------------------------------------------------------------ answers
    def test_answering_theirs_writes_their_version_and_an_op(self) -> None:
        _local_edit(self.index, "note.md", "mine")
        journal.apply_ops(self.index, [_remote_put(self.index, "note.md", "theirs", 1, "b", 1)])
        conflict = journal.unresolved(self.index)[0]
        self.assertEqual(conflict["their_client"], "b")

        journal.resolve(self.index, conflict["id"], "theirs", client="me")

        self.assertEqual(self.index.get_file("note.md")["blob_id"], "blob-theirs")
        self.assertEqual(journal.unresolved(self.index), [])
        self.assertEqual(len(journal.pending(self.index)), 1, "the answer must travel as an op")

    def test_answering_both_keeps_a_copy_beside_the_file(self) -> None:
        _local_edit(self.index, "note.md", "mine")
        journal.apply_ops(self.index, [_remote_put(self.index, "note.md", "theirs", 1, "b", 1)])
        journal.resolve(self.index, journal.unresolved(self.index)[0]["id"], "both", client="me")

        self.assertEqual(self.index.get_file("note.md")["blob_id"], "blob-mine")
        copy = self.index.get_file(f"note ({journal.COPY_SUFFIX}).md")
        self.assertIsNotNone(copy, "the losing version must survive as a copy")
        self.assertEqual(copy["blob_id"], "blob-theirs")

    def test_answering_mine_keeps_the_local_file_and_clears_the_conflict(self) -> None:
        _local_edit(self.index, "note.md", "mine")
        journal.apply_ops(self.index, [_remote_put(self.index, "note.md", "theirs", 1, "b", 1)])
        journal.resolve(self.index, journal.unresolved(self.index)[0]["id"], "mine", client="me")
        self.assertEqual(self.index.get_file("note.md")["blob_id"], "blob-mine")
        self.assertEqual(journal.unresolved(self.index), [])

    def test_an_answer_applied_on_the_other_device_does_not_conflict_again(self) -> None:
        """The other side receives the decision as an op and applies it, even at a newer revision."""
        other = tmp_vault()
        try:
            for index in (self.index, other.index):
                index.upsert_file("note.md", blob_id="blob-mine", size=4)
                index.conn.execute("UPDATE files SET rev=2 WHERE logical_path='note.md'")
                index.conn.commit()
            journal.apply_ops(self.index, [_remote_put(self.index, "note.md", "theirs", 1, "b", 1)])
            answer = journal.resolve(
                self.index, journal.unresolved(self.index)[0]["id"], "theirs", client="b"
            )

            result = journal.apply_ops(other.index, [answer])

            self.assertEqual(result["applied"], 1, result)
            self.assertEqual(result["conflicts"], 0)
            self.assertEqual(other.index.get_file("note.md")["blob_id"], "blob-theirs")
        finally:
            other.close()

    # ------------------------------------------------------------------ convergence
    def test_two_editors_reach_the_same_state_after_the_same_ops(self) -> None:
        """Both devices apply the same op set in different orders → identical indexes."""
        other = tmp_vault()
        try:
            for index in (self.index, other.index):
                index.upsert_file("note.md", blob_id="blob-base", size=4)
                index.conn.execute("UPDATE files SET rev=1 WHERE logical_path='note.md'")
                index.upsert_file("shared.md", blob_id="blob-base", size=4)
                index.conn.execute("UPDATE files SET rev=1 WHERE logical_path='shared.md'")
                index.conn.commit()

            ops = [
                _remote_put(self.index, "shared.md", "a1", 1, "a", 1),
                _remote_put(self.index, "shared.md", "b1", 1, "b", 2),
                _remote_put(self.index, "new-a.md", "a2", 0, "a", 3),
                _remote_put(self.index, "new-b.md", "b2", 0, "b", 4),
            ]
            shuffled = list(ops)
            random.Random(7).shuffle(shuffled)
            journal.apply_ops(self.index, shuffled)
            reordered = list(ops)
            random.Random(11).shuffle(reordered)
            journal.apply_ops(other.index, reordered)

            def snapshot(index):
                rows = index.conn.execute(
                    "SELECT logical_path, blob_id, rev FROM files ORDER BY logical_path"
                ).fetchall()
                return [(str(r["logical_path"]), r["blob_id"], int(r["rev"] or 0)) for r in rows]

            self.assertEqual(snapshot(self.index), snapshot(other.index))
            self.assertEqual(len(journal.unresolved(self.index)), 1)
            self.assertEqual(len(journal.unresolved(other.index)), 1)
        finally:
            other.close()

    # ------------------------------------------------------------------ journal
    def test_pending_and_publish_round_trip(self) -> None:
        first = journal.record(
            self.index, "put", "x.md", client="me", payload={"blob_id": "b", "size": 1}
        )
        second = journal.record(
            self.index, "put", "y.md", client="me", payload={"blob_id": "c", "size": 1}
        )
        self.assertNotEqual(first["op_id"], second["op_id"], "two ops must never share an id")
        self.assertEqual(len(journal.pending(self.index)), 2)
        ids = [op["op_id"] for op in journal.pending(self.index)]
        self.assertEqual(journal.mark_published(self.index, ids), 2)
        self.assertEqual(journal.pending(self.index), [])

    def test_client_id_is_machine_local_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = journal.client_id("vault-abc", base=Path(tmp))
            self.assertEqual(first, journal.client_id("vault-abc", base=Path(tmp)))
            other = journal.client_id("vault-xyz", base=Path(tmp))
            self.assertNotEqual(first, other, "two vaults get two client ids")
            self.assertFalse(
                (Path(tmp) / f"{first}.json").exists(), "the id is not stored under its own name"
            )
        op = journal.record(self.index, "put", "z.md", client="me", payload={"blob_id": "b"})
        self.assertTrue(op["op_id"].startswith("me-"))


if __name__ == "__main__":
    unittest.main()
