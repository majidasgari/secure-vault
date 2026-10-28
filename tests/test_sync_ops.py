"""Bucket transport for the op log: push/pull, gaps, identity, retries (SPEC/01 §10)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from support import tmp_vault
from vault.core import journal, sync_ops
from vault.errors import SyncError


class FakeBucket:
    """A dict-backed stand-in for an S3 client (get/put/delete/list)."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.fail_puts = 0

    def get(self, key: str) -> bytes | None:
        return self.objects.get(key)

    def put(self, key: str, data: bytes, *, if_none_match: bool = False) -> bool:
        if self.fail_puts:
            self.fail_puts -= 1
            return False
        self.objects[key] = data
        return True

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)

    def list(self, prefix: str) -> list[dict[str, object]]:
        return [
            {"key": key, "size": len(value), "etag": None, "modified": 0}
            for key, value in sorted(self.objects.items())
            if key.startswith(prefix)
        ]


class _PreconditionBucket(FakeBucket):
    """A bucket that answers like S3: an existing object under ``IfNoneMatch`` is a 412 (False)."""

    def put(self, key: str, data: bytes, *, if_none_match: bool = False) -> bool:
        if if_none_match and key in self.objects:
            return False
        return super().put(key, data, if_none_match=if_none_match)


class OpsTransportTest(unittest.TestCase):
    """What a sync must guarantee, without a real bucket."""

    def setUp(self) -> None:
        self.bucket = FakeBucket()
        self.home = tmp_vault()
        self.index = self.home.index
        self.transport = sync_ops.OpsTransport(
            self.bucket, prefix="sync/", vault_id="vault-1", client_id="phone"
        )
        self.phone = journal.client_id("vault-1", base=None)  # not used: fixed ids below

    def tearDown(self) -> None:
        self.home.close()

    # ------------------------------------------------------------------ push
    def test_push_publishes_pending_ops_once(self) -> None:
        journal.record(self.index, "put", "a.md", client="phone", payload={"blob_id": "b1", "size": 1})
        journal.record(self.index, "put", "b.md", client="phone", payload={"blob_id": "b2", "size": 1})

        first = self.transport.push(self.index)
        self.assertEqual(first["pushed"], 2)
        self.assertEqual(first["failed"], 0)
        self.assertIsNotNone(self.bucket.get("sync/ops/phone/000001.json"))
        self.assertIsNotNone(self.bucket.get("sync/ops/phone/HEAD"))

        second = self.transport.push(self.index)
        self.assertEqual(second["pushed"], 0, "an op is never pushed twice")

    def test_a_blob_already_in_the_bucket_is_not_a_failure(self) -> None:
        """A 412 on an existing blob is success — the legacy mirror leaves every blob behind."""
        bucket = _PreconditionBucket()
        blob = Path(tempfile.mkdtemp()) / "b1.enc"
        blob.write_bytes(b"ciphertext")
        bucket.objects["sync/files/b1/b1.enc"] = b"ciphertext"  # already there
        transport = sync_ops.OpsTransport(
            bucket, prefix="sync/", vault_id="vault-1", client_id="phone",
            blob_path=lambda _blob_id: blob,
        )
        journal.record(
            self.index, "put", "a.md", client="phone", payload={"blob_id": "b1", "size": 1}
        )

        result = transport.push(self.index)

        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["pushed"], 1)
        self.assertEqual(len(journal.pending(self.index)), 0, "the op must be marked published")

    def test_max_ops_publishes_a_slice_and_leaves_the_rest(self) -> None:
        """A caller with a long backlog drives the push a few ops at a time."""
        for number in range(5):
            journal.record(
                self.index, "put", f"n{number}.md", client="phone",
                payload={"blob_id": f"b{number}", "size": 1},
            )

        first = self.transport.push(self.index, max_ops=2)

        self.assertEqual(first["pushed"], 2)
        self.assertEqual(len(journal.pending(self.index)), 3, "the rest waits for the next slice")
        second = self.transport.push(self.index, max_ops=2)
        self.assertEqual(second["pushed"], 2)
        self.assertEqual(len(journal.pending(self.index)), 1)

    def test_a_failed_put_leaves_the_op_unpublished(self) -> None:
        journal.record(self.index, "put", "a.md", client="phone", payload={"blob_id": "b1", "size": 1})
        self.bucket.fail_puts = 1

        result = self.transport.push(self.index)

        self.assertEqual(result["pushed"], 0)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(len(journal.pending(self.index)), 1, "an unpushed op must stay queued")

        retry = self.transport.push(self.index)
        self.assertEqual(retry["pushed"], 1)

    def test_the_pushed_object_carries_the_vault_id(self) -> None:
        journal.record(self.index, "put", "a.md", client="phone", payload={"blob_id": "b1", "size": 1})
        self.transport.push(self.index)
        raw = self.bucket.get("sync/ops/phone/000001.json")
        self.assertIsNotNone(raw)
        body = json.loads(raw)
        self.assertEqual(body["vault_id"], "vault-1")

    # ------------------------------------------------------------------ pull
    def test_pull_in_slices_says_when_there_is_more(self) -> None:
        """A caller can keep the pull out of its event loop: each call applies a slice."""
        other = tmp_vault()
        try:
            desktop = sync_ops.OpsTransport(
                self.bucket, prefix="sync/", vault_id="vault-1", client_id="desktop"
            )
            for number in range(3):
                journal.record(
                    other.index, "put", f"n{number}.md", client="desktop",
                    payload={"blob_id": f"bd{number}", "size": 1},
                )
            desktop.push(other.index)

            first = self.transport.pull(self.index, max_ops=2)
            self.assertEqual(first["applied"], 2)
            self.assertTrue(first["more"], "one op is still waiting")

            second = self.transport.pull(self.index, max_ops=2)
            self.assertEqual(second["applied"], 1)
            self.assertFalse(second["more"])
        finally:
            other.close()

    def test_pull_applies_the_other_clients_ops(self) -> None:
        other = tmp_vault()
        try:
            desktop = sync_ops.OpsTransport(
                self.bucket, prefix="sync/", vault_id="vault-1", client_id="desktop"
            )
            journal.record(
                other.index, "put", "note.md", client="desktop", payload={"blob_id": "bd", "size": 5}
            )
            desktop.push(other.index)

            result = self.transport.pull(self.index)

            self.assertEqual(result["applied"], 1)
            self.assertEqual(result["conflicts"], 0)
            row = self.index.get_file("note.md")
            self.assertIsNotNone(row)
            self.assertEqual(row["blob_id"], "bd")

            again = self.transport.pull(self.index)
            self.assertEqual(again["applied"], 0, "a second pull is a no-op")
            self.assertEqual(again["duplicates"], 0)
        finally:
            other.close()

    def test_pull_stops_at_a_gap(self) -> None:
        other = tmp_vault()
        try:
            desktop = sync_ops.OpsTransport(
                self.bucket, prefix="sync/", vault_id="vault-1", client_id="desktop"
            )
            for number in range(1, 4):
                journal.record(
                    other.index,
                    "put",
                    f"n{number}.md",
                    client="desktop",
                    payload={"blob_id": f"b{number}", "size": 1},
                )
            desktop.push(other.index)
            self.bucket.delete("sync/ops/desktop/000002.json")

            result = self.transport.pull(self.index)

            self.assertEqual(result["applied"], 1, "only the op before the hole may be applied")
            self.assertEqual(result["gaps"][0]["client"], "desktop")
            self.assertEqual(result["gaps"][0]["missing"], [2])
            self.assertIsNone(self.index.get_file("n2.md"))
            self.assertIsNone(self.index.get_file("n3.md"))

            # The missing object arrives (a retried push) → the rest applies.
            self.bucket.objects["sync/ops/desktop/000002.json"] = json.dumps(
                {
                    "op_id": "desktop-000002",
                    "client": "desktop",
                    "seq": 2,
                    "ts": journal.now_ms(),
                    "kind": "put",
                    "path": "n2.md",
                    "base_rev": 0,
                    "rev": 1,
                    "payload": {"blob_id": "b2", "size": 1},
                    "vault_id": "vault-1",
                },
                ensure_ascii=False,
            ).encode("utf-8")
            healed = self.transport.pull(self.index)
            self.assertEqual(healed["applied"], 2)
            self.assertIsNotNone(self.index.get_file("n3.md"))
        finally:
            other.close()

    def test_a_foreign_vault_is_refused(self) -> None:
        self.bucket.objects["sync/ops/desktop/000001.json"] = json.dumps(
            {
                "op_id": "desktop-000001",
                "client": "desktop",
                "seq": 1,
                "ts": 1,
                "kind": "put",
                "path": "x.md",
                "base_rev": 0,
                "rev": 1,
                "payload": {"blob_id": "bx", "size": 1},
                "vault_id": "another-vault",
            }
        ).encode("utf-8")
        with self.assertRaises(SyncError):
            self.transport.pull(self.index)
        self.assertIsNone(self.index.get_file("x.md"))

    # ------------------------------------------------------------------ together
    def test_two_clients_exchange_edits_and_one_conflict(self) -> None:
        other = tmp_vault()
        try:
            desktop = sync_ops.OpsTransport(
                self.bucket, prefix="sync/", vault_id="vault-1", client_id="desktop"
            )
            # Both start from the same file, revision 1.
            for index in (self.index, other.index):
                index.upsert_file("shared.md", blob_id="base", size=4)
                index.conn.execute("UPDATE files SET rev=1 WHERE logical_path='shared.md'")
                index.conn.commit()

            # Offline: both edit it, and each adds one note of its own. A local edit writes the row
            # and records the op on top of the revision both sides had (phase 3 wires this).
            for index, client, blob in (
                (self.index, "phone", "from-phone"),
                (other.index, "desktop", "from-desktop"),
            ):
                index.upsert_file("shared.md", blob_id=blob, size=9)
                index.conn.execute("UPDATE files SET rev=rev+1 WHERE logical_path='shared.md'")
                index.conn.commit()
                journal.record(
                    index,
                    "put",
                    "shared.md",
                    client=client,
                    payload={"blob_id": blob, "size": 9},
                    base_rev=1,
                )
            journal.record(
                self.index, "put", "phone.md", client="phone", payload={"blob_id": "p1", "size": 1}
            )
            journal.record(
                other.index, "put", "desk.md", client="desktop", payload={"blob_id": "d1", "size": 1}
            )

            self.transport.push(self.index)
            desktop.push(other.index)
            phone_pull = self.transport.pull(self.index)
            desktop_pull = desktop.pull(other.index)

            self.assertEqual(phone_pull["applied"], 1, "the desktop's new file lands on the phone")
            self.assertEqual(phone_pull["conflicts"], 1, "the shared edit is a question, not a choice")
            self.assertEqual(desktop_pull["applied"], 1)
            self.assertEqual(desktop_pull["conflicts"], 1)
            self.assertIsNotNone(self.index.get_file("desk.md"))
            self.assertIsNotNone(other.index.get_file("phone.md"))
        finally:
            other.close()


class BlobTransferTest(unittest.TestCase):
    """Content travels with the op that names it — an op alone is not a readable file."""

    def setUp(self) -> None:
        self.bucket = FakeBucket()
        self.a_home = tmp_vault()
        self.b_home = tmp_vault()
        self.a_dir = tempfile.mkdtemp(prefix="blobs-a-")
        self.b_dir = tempfile.mkdtemp(prefix="blobs-b-")

    def tearDown(self) -> None:
        self.a_home.close()
        self.b_home.close()

    def _path(self, directory):
        return lambda blob_id: Path(directory) / f"{blob_id}.enc"

    def _transport(self, home, client, directory):
        return sync_ops.OpsTransport(
            self.bucket,
            prefix="sync/",
            vault_id="vault-1",
            client_id=client,
            blob_path=self._path(directory),
        )

    def test_push_uploads_the_blob_before_the_op(self) -> None:
        blob = Path(self.a_dir) / "deadbeef.enc"
        blob.write_bytes(b"payload!")
        journal.record(
            self.a_home.index,
            "put",
            "note.md",
            client="a",
            payload={"blob_id": "deadbeef", "size": 8},
        )

        self._transport(self.a_home, "a", self.a_dir).push(self.a_home.index)

        self.assertEqual(self.bucket.get("sync/files/de/deadbeef.enc"), b"payload!")
        self.assertIsNotNone(self.bucket.get("sync/ops/a/000001.json"))

    def test_pull_writes_the_blob_next_to_the_row(self) -> None:
        blob = Path(self.a_dir) / "cafebabe.enc"
        blob.write_bytes(b"content")
        journal.record(
            self.a_home.index,
            "put",
            "note.md",
            client="a",
            payload={"blob_id": "cafebabe", "size": 7},
        )
        self._transport(self.a_home, "a", self.a_dir).push(self.a_home.index)

        self._transport(self.b_home, "b", self.b_dir).pull(self.b_home.index)

        self.assertEqual((Path(self.b_dir) / "cafebabe.enc").read_bytes(), b"content")
        self.assertIsNotNone(self.b_home.index.get_file("note.md"))

    def test_an_op_whose_blob_is_missing_is_not_applied(self) -> None:
        journal.record(
            self.b_home.index,
            "put",
            "other.md",
            client="a",
            payload={"blob_id": "00112233", "size": 3},
        )
        # The op is in the bucket, its blob is not (a crashed upload).
        self.bucket.objects["sync/ops/a/000001.json"] = json.dumps(
            {
                "op_id": "a-000001",
                "client": "a",
                "seq": 1,
                "ts": 1,
                "kind": "put",
                "path": "note.md",
                "base_rev": 0,
                "rev": 1,
                "payload": {"blob_id": "00112233", "size": 3},
                "vault_id": "vault-1",
            }
        ).encode("utf-8")

        result = self._transport(self.a_home, "b", self.b_dir).pull(self.a_home.index)

        self.assertEqual(result["applied"], 0)
        self.assertIsNone(self.a_home.index.get_file("note.md"))
        self.assertTrue(result["gaps"])


if __name__ == "__main__":
    unittest.main()
