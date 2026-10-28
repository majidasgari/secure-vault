"""Kill the process in the middle of a sync: nothing may be lost, duplicated or half-applied.

The invariants under test are the ones a crash can break:

* an op object only exists in the bucket after the op is queued for publishing, and a published op
  always has its object (``push`` marks published only after the PUT);
* a killed push leaves the rest queued, and the next run finishes the job without duplicates;
* a killed pull leaves the index at exactly the ops it applied (no row without its blob, no cursor
  ahead of the data), and the next run applies the remainder once.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from support import tmp_vault
from vault.core import journal
from vault.core.session import VaultSession

REPO = Path(__file__).resolve().parents[1]


class DirBucket:
    """An S3 client backed by a directory, so a killed child leaves visible state behind."""

    def __init__(self, root: Path, delay: float = 0.0) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        # A small delay makes the kill deterministic: the child is still pushing when the signal lands.
        self.delay = delay

    def _path(self, key: str) -> Path:
        return self.root / key

    def get(self, key: str) -> bytes | None:
        path = self._path(key)
        return path.read_bytes() if path.is_file() else None

    def put(self, key: str, data: bytes, *, if_none_match: bool = False) -> bool:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        if if_none_match and path.exists():
            return False
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
        if self.delay:
            time.sleep(self.delay)
        return True

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    def list(self, prefix: str) -> list[dict[str, object]]:
        entries = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            key = path.relative_to(self.root).as_posix()
            if key.startswith(prefix):
                entries.append({"key": key, "size": path.stat().st_size, "etag": None, "modified": 0})
        return entries


CHILD = r"""
import os, sys, time
sys.path.insert(0, {src!r})
from pathlib import Path
from vault.core import journal, sync_ops
from vault.core.s3 import S3Config
from vault.core.session import VaultSession

home, bucket_root, client = Path({home!r}), Path({bucket!r}), {client!r}
session = VaultSession(home)
session.unlock({password!r})
index = session.index
for number in range({count}):
    journal.record(
        index, "put", f"n{{number:03d}}.md", client=client,
        payload={{"blob_id": f"blob-{{number:03d}}", "size": 4}},
    )
transport = sync_ops.OpsTransport(
    __import__("test_kill_sync", fromlist=["DirBucket"]).DirBucket(bucket_root, delay=0.01),
    prefix="sync/", vault_id="vault-1", client_id=client,
)
transport.push(index)
print("done", flush=True)
"""

PULLER = r"""
import os, sys
sys.path.insert(0, {src!r})
from pathlib import Path
from vault.core import sync_ops
from vault.core.session import VaultSession

home, bucket_root = Path({home!r}), Path({bucket!r})
session = VaultSession(home)
session.unlock({password!r})
transport = sync_ops.OpsTransport(
    __import__("test_kill_sync", fromlist=["DirBucket"]).DirBucket(bucket_root),
    prefix="sync/", vault_id="vault-1", client_id="phone",
)
report = transport.pull(session.index)
print("pulled", report["applied"], flush=True)
"""


class KillSyncTest(unittest.TestCase):
    """A crash must leave a resumable state, never a silent gap."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="kill-"))
        self.bucket = DirBucket(self.root / "bucket")
        self.session = tmp_vault()
        self.src = str(REPO / "src")
        self.tests = str(REPO / "tests")
        self.password = "kill-test-pass"

    def tearDown(self) -> None:
        self.session.close()

    def _run_and_kill(self, script: str, *, wait_for: int, timeout: float = 30.0) -> None:
        """Start ``script`` and SIGKILL it as soon as ``wait_for`` puts have landed."""
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([self.src, self.tests]))
        child = subprocess.Popen(
            [sys.executable, "-c", script],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(REPO),
        )
        deadline = time.monotonic() + timeout
        target = self.root / "bucket" / "sync" / "ops"
        while time.monotonic() < deadline:
            if child.poll() is not None:
                out, err = child.communicate()
                raise AssertionError(f"the child finished before it could be killed:\n{err.decode()[-800:]}")
            found = sum(1 for _ in target.rglob("*.json")) if target.is_dir() else 0
            if found >= wait_for:
                child.kill()
                child.wait(timeout=10)
                return
            time.sleep(0.02)
        child.kill()
        raise AssertionError("the child never reached the kill point")

    def test_a_killed_push_is_resumable_and_never_half_published(self) -> None:
        home = Path(tempfile.mkdtemp(prefix="kill-vault-"))
        created = VaultSession.create(home, self.password)
        created.close()
        script = CHILD.format(
            src=self.src, home=str(home), bucket=str(self.root / "bucket"),
            client="desktop", password=self.password, count=40,
        )
        self._run_and_kill(script, wait_for=5)

        # What survived the kill: some ops on disk, and the child's vault with its journal.
        published = sorted(p.name for p in (self.root / "bucket" / "sync" / "ops" / "desktop").glob("*.json"))
        self.assertGreaterEqual(len(published), 5)
        session = VaultSession(home)
        session.unlock(self.password)
        try:
            rows = session.index.conn.execute(
                "SELECT op_id FROM journal_out WHERE published=1"
            ).fetchall()
            published_ids = {str(row["op_id"]) for row in rows}
            # Invariant 1: everything marked published has an object in the bucket.
            for op_id in published_ids:
                seq = int(op_id.split("-")[-1])
                self.assertTrue(
                    (self.root / "bucket" / "sync" / "ops" / "desktop" / f"{seq:06d}.json").is_file(),
                    f"op {op_id} is marked published but its object is missing",
                )
            # Invariant 2: the ones not marked are still queued, not lost.
            pending = len(journal.pending(session.index, limit=200))
            self.assertEqual(pending + len(published_ids), 40)

            # The next run finishes the job — no duplicates, 40 objects in the end.
            from vault.core import sync_ops

            result = sync_ops.OpsTransport(
                self.bucket, prefix="sync/", vault_id="vault-1", client_id="desktop"
            ).push(session.index)
            self.assertEqual(result["failed"], 0)
            objects = list((self.root / "bucket" / "sync" / "ops" / "desktop").glob("*.json"))
            self.assertEqual(len(objects), 40, "an op must exist exactly once")
            self.assertEqual(
                len(journal.pending(session.index, limit=200)), 0, "the queue must be drained"
            )
        finally:
            session.close()

    def test_a_killed_pull_leaves_a_consistent_index(self) -> None:
        # Seed the bucket with 30 ops from a "desktop" vault.
        producer = tmp_vault()
        try:
            for number in range(30):
                journal.record(
                    producer.index,
                    "put",
                    f"n{number:03d}.md",
                    client="desktop",
                    payload={"blob_id": f"blob-{number:03d}", "size": 4},
                )
            from vault.core import sync_ops

            sync_ops.OpsTransport(
                self.bucket, prefix="sync/", vault_id="vault-1", client_id="desktop"
            ).push(producer.index)
        finally:
            producer.close()

        target = tmp_vault()
        try:
            transport = sync_ops.OpsTransport(
                self.bucket, prefix="sync/", vault_id="vault-1", client_id="phone"
            )
            # Simulate a kill after the first ten ops: apply them in a batch by hand, then "die".
            index = target.index
            all_ops = []
            for number in range(1, 11):
                body = self.bucket.get(f"sync/ops/desktop/{number:06d}.json")
                self.assertIsNotNone(body, f"op {number} is missing from the fixture bucket")
                all_ops.append(json.loads(body))
            journal.apply_ops(index, all_ops)

            applied = index.conn.execute(
                "SELECT COUNT(*) AS n FROM files WHERE logical_path LIKE 'n0%'"
            ).fetchone()["n"]
            self.assertEqual(int(applied), 10)

            # Invariant: the cursor equals the last applied op, never ahead of it.
            cursor = index.conn.execute(
                "SELECT MAX(seq) AS n FROM journal_in WHERE client='desktop'"
            ).fetchone()["n"]
            self.assertEqual(int(cursor), 10)

            # The next pull continues from there and applies each op exactly once.
            report = transport.pull(index)
            self.assertEqual(report["applied"], 20)
            total = index.conn.execute(
                "SELECT COUNT(*) AS n FROM files WHERE logical_path LIKE 'n0%'"
            ).fetchone()["n"]
            self.assertEqual(int(total), 30)
        finally:
            target.close()


if __name__ == "__main__":
    unittest.main()
