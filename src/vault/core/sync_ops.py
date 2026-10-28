"""Bucket transport for the operation log (phase 2 of multi-client sync).

Each client publishes its own ops under its own prefix, so two devices never write the same object
and no lock is needed:

```
<prefix>ops/<client>/HEAD            {"client", "seq", "vault_id", "at"}
<prefix>ops/<client>/000042.json     one op, exactly what journal.py produced
```

``push`` publishes unpublished ops and only marks them published after the object was accepted;
``pull`` lists what is there (never trusting HEAD for the set), applies what this client has not seen,
and **stops at a gap**: applying op 43 while 42 is still in flight would be exactly the silent
divergence this design exists to prevent.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from ..errors import SyncError
from ..util import atomic_write_bytes
from . import journal

#: Directory (under the sync prefix) that holds every client's operation stream.
OPS_DIR = "ops"

#: Object name holding a client's published high-water mark.
HEAD_NAME = "HEAD"

#: How many objects one push keeps in flight. A PUT costs about a second on a slow bucket and the
#: ops are independent objects, so a backlog of thousands goes out in minutes, not hours.
PUSH_WORKERS = 8


class OpsTransport:
    """Push/pull one vault's operations through any S3-compatible client."""

    def __init__(
        self,
        client: Any,
        *,
        prefix: str = "",
        vault_id: str = "",
        client_id: str = "",
        blob_path: Callable[[str], Path] | None = None,
        handler: Callable[[dict[str, Any]], str | None] | None = None,
        log: Callable[[str], None] | None = None,
    ) -> None:
        """Bind the transport to an S3 client, the vault's identity and this machine's id.

        ``blob_path`` maps a blob id to its local file; with it the transport also moves content —
        an op names a blob id, and a peer that receives the op needs the bytes to read the file.
        """
        self.client = client
        self.prefix = prefix or ""
        self.vault_id = vault_id or ""
        self.client_id = client_id or ""
        self.blob_path = blob_path
        self.handler = handler
        self._log = log

    # ------------------------------------------------------------------ keys
    def ops_root(self) -> str:
        """Return the bucket prefix that holds every client's ops."""
        return f"{self.prefix}{OPS_DIR}/"

    def client_prefix(self, client: str) -> str:
        """Return one client's prefix."""
        return f"{self.ops_root()}{client}/"

    def head_key(self, client: str) -> str:
        """Return one client's HEAD key."""
        return f"{self.client_prefix(client)}{HEAD_NAME}"

    @staticmethod
    def op_key(client: str, seq: int) -> str:
        """Return the object name of one op (relative to the client's prefix)."""
        return f"{int(seq):06d}.json"

    # ------------------------------------------------------------------ blobs
    def blob_key(self, blob_id: str) -> str:
        """Return the bucket key of one content blob (the same layout the vault folder uses)."""
        return f"{self.prefix}files/{blob_id[:2]}/{blob_id}.enc"

    def _upload_blob(self, blob_id: str, existing: set[str] | None = None) -> bool:
        """Make sure this blob is in the bucket; True when it is (or already was)."""
        if self.blob_path is None or not blob_id:
            return True
        key = self.blob_key(blob_id)
        if existing is not None and key in existing:
            return True
        local = self.blob_path(blob_id)
        if not local.is_file():
            # We do not have the bytes (an op referring to a blob from a peer): it uploads its own.
            return True
        try:
            data = local.read_bytes()
            # if_none_match: a blob is immutable and content-addressed, so "already there" is a win
            # — ``put`` answers False for that (412), and the legacy mirror left every blob behind.
            self.client.put(key, data, if_none_match=True)
            return True
        except TypeError:
            # A backend without the conditional flag: an unconditional put of identical bytes is safe.
            try:
                self.client.put(key, local.read_bytes())
                return True
            except Exception:  # noqa: BLE001
                return False
        except Exception:  # noqa: BLE001
            return False

    def _ensure_blob(self, blob_id: str) -> bool:
        """Fetch a blob the op refers to when it is not on this device yet."""
        if self.blob_path is None or not blob_id:
            return True
        local = self.blob_path(blob_id)
        if local.is_file() and local.stat().st_size > 0:
            return True
        try:
            data = self.client.get(self.blob_key(blob_id))
        except Exception:  # noqa: BLE001
            return False
        if not data:
            self._note(f"ops: blob {blob_id} is missing in the bucket")
            return False
        local.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(local, data)
        return True

    # ------------------------------------------------------------------ push
    def push(self, index: Any, *, max_ops: int | None = None) -> dict[str, Any]:
        """Publish this client's unpublished ops; returns what happened.

        An op is marked published only after its object was written, so a failure mid-way leaves the
        rest to the next run instead of losing them. ``max_ops`` stops after that many, which is how
        a caller keeps a long first push out of its own event loop.
        """
        pushed: list[str] = []
        published = 0
        failed = 0
        # One listing tells us which blobs the bucket already has: probing them one by one costs a
        # slow 412 per op, and the legacy mirror left every blob behind.
        existing = self._bucket_blobs()
        for _round in range(200):  # a backlog is drained in pages, not one run per 200 ops
            ops = journal.pending(index)
            if not ops:
                break
            if max_ops is not None:
                if published >= max_ops:
                    break
                ops = ops[: max(1, max_ops - published)]
            batch = self._publish(ops, existing)
            pushed.extend(batch["pushed"])
            failed = batch["failed"]
            if pushed:
                journal.mark_published(index, pushed)
                published += len(pushed)
                pushed = []
            if failed:
                break
        head = self._head_seq(index)
        self._write_head(head)
        return {"pushed": published, "failed": failed, "head": head}

    def _publish(self, ops: list[dict[str, Any]], existing: set[str]) -> dict[str, Any]:
        """Upload one page of ops (content first), a few at a time.

        A PUT costs about a second on a slow bucket and the ops are independent objects, so the
        page goes out in parallel; ``mark_published`` still happens once, in the caller's thread.
        """
        def one(op: dict[str, Any]) -> str | None:
            payload = dict(op.get("payload") or {})
            # Content first: a peer must never see an op whose blob is not in the bucket yet.
            if str(op.get("kind")) == "put" and payload.get("blob_id"):
                if not self._upload_blob(str(payload["blob_id"]), existing):
                    return None
            client = str(op["client"])
            key = self.client_prefix(client) + self.op_key(client, int(op["seq"]))
            body = dict(op)
            # Tagged with the vault so a bucket shared by two vaults is caught per object.
            body["vault_id"] = self.vault_id
            data = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
            try:
                return str(op["op_id"]) if self.client.put(key, data) else None
            except Exception:  # noqa: BLE001 - a network failure must not lose the journal
                return None

        pushed: list[str] = []
        failed = 0
        with ThreadPoolExecutor(max_workers=PUSH_WORKERS) as pool:
            for op_id in pool.map(one, ops):
                if op_id is None:
                    failed += 1
                else:
                    pushed.append(op_id)
        return {"pushed": pushed, "failed": failed}

    def _bucket_blobs(self) -> set[str]:
        """Every blob key the bucket already holds (empty when the client cannot list)."""
        try:
            entries = self.client.list(f"{self.prefix}files/")
        except Exception:  # noqa: BLE001 - without a listing we simply try every upload
            return set()
        return {str(entry.get("key")) for entry in entries}

    def _head_seq(self, index: Any) -> int:
        """Return the highest sequence number this client has published so far."""
        row = index.conn.execute("SELECT MAX(seq) AS n FROM journal_out WHERE published=1").fetchone()
        return int(row["n"] or 0) if row is not None else 0

    def _write_head(self, seq: int) -> None:
        """Best effort: HEAD is a hint for humans and gap diagnostics, never the source of truth."""
        if not self.client_id:
            return
        payload = json.dumps(
            {
                "client": self.client_id,
                "seq": int(seq),
                "vault_id": self.vault_id,
                "at": journal.now_ms(),
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        try:
            self.client.put(self.head_key(self.client_id), payload)
        except Exception:  # noqa: BLE001 - the ops themselves are already consistent
            self._note("ops: HEAD write failed (ignored)")

    # ------------------------------------------------------------------ pull
    def remote_clients(self) -> list[str]:
        """Return every client id that has a prefix in the bucket (including this one)."""
        keys = self.client.list(self.ops_root())
        found: set[str] = set()
        for entry in keys:
            rest = str(entry.get("key", ""))[len(self.ops_root()) :]
            name, _, _ = rest.partition("/")
            if name:
                found.add(name)
        return sorted(found)

    def pull(self, index: Any, *, max_ops: int | None = None) -> dict[str, Any]:
        """Fetch and apply every op this client has not seen; stops at the first gap per client.

        ``max_ops`` applies at most that many and reports ``more`` so a caller can keep the pull out
        of its event loop: applying is idempotent, so the next call simply continues where the
        cursor is.
        """
        applied = 0
        conflicts = 0
        duplicates = 0
        gaps: list[dict[str, Any]] = []
        more = False
        for client in self.remote_clients():
            if client == self.client_id:
                continue  # our own ops are already applied here
            seen = self._cursor(index, client)
            keys = self._op_keys(client)
            if not keys:
                continue
            available = sorted(int(seq) for seq in keys if int(seq) > seen)
            batch: list[dict[str, Any]] = []
            expected = seen + 1
            for seq in available:
                if max_ops is not None and len(batch) >= max_ops:
                    more = True
                    break
                if seq != expected:
                    gaps.append(
                        {"client": client, "missing": list(range(expected, seq)), "at": seq}
                    )
                    break
                body = self.client.get(self.client_prefix(client) + self.op_key(client, seq))
                if body is None:
                    gaps.append({"client": client, "missing": [seq], "at": seq})
                    break
                try:
                    op = json.loads(body.decode("utf-8"))
                except ValueError:
                    gaps.append({"client": client, "missing": [], "at": seq})
                    break
                payload = dict(op.get("payload") or {})
                if str(op.get("kind")) == "put" and payload.get("blob_id"):
                    if not self._ensure_blob(str(payload["blob_id"])):
                        gaps.append({"client": client, "missing": [], "at": seq, "blob": True})
                        break
                if op.get("vault_id") and str(op["vault_id"]) != self.vault_id:
                    raise SyncError(
                        "vault_id_mismatch",
                        details={"remote": str(op["vault_id"]), "local": self.vault_id},
                    )
                batch.append(op)
                expected += 1
            if batch:
                result = journal.apply_ops(index, batch, handler=self.handler)
                applied += int(result["applied"])
                conflicts += int(result["conflicts"])
                duplicates += int(result["duplicates"])
        return {
            "applied": applied,
            "conflicts": conflicts,
            "duplicates": duplicates,
            "gaps": gaps,
            "more": more,
        }

    def _cursor(self, index: Any, client: str) -> int:
        """Return the last sequence number of ``client`` that was already handled here."""
        row = index.conn.execute(
            "SELECT MAX(seq) AS n FROM journal_in WHERE client=?", (client,)
        ).fetchone()
        return int(row["n"] or 0) if row is not None else 0

    def _op_keys(self, client: str) -> list[str]:
        """Return the sequence numbers present for ``client`` (as strings, zero padded)."""
        prefix = self.client_prefix(client)
        keys: list[str] = []
        for entry in self.client.list(prefix):
            name = str(entry.get("key", ""))[len(prefix) :]
            if name.endswith(".json") and name[:-5].isdigit():
                keys.append(name[:-5])
        return keys

    def _note(self, message: str) -> None:
        """Forward a diagnostic line when a logger was given."""
        if self._log is not None:
            self._log(message)


__all__ = ["HEAD_NAME", "OPS_DIR", "OpsTransport"]
