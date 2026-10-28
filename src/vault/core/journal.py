"""Per-client operation log: the layer that lets several clients write at once (SPEC/01 §10).

The vault's index is one SQLite file, so two clients cannot append to it: that is why the old
synchroniser needed a single-writer lock. This module replaces the lock with an append-only log —
each client only ever writes ops under its own id, and every client applies everyone else's ops
through :func:`apply_ops`, which is where conflicts are detected and stored for the user to answer.

Three rules make it safe:

* an op is applied **at most once** (``journal_in`` is the dedupe ledger),
* an op is applied only when it was written on top of the revision that is still current — anything
  else becomes a row in ``conflicts``, never a silent overwrite,
* the order ops are applied in is ``(client, seq)``, never a wall clock, so two devices applying the
  same set reach the same state.

Metadata ops (tags, emoji, level, note, learning) are last-writer-wins in that same deterministic
order and are *reported* as merged; content and existence (put/delete/rename) are the kinds that ask.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Iterable

from ..config import user_data_dir
from ..util import normalize_logical_path, now_ms

#: Op kinds that change content or existence — these ask the user when they collide.
CONFLICTING_KINDS = frozenset({"put", "delete", "rename"})

#: Every kind this version can write and apply.
OP_KINDS = CONFLICTING_KINDS | {"tag", "emoji", "level", "note", "learning"}

#: Suffix used by the "keep both" answer, in the vault's own language.
COPY_SUFFIX = "نسخهٔ ۲"

#: Sub-directory of the machine-local data dir that holds each vault's client id.
_CLIENT_DIR = "clients"


# --------------------------------------------------------------------------- identity
def client_id(vault_id: str, *, base: Path | None = None) -> str:
    """Return **this machine's** client id for ``vault_id``, creating it once.

    Machine-local on purpose, never in ``meta.sqlite``: a client id is the identity of a device, and
    a copied vault (or a synced one) must not make two machines claim the same operation stream.
    """
    directory = Path(base) if base is not None else user_data_dir() / _CLIENT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{vault_id or 'vault'}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        existing = str(data.get("client_id") or "")
        if existing:
            return existing
    except (OSError, ValueError):
        pass
    fresh = uuid.uuid4().hex[:12]
    payload = json.dumps(
        {"client_id": fresh, "created": now_ms(), "vault_id": vault_id}, ensure_ascii=False
    ).encode("utf-8")
    path.write_bytes(payload)
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - best effort on exotic filesystems
        pass
    return fresh


# --------------------------------------------------------------------------- build
def build_op(
    index: Any,
    kind: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    base_rev: int | None = None,
    resolution_of: str | None = None,
    client: str = "",
    seq: int | None = None,
    op_id: str | None = None,
) -> dict[str, Any]:
    """Build (but do not store) one op for ``path``.

    ``base_rev`` defaults to the path's current revision, which is what a mutation made right now is
    based on; a caller that edits from a snapshot must pass the revision it read. ``client`` is this
    machine's id (:func:`client_id`). The sequence number and the op id are filled in by
    :func:`append_op` — building twice must not claim the same id.
    """
    if kind not in OP_KINDS:
        raise ValueError(f"unknown op kind: {kind}")
    if not client:
        raise ValueError("client id is required for an operation")
    logical = normalize_logical_path(path)
    current = current_rev(index, logical)
    op: dict[str, Any] = {
        "op_id": op_id,
        "client": client,
        "seq": seq,
        "ts": now_ms(),
        "kind": kind,
        "path": logical,
        "base_rev": current if base_rev is None else int(base_rev),
        "rev": current + 1,
        "payload": dict(payload or {}),
    }
    if resolution_of:
        op["resolution_of"] = resolution_of
    return op


def append_op(index: Any, op: dict[str, Any]) -> dict[str, Any]:
    """Store ``op`` in the outgoing journal (unpublished) and return it with its ids filled in."""
    if not op.get("client"):
        raise ValueError("client id is required for an operation")
    if op.get("seq") is None:
        op["seq"] = _next_seq(index)
    if not op.get("op_id"):
        op["op_id"] = f"{op['client']}-{int(op['seq']):06d}"
    if not op.get("ts"):
        op["ts"] = now_ms()
    index.conn.execute(
        "INSERT INTO journal_out(op_id, created, json, published) VALUES(?,?,?,0)",
        (op["op_id"], int(op["ts"]), json.dumps(op, ensure_ascii=False, sort_keys=True)),
    )
    index.conn.commit()
    return op


def record(index: Any, kind: str, path: str, *, client: str, **kwargs: Any) -> dict[str, Any]:
    """Build and store one outgoing op in a single call."""
    return append_op(index, build_op(index, kind, path, client=client, **kwargs))


def pending(index: Any, limit: int = 200) -> list[dict[str, Any]]:
    """Return this client's unpublished ops, oldest first."""
    rows = index.conn.execute(
        "SELECT json FROM journal_out WHERE published=0 ORDER BY seq LIMIT ?", (int(limit),)
    ).fetchall()
    return [json.loads(str(row["json"])) for row in rows]


def mark_published(index: Any, op_ids: Iterable[str]) -> int:
    """Mark ops as uploaded; returns how many rows changed."""
    ids = [str(op_id) for op_id in op_ids]
    if not ids:
        return 0
    marks = ",".join("?" for _ in ids)
    cur = index.conn.execute(f"UPDATE journal_out SET published=1 WHERE op_id IN ({marks})", ids)
    index.conn.commit()
    return int(cur.rowcount or 0)


# --------------------------------------------------------------------------- read
def current_rev(index: Any, path: str) -> int:
    """Return the current revision of ``path`` (0 when it does not exist)."""
    row = index.conn.execute(
        "SELECT rev FROM files WHERE logical_path=? COLLATE NOCASE",
        (normalize_logical_path(path),),
    ).fetchone()
    return int(row["rev"]) if row is not None and row["rev"] is not None else 0


def already_applied(index: Any, op_id: str) -> bool:
    """True when this op id is in the ledger, whatever its outcome was."""
    row = index.conn.execute("SELECT 1 FROM journal_in WHERE op_id=?", (op_id,)).fetchone()
    return row is not None


# --------------------------------------------------------------------------- apply
def apply_ops(
    index: Any,
    ops: Iterable[dict[str, Any]],
    *,
    handler: Any = None,
) -> dict[str, Any]:
    """Apply a batch of remote ops and return what happened.

    Ops are processed in ``(client, seq)`` order — deterministic on every device — and each one is
    applied at most once. A conflicting op is never applied: it becomes a row the user answers.

    ``handler(op)`` is consulted first and may return ``"applied"``/``"conflict"`` for the kinds the
    index alone cannot apply (``note``, ``learning`` — they live in the encrypted content store).
    """
    ordered = sorted(
        (op for op in ops if isinstance(op, dict) and op.get("op_id")),
        key=lambda op: (str(op.get("client", "")), int(op.get("seq", 0))),
    )
    applied = 0
    duplicates = 0
    conflicts = 0
    invalid = 0
    for op in ordered:
        if already_applied(index, str(op["op_id"])):
            duplicates += 1
            continue
        try:
            outcome = _apply_one(index, op, handler)
        except Exception:  # noqa: BLE001 - one malformed op must not stop the batch
            invalid += 1
            _ledger(index, op, applied=False)
            continue
        if outcome == "conflict":
            conflicts += 1
            _ledger(index, op, applied=False)
        else:
            applied += 1
            _ledger(index, op, applied=True)
    index.conn.commit()
    return {
        "applied": applied,
        "conflicts": conflicts,
        "duplicates": duplicates,
        "invalid": invalid,
    }


def _ledger(index: Any, op: dict[str, Any], *, applied: bool) -> None:
    """Record an op as seen (the dedupe ledger), applied or not."""
    index.conn.execute(
        "INSERT OR IGNORE INTO journal_in(op_id, client, seq, ts, applied, at) VALUES(?,?,?,?,?,?)",
        (
            str(op["op_id"]),
            str(op.get("client", "")),
            int(op.get("seq", 0)),
            int(op.get("ts", 0)),
            1 if applied else 0,
            now_ms(),
        ),
    )


def _apply_one(index: Any, op: dict[str, Any], handler: Any = None) -> str:
    """Apply one op; return ``"applied"`` or ``"conflict"``."""
    kind = str(op.get("kind", ""))
    if kind not in OP_KINDS:
        raise ValueError(f"unknown op kind: {kind}")
    if handler is not None:
        outcome = handler(op)
        if outcome in ("applied", "conflict"):
            return str(outcome)
    path = normalize_logical_path(str(op.get("path", "")))
    base = int(op.get("base_rev", 0))
    current = current_rev(index, path)
    resolution = bool(op.get("resolution_of"))

    if kind == "rename":
        source = normalize_logical_path(str(op.get("payload", {}).get("from", "")))
        return _apply_rename(index, op, source, path, base, resolution)
    if kind == "put":
        if not resolution:
            if current != 0 and base != current:
                return conflict_record(index, op, current)
            if current == 0:
                # A create on top of a delete we already applied is the delete-vs-edit question.
                tomb = _tombstone(index, path)
                if tomb is not None and int(tomb) > base:
                    return conflict_record(index, op, int(tomb))
        return _apply_put(index, op, path)

    if kind in ("tag", "emoji", "level", "note", "learning"):
        # Metadata: deterministic last-writer-wins in the caller's canonical order, reported not asked.
        return _apply_metadata(index, op, path)

    # delete
    if current == 0:
        return "applied"  # already gone (or never existed here)
    if not resolution and base != current:
        return conflict_record(index, op, current)
    row = index.get_file(path)
    if row is not None and int(row.get("is_dir", 0)):
        index.delete_file(path, recursive=True)
    else:
        index.delete_file(path)
    # The tombstone carries the *revision* the deletion produced: a create based on an older
    # revision is the delete-vs-edit question, one based on this revision or later is causally after.
    _mark_deleted(index, path, str(op.get("client", "")), rev=int(op.get("rev", current + 1)))
    return "applied"


def _apply_put(index: Any, op: dict[str, Any], path: str) -> str:
    """Create or replace a file row from a ``put`` op."""
    payload = dict(op.get("payload") or {})
    blob_id = payload.get("blob_id")
    index.upsert_file(
        path,
        blob_id=None if blob_id is None else str(blob_id),
        is_dir=bool(payload.get("is_dir", False)),
        size=int(payload.get("size", 0)),
        encrypted=int(payload.get("encrypted", 1)),
        sensitivity=str(payload.get("sensitivity", "normal")),
        mtime=int(payload.get("mtime", 0)) or None,
        source=str(op.get("client", "sync")),
    )
    _bump(index, path, str(op.get("client", "")))
    return "applied"


def _apply_rename(
    index: Any, op: dict[str, Any], source: str, target: str, base: int, resolution: bool
) -> str:
    """Move ``source`` to ``target``; a taken target is a conflict, never an overwrite."""
    if not source:
        raise ValueError("rename without payload.from")
    source_row = index.get_file(source)
    if source_row is None:
        return "applied"  # the source is gone everywhere; nothing to move
    if int(source_row.get("rev") or 0) != base and not resolution:
        return conflict_record(index, op, int(source_row.get("rev") or 0))
    if index.get_file(target) is not None:
        return conflict_record(index, op, current_rev(index, target))
    index.move(source, target)
    _bump(index, target, str(op.get("client", "")))
    return "applied"


def _apply_metadata(index: Any, op: dict[str, Any], path: str) -> str:
    """Apply a metadata op (tags/emoji/level/note/learning) to an existing row."""
    row = index.get_file(path)
    if row is None:
        return "applied"  # nothing to change; the op is not a resurrection
    kind = str(op["kind"])
    payload = dict(op.get("payload") or {})
    if kind == "level":
        index.set_sensitivity(path, str(payload.get("sensitivity", "normal")))
    elif kind == "emoji":
        index.set_emoji(path, payload.get("emoji"))
    elif kind == "tag":
        index.set_tags(path, [str(tag) for tag in payload.get("tags", [])])
    # ``note`` and ``learning`` are applied by the layer that owns those stores (phase 3).
    _bump(index, path, str(op.get("client", "")))
    return "applied"


def _bump(index: Any, path: str, writer: str) -> None:
    """Advance a path's revision past the op that just landed on it."""
    index.conn.execute(
        "UPDATE files SET rev=COALESCE(rev,0)+1, last_writer=? "
        "WHERE logical_path=? COLLATE NOCASE",
        (writer, normalize_logical_path(path)),
    )


def conflict_record(index: Any, op: dict[str, Any], current: int) -> str:
    """Store a conflict row for the user and leave the index untouched."""
    index.conn.execute(
        "INSERT INTO conflicts(path, kind, mine, theirs, their_client, my_rev, their_rev, "
        "created, resolved, their_json) VALUES(?,?,?,?,?,?,?,?,0,?)",
        (
            normalize_logical_path(str(op.get("path", ""))),
            str(op.get("kind", "")),
            None,
            str(op["op_id"]),
            str(op.get("client", "")),
            current,
            int(op.get("rev", 0)),
            now_ms(),
            json.dumps(op, ensure_ascii=False, sort_keys=True),
        ),
    )
    return "conflict"


def _tombstone(index: Any, path: str) -> int | None:
    """Return the revision at which ``path`` was deleted here (None when it never was)."""
    row = index.conn.execute(
        "SELECT rev FROM tombstones WHERE path=? COLLATE NOCASE", (normalize_logical_path(path),)
    ).fetchone()
    return int(row["rev"]) if row is not None else None


def _mark_deleted(index: Any, path: str, writer: str, *, rev: int) -> None:
    """Remember a deletion so a later offline create cannot resurrect it silently."""
    logical = normalize_logical_path(path)
    index.conn.execute(
        "INSERT INTO tombstones(path, rev, writer, at) VALUES(?,?,?,?) "
        "ON CONFLICT(path) DO UPDATE SET rev=excluded.rev, writer=excluded.writer, at=excluded.at",
        (logical, int(rev), writer, now_ms()),
    )


def _next_seq(index: Any) -> int:
    """Return the next sequence number for this client's outgoing journal."""
    row = index.conn.execute("SELECT COALESCE(MAX(seq),0)+1 AS n FROM journal_out").fetchone()
    return int(row["n"]) if row is not None else 1


# --------------------------------------------------------------------------- conflicts
def unresolved(index: Any) -> list[dict[str, Any]]:
    """Return every conflict still waiting for an answer, oldest first."""
    rows = index.conn.execute(
        "SELECT id, path, kind, their_client, my_rev, their_rev, created "
        "FROM conflicts WHERE resolved=0 ORDER BY id"
    ).fetchall()
    return [dict(row) for row in rows]


def resolve(
    index: Any,
    conflict_id: int,
    choice: str,
    *,
    client: str,
    handler: Any = None,
    answer_builder: Any = None,
) -> dict[str, Any]:
    """Answer one conflict: ``mine``, ``theirs`` or ``both``.

    The answer is written as an outgoing op (``put``/``delete`` with ``resolution_of``), so the other
    device learns the decision without a second protocol. ``client`` is this machine's id.
    """
    if not client:
        raise ValueError("client id is required to answer a conflict")
    if choice not in ("mine", "theirs", "both"):
        raise ValueError(f"unknown conflict choice: {choice}")
    row = index.conn.execute("SELECT * FROM conflicts WHERE id=?", (int(conflict_id),)).fetchone()
    if row is None:
        raise KeyError(f"no conflict {conflict_id}")
    if int(row["resolved"]):
        raise ValueError("conflict already answered")
    theirs = json.loads(str(row["their_json"]))
    path = normalize_logical_path(str(row["path"]))
    mine = index.get_file(path)

    if answer_builder is not None and str(theirs.get("kind")) in ("note", "learning"):
        # Kinds owned by the session (sealed text): it applies the answer and records the op.
        answer = answer_builder(theirs, choice)
        index.conn.execute("UPDATE conflicts SET resolved=1 WHERE id=?", (int(conflict_id),))
        index.conn.commit()
        return answer

    if choice == "theirs":
        _apply_one(index, dict(theirs, resolution_of=str(theirs["op_id"])), handler)
        answer = record(
            index,
            "put" if theirs["kind"] != "delete" else "delete",
            path,
            client=client,
            payload=dict(theirs.get("payload") or {}),
            base_rev=current_rev(index, path),
            resolution_of=str(theirs["op_id"]),
        )
    elif choice == "both":
        # The local version keeps the path; the other one lands beside it.
        if mine is not None and theirs["kind"] == "put":
            copy = _free_copy_path(index, path)
            payload = dict(theirs.get("payload") or {})
            index.upsert_file(
                copy,
                blob_id=payload.get("blob_id"),
                is_dir=False,
                size=int(payload.get("size", 0)),
                encrypted=int(payload.get("encrypted", 1)),
                sensitivity=str(payload.get("sensitivity", "normal")),
                mtime=int(payload.get("mtime", 0)) or None,
                source=str(theirs.get("client", "sync")),
            )
            answer = record(
                index,
                "put",
                copy,
                client=client,
                payload=payload,
                base_rev=current_rev(index, copy),
                resolution_of=str(theirs["op_id"]),
            )
        else:
            answer = record(
                index,
                "delete" if theirs["kind"] == "delete" else "put",
                path,
                client=client,
                payload=dict(theirs.get("payload") or {}),
                base_rev=current_rev(index, path),
                resolution_of=str(theirs["op_id"]),
            )
    else:  # mine
        payload = {} if mine is None else {
            "blob_id": mine.get("blob_id"),
            "size": int(mine.get("size") or 0),
            "encrypted": int(mine.get("encrypted") or 1),
            "sensitivity": str(mine.get("sensitivity") or "normal"),
            "mtime": int(mine.get("mtime") or 0),
        }
        answer = record(
            index,
            "delete" if mine is None else "put",
            path,
            client=client,
            payload=payload,
            base_rev=current_rev(index, path),
            resolution_of=str(theirs["op_id"]),
        )

    index.conn.execute("UPDATE conflicts SET resolved=1 WHERE id=?", (int(conflict_id),))
    index.conn.commit()
    return answer


def _free_copy_path(index: Any, path: str) -> str:
    """Return ``<name> (نسخهٔ ۲).md`` (or the next free number) beside ``path``."""
    logical = normalize_logical_path(path)
    parent, _, name = logical.rpartition("/")
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    for number in range(2, 20):
        suffix = COPY_SUFFIX if number == 2 else f"نسخهٔ {number}"
        candidate = f"{stem} ({suffix}){'.' + ext if ext else ''}"
        full = f"{parent}/{candidate}" if parent else candidate
        if index.get_file(full) is None:
            return normalize_logical_path(full)
    raise ValueError("could not find a free copy name")


__all__ = [
    "COPY_SUFFIX",
    "CONFLICTING_KINDS",
    "OP_KINDS",
    "already_applied",
    "append_op",
    "apply_ops",
    "build_op",
    "client_id",
    "conflict_record",
    "current_rev",
    "mark_published",
    "pending",
    "record",
    "resolve",
    "unresolved",
]
