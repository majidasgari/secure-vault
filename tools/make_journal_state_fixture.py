#!/usr/bin/env python3
"""Scenarios proving the Android index *state machine* matches the desktop, not just the verdicts.

    PYTHONPATH=src ./.venv/bin/python tools/make_journal_state_fixture.py --android <android repo>

Each scenario runs the real desktop engine (`journal.apply_ops` over a real vault) and records the
index before, the operations, the index after, and how many conflicts it produced. The Kotlin port
(`core/JournalIndex.kt`) must reproduce that "after" exactly — rows, blobs, revisions, tags, emoji.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vault.core import journal  # noqa: E402
from vault.core.session import VaultSession  # noqa: E402

PASSWORD = "state-fixture-pass"
COLUMNS = ("logical_path", "blob_id", "is_dir", "size", "encrypted", "sensitivity", "mtime", "emoji", "rev")


def snapshot(index) -> list[dict]:
    """Every row the phone also keeps, ordered so the JSON is stable."""
    rows = index.conn.execute(
        f"SELECT {', '.join(COLUMNS)} FROM files ORDER BY logical_path"
    ).fetchall()
    out = []
    for row in rows:
        entry = {column: row[column] for column in COLUMNS}
        entry["logical_path"] = str(entry["logical_path"])
        entry["tags"] = index.get_tags(str(entry["logical_path"]))
        out.append(entry)
    return out


def op(kind: str, path: str, *, base: int, client: str = "desktop", seq: int, **payload) -> dict:
    """One operation exactly as it travels."""
    return {
        "op_id": f"{client}-{seq:06d}",
        "client": client,
        "seq": seq,
        "ts": 1000 + seq,
        "kind": kind,
        "path": path,
        "base_rev": base,
        "rev": base + 1,
        "payload": payload,
    }


def scenario(session, name: str, rows: list[dict], ops: list[dict]) -> dict:
    """Prepare ``rows``, apply ``ops``, and record both snapshots."""
    index = session.index
    for table in ("files", "file_tags", "tags", "tombstones", "journal_in", "conflicts"):
        index.conn.execute(f"DELETE FROM {table}")
    index.conn.commit()
    for row in rows:
        index.upsert_file(
            row["logical_path"],
            blob_id=row.get("blob_id"),
            is_dir=bool(row.get("is_dir", False)),
            size=int(row.get("size", 0)),
            encrypted=int(row.get("encrypted", 1)),
            sensitivity=row.get("sensitivity", "normal"),
            mtime=int(row.get("mtime", 1)),
        )
        index.conn.execute(
            "UPDATE files SET rev=? WHERE logical_path=?", (int(row.get("rev", 0)), row["logical_path"])
        )
        if row.get("emoji"):
            index.set_emoji(row["logical_path"], row["emoji"])
        if row.get("tags"):
            index.set_tags(row["logical_path"], row["tags"])
    index.conn.commit()
    before = snapshot(index)
    report = journal.apply_ops(index, ops, handler=session.apply_journal_op)
    index.conn.commit()
    return {
        "name": name,
        "before": before,
        "ops": ops,
        "after": snapshot(index),
        "conflicts": int(report["conflicts"]),
        "applied": int(report["applied"]),
    }


def scenarios(session) -> list[dict]:
    """The five shapes a phone must reproduce: create, edit, conflict, tombstone, rename, metadata."""
    blob = lambda name: {"blob_id": name, "size": 4, "encrypted": 1}  # noqa: E731
    return [
        scenario(
            session,
            "create_then_edit",
            [],
            [
                op("put", "a.md", base=0, seq=1, **blob("blob-1")),
                op("put", "a.md", base=1, seq=2, **blob("blob-2")),
            ],
        ),
        scenario(
            session,
            "conflict_keeps_the_local_row",
            [{"logical_path": "a.md", "blob_id": "blob-local", "size": 4, "rev": 2}],
            [op("put", "a.md", base=1, seq=3, **blob("blob-theirs"))],
        ),
        scenario(
            session,
            "delete_then_resurrect",
            [{"logical_path": "a.md", "blob_id": "blob-1", "size": 4, "rev": 2}],
            [
                op("delete", "a.md", base=2, seq=4),
                op("put", "a.md", base=1, seq=5, **blob("blob-zombie")),
            ],
        ),
        scenario(
            session,
            "rename_moves_the_row",
            [{"logical_path": "a.md", "blob_id": "blob-1", "size": 4, "rev": 1}],
            [op("rename", "b.md", base=1, seq=6, **{"from": "a.md"})],
        ),
        scenario(
            session,
            "tags_and_emoji_bump_the_revision",
            [{"logical_path": "a.md", "blob_id": "blob-1", "size": 4, "rev": 1}],
            [
                op("tag", "a.md", base=1, seq=7, tags=["کار", "مالی"]),
                op("emoji", "a.md", base=2, seq=8, emoji="📌"),
            ],
        ),
        scenario(
            session,
            "delete_is_a_noop_when_already_gone",
            [],
            [op("delete", "ghost.md", base=0, seq=9)],
        ),
    ]


def main(argv: list[str] | None = None) -> int:
    """Write the state fixture (and copy it into the Android tests)."""
    parser = argparse.ArgumentParser(description="Generate journal state scenarios.")
    parser.add_argument("--android", help="Android repo to copy the fixture into")
    args = parser.parse_args(argv)

    home = Path(tempfile.mkdtemp(prefix="state-fixture-"))
    session = VaultSession.create(home, PASSWORD)
    session.close()
    session = VaultSession(home)
    session.unlock(PASSWORD)
    try:
        cases = scenarios(session)
    finally:
        session.close()

    text = json.dumps(
        {"generated_by": "secure-vault/tools/make_journal_state_fixture.py", "scenarios": cases},
        ensure_ascii=False,
        indent=2,
    ) + "\n"
    local = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "journal_state_vectors.json"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(text, encoding="utf-8")
    print(f"wrote {len(cases)} scenarios → {local}")
    if args.android:
        target = Path(args.android) / "app/src/test/resources/fixture/journal_state_vectors.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        print(f"copied → {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
