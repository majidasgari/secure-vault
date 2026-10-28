#!/usr/bin/env python3
"""Generate the conflict-decision vectors the Android journal is tested against.

    PYTHONPATH=src ./.venv/bin/python tools/make_journal_fixture.py

Writes ``<repo>/tests/fixtures/journal_vectors.json`` and — with ``--android <repo>`` — copies it into
the Android client's test resources. Each case is produced by running the *desktop* engine over a real
vault in a prepared state, so the Kotlin rules are checked against the original, not against a second
hand-written table.
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

PASSWORD = "journal-fixture-pass"


CASES = [
    # name, kind, current_rev, tombstone_rev, target_exists, source_exists, source_rev, base_rev, resolution
    ("put_on_current", "put", 3, 0, False, True, 0, 3, False),
    ("put_on_stale", "put", 4, 0, False, True, 0, 3, False),
    ("put_new_file", "put", 0, 0, False, False, 0, 0, False),
    ("put_after_our_delete", "put", 0, 5, False, False, 0, 3, False),
    ("put_after_older_delete", "put", 0, 2, False, False, 0, 4, False),
    ("put_resolution", "put", 9, 0, False, True, 0, 3, True),
    ("delete_on_current", "delete", 2, 0, False, True, 0, 2, False),
    ("delete_on_stale", "delete", 5, 0, False, True, 0, 2, False),
    ("delete_missing", "delete", 0, 0, False, False, 0, 0, False),
    ("rename_free_target", "rename", 0, 0, False, True, 4, 4, False),
    ("rename_taken_target", "rename", 0, 0, True, True, 4, 4, False),
    ("rename_stale_source", "rename", 0, 0, False, True, 6, 4, False),
    ("rename_missing_source", "rename", 0, 0, False, False, 0, 4, False),
    ("note_on_current", "note", 1, 0, False, True, 0, 1, False),
    ("note_on_stale", "note", 3, 0, False, True, 0, 1, False),
    ("tag_always_applies", "tag", 7, 0, False, True, 0, 1, False),
    ("emoji_always_applies", "emoji", 2, 0, False, True, 0, 0, False),
    ("learning_always_applies", "learning", 5, 0, False, True, 0, 1, False),
]


def _prepare(session: VaultSession, name: str, case: tuple) -> None:
    """Put the vault in the state the case describes."""
    _, _, current_rev, tombstone_rev, target_exists, source_exists, source_rev, _, _ = case
    index = session.index
    index.conn.execute("DELETE FROM files")
    index.conn.execute("DELETE FROM tombstones")
    index.conn.execute("DELETE FROM conflicts")
    index.conn.execute("DELETE FROM journal_in")
    index.conn.commit()
    if current_rev or source_exists or target_exists:
        index.upsert_file("note.md", blob_id="blob-one", size=4)
        index.conn.execute("UPDATE files SET rev=? WHERE logical_path='note.md'", (current_rev,))
    if not source_exists and current_rev:
        index.conn.execute("DELETE FROM files WHERE logical_path='note.md'")
    if source_exists and source_rev:
        index.conn.execute("UPDATE files SET rev=? WHERE logical_path='note.md'", (source_rev,))
    if target_exists:
        index.upsert_file("target.md", blob_id="blob-two", size=4)
    if tombstone_rev:
        index.conn.execute(
            "INSERT INTO tombstones(path, rev, writer, at) VALUES('note.md', ?, 'desktop', 1)",
            (tombstone_rev,),
        )
    index.conn.commit()


def _op_for(name: str, case: tuple) -> dict:
    """Build the operation the case is about."""
    _, kind, _, _, _, _, _, base_rev, resolution = case
    payload = {}
    if kind == "put":
        payload = {"blob_id": "blob-incoming", "size": 6, "encrypted": 1, "sensitivity": "normal"}
    elif kind == "rename":
        payload = {"from": "note.md"}
    elif kind == "tag":
        payload = {"tags": ["کار"]}
    elif kind == "emoji":
        payload = {"emoji": "📌"}
    elif kind == "learning":
        payload = {"stage": 2, "due": 5, "started": 1, "seen": 4}
    # note payloads are sealed by the caller (it has the vault key)
    op = {
        "op_id": f"desktop-{abs(hash(name)) % 100000:05d}",
        "client": "desktop",
        "seq": 7,
        "ts": 1,
        "kind": kind,
        "path": "target.md" if kind == "rename" else "note.md",
        "base_rev": base_rev,
        "rev": base_rev + 1,
        "payload": payload,
    }
    if resolution:
        op["resolution_of"] = "desktop-000001"
    return op


def main(argv: list[str] | None = None) -> int:
    """Write the fixture and print where it went."""
    parser = argparse.ArgumentParser(description="Generate journal decision vectors.")
    parser.add_argument("--android", help="Android repo to copy the fixture into")
    args = parser.parse_args(argv)

    home = Path(tempfile.mkdtemp(prefix="journal-fixture-"))
    session = VaultSession.create(home, PASSWORD)
    session.close()
    session = VaultSession(home)
    session.unlock(PASSWORD)

    vectors = []
    try:
        for name, *case in CASES:
            case = tuple(case)
            _prepare(session, name, (name, *case))
            op = _op_for(name, (name, *case))
            if op["kind"] == "note":
                op["payload"] = {"scope": "file", **session._seal_note("fixture note text")}
            report = journal.apply_ops(
                session.index, [op], handler=session.apply_journal_op
            )
            # Only two outcomes matter to the phone: it must ask, or it must apply. "Already gone"
            # and "applied" are the same answer from its point of view.
            outcome = "conflict" if report["conflicts"] else "apply"
            vectors.append(
                {
                    "name": name,
                    "op": op,
                    "state": {
                        "current_rev": int(case[1]),
                        "tombstone_rev": int(case[2]),
                        "target_exists": bool(case[3]),
                        "source_exists": bool(case[4]),
                        "source_rev": int(case[5]),
                    },
                    "expected": outcome,
                }
            )
    finally:
        session.close()

    payload = {"generated_by": "secure-vault/tools/make_journal_fixture.py", "cases": vectors}
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    local = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "journal_vectors.json"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(text, encoding="utf-8")
    print(f"wrote {len(vectors)} cases → {local}")
    if args.android:
        target = Path(args.android) / "app/src/test/resources/fixture/journal_vectors.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        print(f"copied → {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
