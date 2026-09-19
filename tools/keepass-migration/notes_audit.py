#!/usr/bin/env python3
"""Audit every current file under a vault subtree: sensitivity + note presence.

Usage:
    ./.venv/bin/python tools/keepass-migration/notes_audit.py [--root /رمزها] [--expect secretfile]

Walks the live vault (no extracted plaintext needed) and reports:
  * how many files/folders exist,
  * any file whose sensitivity differs from `--expect` (empty = do not care),
  * any file without a note,
  * any folder without a folder note.
Prints the offending paths so they can be fixed one by one.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from vault.api.client import RefreshingClient  # noqa: E402
from vault.errors import VaultError  # noqa: E402


def main() -> int:
    """Walk the subtree and report missing notes / unexpected levels."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default="/رمزها")
    ap.add_argument("--expect", default="secretfile",
                    help="expected sensitivity for files ('' to skip the check)")
    ap.add_argument("--allow", action="append", default=[],
                    help="path (or prefix) legitimately exempt from the checks; repeatable")
    args = ap.parse_args()

    def allowed(path: str) -> bool:
        """True when the path is an intentional exception (e.g. the human-readable guide)."""
        return any(path == a or path.startswith(a.rstrip("/") + "/") for a in args.allow)

    client = RefreshingClient()
    stack = [args.root]
    files = folders = 0
    no_note: list[str] = []
    no_folder_note: list[str] = []
    wrong_level: list[str] = []
    skipped_dirs: list[str] = []

    while stack:
        path = stack.pop()
        try:
            listing = client.call("vault.list_folder", {"path": path})
        except VaultError as exc:
            skipped_dirs.append(f"{path}: {exc}")
            continue
        if path != args.root and not allowed(path) and not (listing.get("note") or "").strip():
            no_folder_note.append(path)
        for entry in listing.get("entries") or []:
            if entry.get("is_dir"):
                folders += 1
                stack.append(entry["path"])
                continue
            files += 1
            if allowed(entry["path"]):
                continue
            if args.expect and entry.get("sensitivity") != args.expect:
                wrong_level.append(f"{entry['path']} ({entry.get('sensitivity')})")
            try:
                note = client.call("vault.file_note", {"path": entry["path"]}).get("note")
            except VaultError as exc:
                no_note.append(f"{entry['path']} (error: {exc})")
                continue
            if not (note or "").strip():
                no_note.append(entry["path"])

    print(f"root={args.root} files={files} folders={folders}")
    print(f"wrong_level={len(wrong_level)} no_note={len(no_note)} "
          f"no_folder_note={len(no_folder_note)} unreadable_folders={len(skipped_dirs)}")
    for label, rows in (("LEVEL", wrong_level), ("NOTE", no_note),
                        ("FOLDER-NOTE", no_folder_note), ("FOLDER-ERR", skipped_dirs)):
        for row in rows[:50]:
            print(f"  {label}: {row}")
    ok = not (wrong_level or no_note or no_folder_note or skipped_dirs)
    print("AUDIT OK" if ok else "AUDIT FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
