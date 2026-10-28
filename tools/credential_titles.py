#!/usr/bin/env python3
"""Write each credential entry's username into its title (one-off maintenance tool).

    read -r -s -p "master password: " SV_PW; echo
    SV_PW="$SV_PW" PYTHONPATH=src ./.venv/bin/python tools/credential_titles.py --home /data/Vault --dry-run
    SV_PW="$SV_PW" PYTHONPATH=src ./.venv/bin/python tools/credential_titles.py --home /data/Vault --sync

Only the first ``# heading`` of an entry changes (``# گیت‌هاب`` → ``# گیت‌هاب — max``); every other
byte of the body stays as it is. Entries whose title already carries the username, whose username is
empty/placeholder, and bodies without a heading are left alone, so a second run changes nothing.

The password is needed because a title lives *inside* the encrypted body — this tool reads and
writes through the vault, never around it, and prints counts plus (on ``--dry-run``) paths, never a
field value. ``--sync`` runs the multi-device sync afterwards, so the desktop app must be closed
while it runs: one writer at a time.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vault.config import runtime_dir  # noqa: E402
from vault.core import credentials  # noqa: E402
from vault.core.security import SECRET_LEVELS, SOURCE_IMPORTER  # noqa: E402
from vault.core.session import VaultSession  # noqa: E402

#: The credential treasure; ``--root /`` widens the walk to every secret file in the vault.
ROOT = "/" + credentials.CREDENTIAL_ROOT.strip("/")

#: What separates the old title from the username.
SEPARATOR = " — "

#: The duplicate counter the browser save path adds (``site.com (2).md``).
COUNTER = re.compile(r"\s*\(\d+\)$")


def app_is_running() -> bool:
    """True while the desktop app holds its single-instance lock (two writers would collide)."""
    try:
        handle = open(runtime_dir() / "gui.lock", "a+")
    except OSError:
        return False
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    finally:
        handle.close()
    return False


def retitle(text: str, username: str) -> str | None:
    """Return ``text`` with the username added to its first heading, or None to leave it alone."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            return None  # no heading: not a body whose title we can safely address
        title = stripped.lstrip("#").strip()
        if not title or username in title:
            return None  # nothing to add, or already there
        lines[index] = f"# {title}{SEPARATOR}{username}"
        return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    return None


def renamed_path(path: str, username: str) -> str | None:
    """Return ``path`` with the username in its file name, or None to leave the name alone."""
    parent, _, name = str(path).rpartition("/")
    stem, dot, ext = name.rpartition(".")
    if not stem:  # no extension at all
        stem, dot, ext = name, "", ""
    if username in stem:
        return None  # already named after the account
    # ``site.com (2)`` only says "a duplicate": with the account in the name the counter says nothing.
    base = COUNTER.sub("", stem).strip() or stem
    return f"{parent}/{base}{SEPARATOR}{username}{dot}{ext}"


def _retitle_vault(
    session: VaultSession, root: str, *, dry_run: bool, rename: bool = False
) -> dict[str, int]:
    """Walk ``root`` and put every entry's username into its title (and, with ``rename``, its name)."""
    counts = {
        "scanned": 0, "retitled": 0, "renamed": 0, "unchanged": 0,
        "no_username": 0, "unreadable": 0, "name_taken": 0,
    }
    # ``index.walk`` speaks the stored form: no leading slash, and "/" for the whole vault.
    for row in session.index.walk(root.strip("/") or "/"):
        if int(row.get("is_dir") or 0) or str(row.get("sensitivity")) not in SECRET_LEVELS:
            continue
        path = str(row["logical_path"])
        counts["scanned"] += 1
        try:
            text = session.read_file(path, source=SOURCE_IMPORTER).decode("utf-8")
        except Exception:  # noqa: BLE001 - one odd entry (or binary) must not stop the run
            counts["unreadable"] += 1
            continue
        fields = credentials.parse_body(text, fallback_title=Path(path).stem)
        username = str(fields.get("username") or "").strip()
        if not username or username in credentials.EMPTY_MARKERS or not credentials.storable(username):
            counts["no_username"] += 1
            continue
        new_text = retitle(text, username)
        if new_text is None:
            counts["unchanged"] += 1
        else:
            counts["retitled"] += 1
            if dry_run:
                print(f"would retitle: {path}")
            else:
                session.write_file(path, new_text.encode("utf-8"), source=SOURCE_IMPORTER)
        if not rename:
            continue
        target = renamed_path(path, username)
        if target is None:
            continue
        if dry_run:
            print(f"would rename: {path} -> {target}")
            counts["renamed"] += 1
            continue
        try:
            session.move(path, target, source=SOURCE_IMPORTER)
        except Exception:  # noqa: BLE001 - a name already taken (or a bad name) is skipped
            counts["name_taken"] += 1
            continue
        counts["renamed"] += 1
    return counts


def _sync(session: VaultSession) -> None:
    """Publish the new titles (journal mode) or say who has to sync instead."""
    if session.sync_mode() != "journal":
        print("sync mode is legacy — press «همگام‌سازی» in the app", file=sys.stderr)
        return
    try:
        result = session.sync_journal()
    except Exception as exc:  # noqa: BLE001 - a failed push must not hide the retitle result
        print(f"sync failed: {getattr(exc, 'code', None) or exc}", file=sys.stderr)
        return
    print(
        f"synced: {result['pushed']} pushed, {result['applied']} applied, "
        f"{result['conflicts']} conflict(s), {result['pending']} still pending"
    )


def main(argv: list[str] | None = None) -> int:
    """Retitle the vault at ``--home`` and print what happened."""
    parser = argparse.ArgumentParser(description="Add the username to every credential title.")
    parser.add_argument("--home", required=True, help="the vault home (folder holding meta.sqlite)")
    parser.add_argument("--root", default=ROOT, help=f"subtree to walk (default: {ROOT})")
    parser.add_argument("--rename", action="store_true",
                        help="also put the username in the file name (what the list shows)")
    parser.add_argument("--dry-run", action="store_true", help="list what would change; write nothing")
    parser.add_argument("--sync", action="store_true", help="run the multi-device sync afterwards")
    parser.add_argument("--password-env", default="SV_PW", help="env var holding the password")
    args = parser.parse_args(argv)

    password = os.environ.get(args.password_env) or ""
    if not password:
        print(f"set the master password in ${args.password_env}", file=sys.stderr)
        return 2
    if app_is_running():
        print("the desktop app is running — close it first (one writer at a time)", file=sys.stderr)
        return 3

    session = VaultSession(Path(args.home))
    session.unlock(password)
    if session.is_locked:
        print("unlock failed (wrong password?)", file=sys.stderr)
        return 1
    try:
        counts = _retitle_vault(session, args.root, dry_run=args.dry_run, rename=args.rename)
        print(
            f"{counts['scanned']} secret files under {args.root}: {counts['retitled']} retitled, "
            f"{counts['renamed']} renamed, {counts['unchanged']} already titled, "
            f"{counts['no_username']} without a username, {counts['unreadable']} unreadable, "
            f"{counts['name_taken']} name(s) taken"
        )
        if args.dry_run:
            print("dry run — nothing was written")
        elif args.sync:
            _sync(session)
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
