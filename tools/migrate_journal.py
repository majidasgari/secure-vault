#!/usr/bin/env python3
"""Adopt the operation log for an existing vault (headless twin of Tools → ارتقای همگام‌سازی).

    read -r -s -p "master password: " SV_PW; echo
    SV_PW="$SV_PW" PYTHONPATH=src ./.venv/bin/python tools/migrate_journal.py --home /data/Vault

Seeds one operation per entry/note/learning card, switches ``sync.mode`` to ``journal`` and prints
what is queued. Idempotent: running it twice changes nothing. Nothing is uploaded here — the next
"multi-device sync" does that (and the first one uploads the whole content).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vault.core.session import VaultSession  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Migrate the vault at ``--home`` and print the outcome."""
    parser = argparse.ArgumentParser(description="Seed the operation log for an existing vault.")
    parser.add_argument("--home", required=True, help="the vault home (folder holding meta.sqlite)")
    parser.add_argument("--password-env", default="SV_PW", help="env var holding the password")
    args = parser.parse_args(argv)

    password = os.environ.get(args.password_env) or ""
    if not password:
        print(f"set the master password in ${args.password_env}", file=sys.stderr)
        return 2

    session = VaultSession(Path(args.home))
    session.unlock(password)  # raises nothing; the session simply stays locked on a wrong password
    if session.is_locked:
        print("unlock failed (wrong password?)", file=sys.stderr)
        return 1
    try:
        result = session.migrate_to_journal()
        if result.get("already"):
            print("already migrated — nothing to do")
        else:
            print(
                f"seeded {result['files']} entries, {result['notes']} notes, "
                f"{result['learning']} learning cards; {result['pending']} changes queued"
            )
        print("sync mode:", session.sync_mode())
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
