#!/usr/bin/env python3
"""Rebuild the vault's full-text search index (reclaims inline-base64 bloat).

Usage:
    python tools/reindex.py --home /path/to/vault --unlock-file /path/to/pw-file [--json]

Reads nothing else and writes only ``secure.store`` (the index is derived data).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vault.core.session import VaultSession  # noqa: E402
from vault.errors import VaultError  # noqa: E402


def _read_password(path: Path) -> str:
    """Read the vault password from ``path`` (first line, trailing newline trimmed)."""
    try:
        password = Path(path).read_text(encoding="utf-8").splitlines()[0]
    except (OSError, IndexError) as exc:
        raise SystemExit(f"cannot read the password file {path}: {exc}") from exc
    if not password:
        raise SystemExit(f"the password file {path} is empty")
    return password


def main(argv: list[str] | None = None) -> int:
    """Run the rebuild and print the before/after store size."""
    parser = argparse.ArgumentParser(description="Rebuild the Secure Vault search index")
    parser.add_argument("--home", required=True, help="vault home directory")
    parser.add_argument("--unlock-file", required=True, help="file holding the passphrase")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)

    home = Path(args.home).expanduser()
    if not home.is_dir():
        raise SystemExit(f"no such vault home: {home}")
    store = home / "secure.store"
    before = store.stat().st_size if store.exists() else 0

    session = VaultSession(home)
    try:
        session.unlock(_read_password(Path(args.unlock_file).expanduser()))
    except VaultError as exc:
        raise SystemExit(f"could not unlock the vault: {exc}") from exc
    try:
        print(f"vault: {home}")
        print(f"store before: {before / 1048576:.1f} MB")
        result = session.reindex_search(
            progress=lambda phase, done, total: print(
                f"\r  {phase}: {done}/{total}", end="", flush=True
            )
        )
        print()
    finally:
        session.close()
    after = store.stat().st_size if store.exists() else 0
    print(f"store after : {after / 1048576:.1f} MB "
          f"(saved {(before - after) / 1048576:.1f} MB)")
    print(f"indexed {result['indexed']} of {result['files']} files "
          f"(dropped {result['dropped']} stale rows)")
    if args.json:
        print(json.dumps({**result, "store_before": before, "store_after": after}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
