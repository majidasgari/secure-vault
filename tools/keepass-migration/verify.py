#!/usr/bin/env python3
"""Verify that a keepass-migration plan really landed in the vault.

Usage:
    ./.venv/bin/python tools/keepass-migration/verify.py \
        --plan plan.json --entries entries.json [--notes]

For every planned path it checks the file exists, carries `secretfile`, matches the
byte size of the body the plan would build, and (with `--notes`) has a file note.
Prints a PASS/FAIL summary plus the exact missing/leaky paths.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from vault.api.client import VaultClient  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apply import build_body  # noqa: E402


def main() -> int:
    """Compare the plan against the live vault and print the result."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--entries", required=True)
    ap.add_argument("--notes", action="store_true")
    args = ap.parse_args()

    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    entries = json.loads(Path(args.entries).read_text(encoding="utf-8"))["entries"]
    by_uuid = {e["uuid"]: e for e in entries}
    client = VaultClient.from_runtime(role="mcp")

    listings: dict[str, dict] = {}
    missing: list[str] = []
    wrong_level: list[str] = []
    wrong_size: list[str] = []
    no_note: list[str] = []
    checked = 0
    for item in plan["items"]:
        parent, name = item["vault_path"].rsplit("/", 1)
        if parent not in listings:
            listings[parent] = call_listing(client, parent)
        rows = {r["name"]: r for r in listings[parent].get("entries", []) if not r.get("is_dir")}
        row = rows.get(name)
        if row is None:
            missing.append(item["vault_path"])
            continue
        checked += 1
        expected = len(build_body(by_uuid[item["uuid"]], item).encode("utf-8"))
        if row.get("sensitivity") != "secretfile":
            wrong_level.append(f"{item['vault_path']} ({row.get('sensitivity')})")
        if int(row.get("size", -1)) != expected:
            wrong_size.append(f"{item['vault_path']} {row.get('size')}!={expected}")
        if args.notes:
            note = client.call("vault.file_note", {"path": item["vault_path"]}).get("note")
            if not note:
                no_note.append(item["vault_path"])

    total = len(plan["items"])
    print(f"planned={total} verified={checked} missing={len(missing)} "
          f"wrong_level={len(wrong_level)} wrong_size={len(wrong_size)}"
          + (f" no_note={len(no_note)}" if args.notes else ""))
    for label, rows in (("MISSING", missing), ("LEVEL", wrong_level),
                        ("SIZE", wrong_size), ("NOTE", no_note)):
        for row in rows[:40]:
            print(f"  {label}: {row}")
    ok = not (missing or wrong_level or wrong_size or (args.notes and no_note))
    print("VERIFY OK" if ok else "VERIFY FAILED")
    return 0 if ok else 1


def call_listing(client: VaultClient, parent: str) -> dict:
    """List one folder, tolerating a missing folder (returns empty entries)."""
    try:
        return client.call("vault.list_folder", {"path": parent})
    except Exception:  # noqa: BLE001 - a missing folder simply means "nothing landed"
        return {"entries": []}


if __name__ == "__main__":
    raise SystemExit(main())
