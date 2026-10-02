#!/usr/bin/env python3
"""Turn a **Bitwarden JSON export** into the `entries.json` shape `plan.py` expects.

Usage:
    python3 bitwarden_entries.py --export bitwarden_export.json --out entries.json

The KeePass extractor and a Bitwarden export describe the same kind of record, so the
mapping is deliberately thin: the item id becomes the `uuid`, the login fields map
straight over, and the Bitwarden *folder* becomes the `group_path` (`Root/Banks`,
`Root/Emails/Google`, …) — the same group names the KeePass taxonomy is keyed on, so
`plan.py` + `taxonomy.json` produce the identical `/رمزها/<دسته>/<سایت>/<عنوان>.md` tree.

The output holds plaintext credentials: write it to tmpfs with mode ``0600`` and shred it
when the migration is done. Nothing here prints a value.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT_GROUP = "Root"


def to_entry(item: dict, folders: dict[str, str]) -> dict:
    """Map one Bitwarden item (type 1 = login) onto a KeePass-style entry dict."""
    login = item.get("login") or {}
    uris = [u.get("uri", "") for u in (login.get("uris") or []) if isinstance(u, dict)]
    folder = folders.get(item.get("folderId") or "", "")
    group_path = [ROOT_GROUP] + [part.strip() for part in folder.split("/") if part.strip()]
    custom: dict[str, str] = {}
    if login.get("totp"):
        custom["otp"] = login["totp"]
    for field in item.get("fields") or []:
        name = (field.get("name") or "").strip()
        value = field.get("value")
        if name and isinstance(value, str) and value:
            custom[name] = value
    return {
        "uuid": item.get("id", ""),
        "title": item.get("name", ""),
        "username": login.get("username") or "",
        "password": login.get("password") or "",
        "url": uris[0] if uris else "",
        "notes": item.get("notes") or "",
        "custom": custom,
        "tags": [],
        "attachments": [],
        "group_path": group_path,
        "folder": folder,
        "favorite": bool(item.get("favorite")),
        "revision_date": item.get("revisionDate") or "",
    }


def main() -> int:
    """Read the export, write `entries.json`, print counts only."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--export", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--source", default="")
    args = ap.parse_args()

    data = json.loads(Path(args.export).read_text(encoding="utf-8"))
    folders = {f["id"]: f["name"] for f in data.get("folders") or []}
    entries, other_types = [], 0
    for item in data.get("items") or []:
        if int(item.get("type", 1)) != 1:
            other_types += 1
            continue
        entries.append(to_entry(item, folders))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "source_db": args.source or Path(args.export).name,
        "origin": "bitwarden",
        "entries": entries,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    out.chmod(0o600)

    with_pw = sum(1 for e in entries if e["password"])
    print(f"items={len(entries)} (non-login skipped={other_types}) with_password={with_pw} "
          f"with_otp={sum(1 for e in entries if 'otp' in e['custom'])} "
          f"folders={len(folders)} → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
