#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Import Max's self-knowledge folders into Secure Vault (the profile's new home).

The profile used to be served straight off the plaintext folders
``max_auto_bio/`` and ``hermes_knowing_from_max/`` under
``/data/Cloud/Documents/Writing/M. for me/hermes``.  Since Sep 2026 the live copy
lives *inside the vault* (default ``/max-profile``) and the
``max-profile`` MCP server reads it from there over the daemon socket; the
plaintext folders stay behind as the rebuild source.

The import is idempotent: files are (re)written by logical path, so running it
again after the source document changed simply refreshes the vault copy.

    ./.venv/bin/python tools/import_max_profile.py --dry-run
    ./.venv/bin/python tools/import_max_profile.py
    ./.venv/bin/python tools/import_max_profile.py --source <dir> --dest /max-profile

Requires the app to be running and unlocked (content tools need a session).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vault.api.client import VaultClient  # noqa: E402  (path set above)

SIDES = ("max_auto_bio", "hermes_knowing_from_max")
DEFAULT_SOURCE = Path(
    "/data/Cloud/Documents/Writing/M. for me/hermes"
)
DEFAULT_DEST = "/max-profile"
SOURCE_DOC = "max_full_profile.md"

FOLDER_NOTE = """# پروفایل مکس (ملینا) — داده‌ی زنده‌ی «شناخت مکس»

این پوشه خانهٔ جدید پروفایل شخصی مکس است (از شهریور ۱۴۰۵ به این‌سو داخل والت است، قبلاً
به‌صورت متن ساده در `M. for me/hermes/` بود).

- `max_auto_bio/` — شناختِ مکس از خودش (ساخته‌شده از سند «میـم مثل من»؛ stateless).
- `hermes_knowing_from_max/` — شناختِ هرمس از مکس که به‌تدریج از گفتگوها به‌روز می‌شود.
- `_source/max_full_profile.md` — سند اصلی (برای بازسازی `max_auto_bio/`).
- `_index.md` در هر شاخه، دروازهٔ ورود است: اول آن، بعد فقط فصلِ مربوط.

⚠ `04_desires-shadows.md` محتوای حساس دارد؛ فقط وقتی مستقیماً مرتبط است خوانده شود و
هیچ‌وقت آپلود/ارسال نشود.
"""


def _iter_source_files(source: Path) -> list[tuple[str, Path]]:
    """Return ``(vault-relative path, local file)`` pairs for everything to import."""
    out: list[tuple[str, Path]] = []
    for side in SIDES:
        d = source / side
        if not d.is_dir():
            print(f"! missing side dir: {d}", file=sys.stderr)
            continue
        for p in sorted(d.glob("*.md")):
            out.append((f"{side}/{p.name}", p))
    doc = source / SOURCE_DOC
    if doc.is_file():
        out.append((f"_source/{SOURCE_DOC}", doc))
    return out


def main(argv: list[str] | None = None) -> int:
    """Import the profile files and print a per-file receipt."""
    ap = argparse.ArgumentParser(description="Import Max's profile folders into Secure Vault.")
    ap.add_argument("--source", default=str(DEFAULT_SOURCE), help="plaintext profile dir")
    ap.add_argument("--dest", default=DEFAULT_DEST, help="vault folder (vault-absolute)")
    ap.add_argument("--dry-run", action="store_true", help="list what would be written")
    args = ap.parse_args(argv)

    source = Path(args.source).expanduser()
    dest = "/" + args.dest.strip("/")
    items = _iter_source_files(source)
    if not items:
        print("nothing to import", file=sys.stderr)
        return 1

    print(f"source : {source}")
    print(f"dest   : {dest}")
    print(f"files  : {len(items)}")
    if args.dry_run:
        for rel, path in items:
            print(f"  would write {dest}/{rel}  ({path.stat().st_size} bytes)")
        return 0

    client = VaultClient.from_runtime(role="mcp")
    status = client.call("vault.status", {})
    if status.get("locked"):
        print("! the vault is locked — unlock the app and retry", file=sys.stderr)
        return 2
    print(f"vault  : {status.get('home')} ({status.get('files')} files)")

    for folder in (dest, *(f"{dest}/{side}" for side in SIDES), f"{dest}/_source"):
        client.call("vault.mkdir", {"path": folder})

    written = 0
    for rel, path in items:
        text = path.read_text(encoding="utf-8")
        res = client.call(
            "vault.write_file",
            {"path": f"{dest}/{rel}", "content": text, "sensitivity": "normal"},
        )
        written += 1
        print(
            f"  {'created' if res.get('created') else 'updated'} "
            f"{dest}/{rel}  ({res.get('size')} bytes, {res.get('sensitivity')})"
        )

    client.call("vault.set_folder_note", {"path": dest, "text": FOLDER_NOTE})

    listing = client.call("vault.list_folder", {"path": dest})
    dirs = [e["name"] for e in listing["entries"] if e["is_dir"]]
    print(f"\nwritten: {written} files into {dest}")
    print(f"folders now under {dest}: {', '.join(dirs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
