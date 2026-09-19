#!/usr/bin/env python3
"""Analyze an extracted KeePass JSON to size up a migration (titles only, no values).

Usage:
    analysis.py --entries <entries.json> [--samples N] [--group "Root/Banks"]
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


def host_of(url: str) -> str:
    """Return the bare host of a URL ('' when there is none)."""
    m = re.match(r"^\s*(?:[a-zA-Z][\w+.-]*://)?([^/\s:]+)", url or "")
    host = (m.group(1) if m else "").lower()
    return host[4:] if host.startswith("www.") else host


def main() -> int:
    """Print the group census and the overlap between auto-captured and curated groups."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--entries", required=True)
    ap.add_argument("--samples", type=int, default=12)
    ap.add_argument("--group", default="")
    args = ap.parse_args()

    entries = json.loads(Path(args.entries).read_text(encoding="utf-8"))["entries"]
    groups: dict[str, list[dict]] = {}
    for e in entries:
        groups.setdefault("/".join(e["group_path"]), []).append(e)

    print(f"total entries: {len(entries)}  groups: {len(groups)}")
    print("\n{:<40} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6}".format(
        "group", "n", "+user", "+pass", "+url", "+otp", "dupTtl"))
    for name, rows in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        titles = Counter((r["title"] or "").strip() for r in rows)
        dups = sum(c - 1 for c in titles.values() if c > 1)
        print("{:<40} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6}".format(
            name[:40], len(rows),
            sum(1 for r in rows if r["username"]),
            sum(1 for r in rows if r["password"]),
            sum(1 for r in rows if r["url"]),
            sum(1 for r in rows if any("otp" in k.lower() for k in r["custom"])),
            dups,
        ))

    if args.group:
        rows = groups.get(args.group, [])
        print(f"\n--- samples from {args.group} ({len(rows)}) ---")
        for r in rows[: args.samples]:
            print(f"  {r['title'][:50]!r} host={host_of(r['url'])[:35]!r} "
                  f"user={'y' if r['username'] else '-'} pw={'y' if r['password'] else '-'}")
        return 0

    auto_groups = [g for g in groups if "Browser" in g or "LastPass" in g or "Recycle" in g]
    curated = [e for g, rows in groups.items() if g not in auto_groups for e in rows]
    print(f"\ncurated entries (outside Browser/LastPass/Recycle): {len(curated)}")
    curated_keys = {(host_of(e["url"]), (e["username"] or "").lower()) for e in curated}
    curated_keys.discard(("", ""))
    curated_hosts = {h for h, _ in curated_keys if h}

    for g in auto_groups:
        rows = groups[g]
        keys = {(host_of(r["url"]), (r["username"] or "").lower()) for r in rows}
        keys.discard(("", ""))
        dup = sum(1 for k in keys if k in curated_keys)
        host_dup = sum(1 for h, _ in keys if h and h in curated_hosts)
        print(f"{g}: {len(rows)} entries, {len(keys)} distinct host+user, "
              f"{dup} identical to a curated entry, {host_dup} share a curated host")
        print("   samples: " + "، ".join(
            (r["title"] or host_of(r["url"]) or "?")[:24] for r in rows[:10]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
