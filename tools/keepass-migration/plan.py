#!/usr/bin/env python3
"""Turn `keepass-migration/extract.py` output into a vault plan.

Usage:
    plan.py --entries <entries.json> [--rules taxonomy.json] [--out plan.json] [--report]

Decides, per entry, a target path `/رمزها/<دسته>/<سایت>/<عنوان>.md` plus a Persian
file note, using the ordered rules in `taxonomy.json` (categories, category rules,
site aliases, per-entry overrides).  Writes `plan.json` — which contains **paths and
notes only, never credentials** — and prints a review report by category/site.
"""
from __future__ import annotations

import argparse
import json
import re
import unicodedata
from pathlib import Path

ROOT = "/رمزها"
DEFAULT_RULES = Path(__file__).with_name("taxonomy.json")

JUNK = re.compile(r"[\u200c\u200f\u200e]")
WS = re.compile(r"\s+")


def norm(text: str) -> str:
    """Normalize a Persian/Latin label for matching (case-fold, ZWNJ, spaces)."""
    text = unicodedata.normalize("NFC", text or "")
    text = JUNK.sub(" ", text)
    text = text.replace("\u064a", "\u06cc").replace("\u0643", "\u06a9")
    return WS.sub(" ", text).strip()


def low(text: str) -> str:
    """Case-folded variant of :func:`norm`, for Latin-insensitive matching."""
    return norm(text).lower()


def host_of(url: str) -> str:
    """Return the bare host of a URL ('' when there is none)."""
    m = re.match(r"^\s*(?:[a-zA-Z][\w+.-]*://)?([^/\s:]+)", url or "")
    host = (m.group(1) if m else "").lower()
    return host[4:] if host.startswith("www.") else host


def entry_host(entry: dict) -> str:
    """Host from the URL field, falling back to the title when it is itself a URL."""
    host = host_of(entry.get("url", ""))
    if host and "." in host:
        return host
    title_host = host_of(entry.get("title", ""))
    return title_host if "." in title_host else host


def load_rules(path: Path) -> dict:
    """Load the taxonomy rules, filling in the defaults for missing keys."""
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    data.setdefault("categories", [])
    data.setdefault("category_rules", [])
    data.setdefault("group_categories", {})
    data.setdefault("priority_groups", {})
    data.setdefault("flat_categories", [])
    data.setdefault("dedupe_categories", [])
    data.setdefault("dedupe_all", False)
    data.setdefault("site_aliases", {})
    data.setdefault("site_from_host", {})
    data.setdefault("overrides", {})
    data.setdefault("default_category", "سایر")
    data.setdefault("ignore_groups", [])
    return data


def pick_category(entry: dict, site: str, rules: dict) -> tuple[str, str]:
    """Return (category, matched_rule_id) for one entry.

    Priority: explicit host rules (site identity is the strongest signal) → the user's own
    KeePass group (longest prefix first) → keyword rules over title/site/group/host.
    """
    groups = [low(g) for g in entry["group_path"]]
    group_path = "/".join(groups)
    host = entry_host(entry).lower()
    for prefix, category in sorted(rules["priority_groups"].items(), key=lambda kv: -len(kv[0])):
        prefix = low(prefix)
        if group_path == prefix or group_path.startswith(prefix + "/"):
            return category, f"priority-group:{prefix}"
    host_rules = [r for r in rules["category_rules"] if r.get("host")]
    key_rules = [r for r in rules["category_rules"] if not r.get("host")]
    for rule in host_rules:
        for kw in rule["match"]:
            kw = low(kw)
            if kw and host.endswith(kw):
                return rule["category"], kw
    for prefix, category in sorted(rules["group_categories"].items(),
                                   key=lambda kv: -len(kv[0])):
        prefix = low(prefix)
        if group_path == prefix or group_path.startswith(prefix + "/"):
            return category, f"group:{prefix}"
    hay_fields = [low(entry["title"]), low(site), group_path, host,
                  low(" ".join(entry["tags"]))]
    hay = " | ".join(f for f in hay_fields if f)
    if low(site) in {low(c) for c in rules["categories"]}:
        return site, "category-is-site"
    for rule in key_rules:
        for kw in rule["match"]:
            kw = low(kw)
            if kw and kw in hay:
                return rule["category"], kw
    return rules["default_category"], "default"


def pick_site(entry: dict, rules: dict) -> str:
    """Return the site folder name for one entry (host map -> title alias -> title)."""
    host = entry_host(entry)
    hosts = {k.lower(): v for k, v in rules["site_from_host"].items()}
    for pattern, name in sorted(hosts.items(), key=lambda kv: -len(kv[0])):
        if pattern and (host == pattern or host.endswith("." + pattern) or pattern in host):
            return norm(name)
    title = norm(entry["title"])
    aliases = {low(k): v for k, v in rules["site_aliases"].items()}
    for key in sorted(aliases, key=len, reverse=True):
        if key and key in title.lower():
            return aliases[key]
    return clean_site(title, host) if title else (host or "بدون‌نام")


def clean_site(name: str, host: str) -> str:
    """Sanitize a site folder name (no slashes; a URL-shaped title falls back to its host)."""
    text = name.strip()
    if "://" in text or "/" in text or "?" in text:
        text = host or text
    return (text.replace("/", "\u2044").replace("\\", "\u2044").strip() or "بدون\u200cنام")[:80]


def clean_title(title: str) -> str:
    """Make an entry title safe and readable as a file name."""
    text = norm(title)
    if text in {"", "/", ".", ".."}:
        return "بدون‌عنوان"
    return text.replace("/", "⁄")[:120]


def build(rules: dict, entries: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (plan items, skipped entries) for every extracted entry."""
    plan: list[dict] = []
    skipped: list[dict] = []
    seen: dict[str, int] = {}
    flat = {norm(c) for c in rules.get("flat_categories", [])}
    dedupe = {norm(c) for c in rules.get("dedupe_categories", [])}
    dedupe_all = bool(rules.get("dedupe_all"))
    seen_secrets: set[tuple[str, str, str, str]] = set()
    for entry in entries:
        groups = [low(g) for g in entry["group_path"]]
        ignored = [low(ig) for ig in rules["ignore_groups"]]
        if any(ig in g for g in groups for ig in ignored if ig):
            skipped.append({"title": entry["title"], "reason": "ignored-group",
                            "group": "/".join(groups)})
            continue
        if not any([entry["title"], entry["username"], entry["password"],
                    entry["url"], entry["notes"], entry["custom"], entry["attachments"]]):
            skipped.append({"title": entry["title"], "reason": "empty",
                            "group": "/".join(groups)})
            continue
        category_guess, _ = pick_category(entry, norm(entry["title"]), rules)
        if (dedupe_all or category_guess in dedupe) and entry["password"]:
            key4 = (category_guess, entry_host(entry).lower(),
                    entry["username"].strip().lower(), entry["password"])
            # only duplicate when the site is known, so host-less entries are never merged
            if key4[1] and key4 in seen_secrets:
                skipped.append({"title": entry["title"], "reason": "duplicate",
                                "group": "/".join(groups)})
                continue
            seen_secrets.add(key4)
        override = rules["overrides"].get(entry["uuid"]) or {}
        site = norm(override.get("site") or "") or pick_site(entry, rules)
        category = norm(override.get("category") or "")
        matched = "override"
        if not category:
            category, matched = pick_category(entry, site, rules)
        filename = clean_title(override.get("filename") or entry["title"])
        key = f"{category}/{site}/{filename}"
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            filename = f"{filename} ({seen[key]})"
        plan.append(
            {
                "uuid": entry["uuid"],
                "vault_path": f"{ROOT}/{category}/{site}/{filename}.md",
                "category": category,
                "site": site,
                "flat": category in flat,
                "matched": matched,
                "group_path": "/".join(entry["group_path"]),
            }
        )
    # a "flat" category keeps single-entry sites as plain files in the category folder
    per_site: dict[tuple[str, str], int] = {}
    for item in plan:
        if item["flat"]:
            per_site[(item["category"], item["site"])] = \
                per_site.get((item["category"], item["site"]), 0) + 1
    for item in plan:
        if item["flat"] and per_site[(item["category"], item["site"])] == 1:
            name = Path(item["vault_path"]).name
            item["vault_path"] = f"{ROOT}/{item['category']}/{name}"
    return plan, skipped


def main() -> int:
    """Build the plan and print the review report."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--entries", required=True)
    ap.add_argument("--rules", default=str(DEFAULT_RULES))
    ap.add_argument("--out", default="/run/user/1000/kp-migration/plan.json")
    ap.add_argument("--report", action="store_true", help="print the category/site report")
    args = ap.parse_args()

    data = json.loads(Path(args.entries).read_text(encoding="utf-8"))
    rules = load_rules(Path(args.rules))
    plan, skipped = build(rules, data["entries"])

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {"root": ROOT, "items": plan, "skipped": skipped,
               "source_db": data.get("source_db", "")}
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    out.chmod(0o600)

    by_cat: dict[str, dict[str, int]] = {}
    for item in plan:
        by_cat.setdefault(item["category"], {}).setdefault(item["site"], 0)
        by_cat[item["category"]][item["site"]] += 1
    print(f"entries={len(data['entries'])} planned={len(plan)} skipped={len(skipped)} "
          f"categories={len(by_cat)} sites={sum(len(v) for v in by_cat.values())}")
    if args.report:
        for category in sorted(by_cat, key=lambda c: -sum(by_cat[c].values())):
            sites = by_cat[category]
            print(f"\n## {category}  ({sum(sites.values())} ورودی، {len(sites)} سایت)")
            for site, count in sorted(sites.items(), key=lambda kv: (-kv[1], kv[0])):
                print(f"  - {site}: {count}")
    if skipped:
        print("\n--- skipped ---")
        for row in skipped[:40]:
            print(f"  {row['reason']}: {row['title']!r} in {row['group']!r}")
    print(f"--- plan: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
