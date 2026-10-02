#!/usr/bin/env python3
"""Second pass over a `/رمزها` plan: **one folder per site, one category per site**, and no
empty folders left behind.

Usage:
    ./.venv/bin/python tools/keepass-migration/curate.py --plan plan.json --entries entries.json \
        --out plan2.json --report            # analysis only (no vault writes)
    ./.venv/bin/python tools/keepass-migration/curate.py --plan plan.json --entries entries.json \
        --out plan2.json --apply             # move files + refresh notes + prune empty folders

Why a second pass
-----------------
`plan.py` decides a category per *entry* from the host rules, the KeePass group and keyword
rules, so the same site can end up in several categories (`توییتر (X)` under `ایمیل`, `Clockify`
under three) and each entry can land in its own near-duplicate folder (`toggl` vs `toggl.com`,
`پارس پک` vs `پارسپک`, `snapteach.ir` vs `snapteach.org`). This pass collapses all of that:

* **Site canonicalisation** — a site's folder name becomes the taxonomy's Persian name when one
  exists (`accounts.google.com` → `گوگل`), otherwise the bare registrable host with the usual
  service prefixes stripped (`panel.iranicard.ir` → `iranicard.ir`), with explicit merges for
  brand variants in `rules["site_canonical"]`.
* **One category per site** — the majority category of that site's entries, overridden by
  `rules["site_category"]` for the cases where the majority is simply wrong.
* **The two archive buckets stay put** (`rules["keep_categories"]`): `بایگانی LastPass` and
  `مرورگر — ورودهای ذخیره‌شده` keep the entries the first pass filed there (flat, host-named
  files) no matter what the site is, because they are archives, not the curated tree.
* **No empty folders** — every folder emptied by a move is deleted at the end.

Nothing here prints a credential value; bodies are never rewritten (a move is a metadata-only
rename) — only the file note is refreshed when a site's name changed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from apply import build_body, call, category_note, note_for, site_note  # noqa: E402

from vault.api.client import RefreshingClient  # noqa: E402
from vault.errors import VaultError  # noqa: E402

ROOT = "/رمزها"
WS = re.compile(r"\s+")
DOMAIN = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")
#: Trailing noise a KeePass/Bitwarden title can carry ("X - Clone", "Y - main", "Z - 2").
NOISE = re.compile(r"\s*[-–—]\s*(clone|copy|main|info|old|new|backup|bak|temp|test)\s*$", re.I)

#: Two-label country suffixes that are still part of the *site*, not the service.
SECOND_LEVEL = {
    "ac.ir", "co.ir", "org.ir", "net.ir", "gov.ir", "sch.ir", "id.ir", "ac.uk", "co.uk",
    "org.uk", "ac.jp", "co.jp", "com.au", "co.in", "com.br", "com.tr", "org.tr", "com.cn",
}

#: Service prefixes that describe *where* a login lives, not *which* site it is.
PREFIXES = (
    "www", "web", "login", "signin", "signup", "app", "apps", "panel", "my", "account",
    "accounts", "auth", "sso", "secure", "dash", "dashboard", "portal", "console", "manage",
    "admin", "api", "test", "testapi", "staging", "beta", "old", "new", "cdn",
)


def norm(text: str) -> str:
    """Normalize a label for **display** (NFC, collapsed whitespace; keeps ZWNJ)."""
    text = unicodedata.normalize("NFC", text or "")
    return WS.sub(" ", text).strip()


def low(text: str) -> str:
    """Normalize a label for **matching**: :func:`norm` plus no ZWNJ, one yeh/kaf, lowercase."""
    text = norm(text).replace("\u200c", "").replace("\u200f", "").replace("\u200e", "")
    text = text.replace("\u064a", "\u06cc").replace("\u0643", "\u06a9")
    return WS.sub(" ", text).strip().lower()


def host_of(text: str) -> str:
    """Bare host of a URL-ish string ('' when there is none)."""
    match = re.match(r"^\s*(?:[a-zA-Z][\w+.-]*://)?([^/\s:]+)", text or "")
    host = (match.group(1) if match else "").lower()
    return host[4:] if host.startswith("www.") else host


def entry_host(entry: dict) -> str:
    """Host from the URL, falling back to a URL-shaped title."""
    host = host_of(entry.get("url", ""))
    if host and "." in host:
        return host
    title_host = host_of(entry.get("title", ""))
    return title_host if "." in title_host else host


def registrable(host: str) -> str:
    """Reduce a host to its registrable domain ('' for anything that is not a domain).

    Country second-level suffixes (`ac.ir`, `co.uk`, …) count as part of the site, and bare
    IPs or host names without a dot are returned as they are.
    """
    host = low(host)
    if not DOMAIN.match(host) or IPV4.match(host):
        return ""
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) > 2 else host


def taxonomy_site(host: str, rules: dict) -> str:
    """Return the taxonomy's Persian site name for a host ('' when unmapped).

    An exact/subdomain match wins; otherwise a match on the registrable domain is used, so
    `cl.parspack.com` follows `my.parspack.com` to «پارسپک» instead of splitting the brand.
    """
    hosts = {low(k): norm(v) for k, v in rules["site_from_host"].items()}
    host = low(host)
    for pattern, name in sorted(hosts.items(), key=lambda kv: -len(kv[0])):
        if pattern and (host == pattern or host.endswith("." + pattern)):
            return name
    domain = registrable(host)
    if domain:
        names: set[str] = set()
        for pattern, name in hosts.items():
            if registrable(pattern) == domain:
                names.add(name)
        # only follow a domain when every key under it agrees on the Persian name —
        # najm.ac carries four different names, so its bare domain must not pick one
        if len(names) == 1:
            return names.pop()
    return ""


def canonical_site(site: str, host: str, rules: dict) -> str:
    """Collapse one plan site name into its canonical folder name."""
    named = taxonomy_site(host, rules)
    if named:
        return named
    canonical = {low(k): norm(v) for k, v in rules.get("site_canonical", {}).items()}
    for candidate in (low(site), low(host), registrable(host), registrable(site)):
        if candidate and candidate in canonical:
            return canonical[candidate]
    base = registrable(host) or registrable(site)
    return base or clean_name(site)


def clean_name(text: str) -> str:
    """Strip the ``- Clone`` / ``- main`` / ``- 2`` noise a KeePass title can carry."""
    out = norm(text)
    for _ in range(4):
        trimmed = NOISE.sub("", out).strip()
        if trimmed == out:
            break
        out = trimmed
    return out or norm(text)


def build(plan: dict, entries: list[dict], rules: dict) -> tuple[dict, list[dict], dict]:
    """Return ``(plan2, moves, stats)``: the curated plan plus the moves that reach it."""
    by_uuid = {e["uuid"]: e for e in entries}
    keep = {low(c) for c in rules.get("keep_categories", [])}
    site_category = {low(k): norm(v) for k, v in rules.get("site_category", {}).items()}

    rows = []
    for item in plan["items"]:
        entry = by_uuid.get(item["uuid"], {})
        row = {
            "uuid": item["uuid"],
            "old_path": item["vault_path"],
            "old_category": item["category"],
            "old_site": item.get("site", ""),
            "old_flat": bool(item.get("flat")),
            "archive": low(item["category"]) in keep,
            "host": registrable(entry_host(entry)),
            "site": canonical_site(item["site"], entry_host(entry), rules),
            "category": "",
            "entry": entry,
        }
        rows.append(row)

    # A title-only record ("Bitbarg", "MEGA", "Vivaldi") has no host to normalise, so it is
    # folded into the host-derived site of the same name when that name is unambiguous.
    stems: dict[str, str] = {}
    ambiguous: set[str] = set()
    for row in rows:
        name = row["site"]
        if row["host"] and re.fullmatch(r"[a-z0-9][a-z0-9.-]*", name):
            stem = re.sub(r"[^a-z0-9]", "", name.rsplit(".", 1)[0])
            if stem in stems and stems[stem] != name:
                ambiguous.add(stem)
            stems.setdefault(stem, name)
    for row in rows:
        if row["host"]:
            continue
        stem = re.sub(r"[^a-z0-9]", "", low(clean_name(row["site"])))
        if stem and stem in stems and stem not in ambiguous:
            row["site"] = stems[stem]

    # curated rows vote for their site's category; the majority wins, ties go to the
    # category that already holds the most entries overall (stable, explainable).
    votes: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        if not row["archive"]:
            votes[low(row["site"])][row["old_category"]] += 1
    totals = Counter(row["old_category"] for row in rows)
    decided: dict[str, str] = {}
    for site, counter in votes.items():
        if site in site_category:
            decided[site] = site_category[site]
            continue
        best = sorted(counter.items(), key=lambda kv: (-kv[1], -totals[kv[0]], kv[0]))
        decided[site] = best[0][0]
    for row in rows:
        row["category"] = row["old_category"] if row["archive"] else decided[low(row["site"])]
    # an archive bucket keeps plan.py's flattening rule: a site with a single entry stays a
    # plain file in the bucket folder, two or more get a folder of their own.
    archive_counts = Counter((r["category"], low(r["site"])) for r in rows if r["archive"])
    for row in rows:
        row["flat"] = row["archive"] and archive_counts[(row["category"], low(row["site"]))] == 1

    # Filenames collide when two old folders merge into one new folder. The vault compares
    # paths with SQLite's COLLATE NOCASE, so names are made unique under ASCII case folding,
    # and **the resident keeps its name**: a file already sitting in its target folder is
    # never renamed (that is what turned a simple merge into a swap in the first run), the
    # incoming file gets the next free `name (n).ext` instead.
    def name_key(text: str) -> str:
        return unicodedata.normalize("NFC", text).lower()

    def free(name: str, taken: set[str]) -> str:
        if name_key(name) not in taken:
            return name
        stem, dot, ext = name.rpartition(".")
        stem = stem if dot else name
        ext = ext if dot else ""
        for index in range(2, 200):
            candidate = f"{stem} ({index}){'.' + ext if ext else ''}"
            if name_key(candidate) not in taken:
                return candidate
        raise SystemExit(f"cannot find a free name for {name}")

    target: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        _parent_old, name = row["old_path"].rsplit("/", 1)
        row["folder"] = (f"{ROOT}/{row['category']}"
                         if row["flat"] else f"{ROOT}/{row['category']}/{row['site']}")
        row["name"] = name
        target[(row["folder"], name_key(name))].append(row)
    del target

    taken: dict[str, set[str]] = defaultdict(set)
    for row in rows:  # residents first: whoever is already there keeps the plain name
        if row["old_path"] == f"{row['folder']}/{row['name']}":
            taken[row["folder"]].add(name_key(row["name"]))
    old_items = {i["uuid"]: i for i in plan["items"]}
    moves: list[dict] = []
    items: list[dict] = []
    for row in rows:
        name = row["name"]
        if row["old_path"] != f"{row['folder']}/{name}":
            name = free(name, taken[row["folder"]])
        taken[row["folder"]].add(name_key(name))
        new_path = f"{row['folder']}/{name}"
        entry = row["entry"]
        # the body on disk is the one plan.py wrote with the *original* site/category
        size = len(build_body(entry, old_items[row["uuid"]]).encode("utf-8"))
        items.append({
            "uuid": row["uuid"],
            "vault_path": new_path,
            "old_path": row["old_path"],
            "category": row["category"],
            "site": "" if row["flat"] else row["site"],
            "flat": row["flat"],
            "matched": "curate",
            "group_path": "",
            "size": size,          # the body size on disk: identifies a file without its name
        })
        if new_path != row["old_path"]:
            moves.append({
                "src": row["old_path"],
                "dst": new_path,
                "size": size,
                "old_category": row["old_category"],
                "category": row["category"],
                "old_site": row["old_site"],
                "site": "" if row["flat"] else row["site"],
                "renamed_site": low(row["old_site"]) != low(row["site"]),
            })
    stats = {
        "items": len(items),
        "moves": len(moves),
        "renamed_site": sum(1 for m in moves if m["renamed_site"]),
        "moved_category": sum(1 for m in moves if m["old_category"] != m["category"]),
        "sites_before": len({(i["category"], low(i.get("site", ""))) for i in plan["items"]}),
        "sites_after": len({(i["category"], low(i["site"])) for i in items if not i["flat"]}),
        "categories_after": len({i["category"] for i in items}),
    }
    return {"root": ROOT, "items": items, "skipped": plan.get("skipped", [])}, moves, stats


def report(plan: dict, moves: list[dict], stats: dict, limit: int) -> None:
    """Print what the pass would change (no credentials, no values)."""
    print(f"items={stats['items']} moves={stats['moves']} "
          f"(renamed_site={stats['renamed_site']}, moved_category={stats['moved_category']})")
    print(f"site folders: {stats['sites_before']} → {stats['sites_after']}  "
          f"categories={stats['categories_after']}")
    by_cat = Counter(m["category"] for m in moves)
    print("\n## moves per target category")
    for cat, n in by_cat.most_common():
        print(f"  {n:5d}  {cat}")
    print("\n## category changes (old → new)")
    pairs = Counter((m["old_category"], m["category"]) for m in moves
                    if m["old_category"] != m["category"])
    for (old, new), n in pairs.most_common():
        print(f"  {n:5d}  {old}  →  {new}")
    print("\n## site renames (old → new), samples")
    renamed = Counter((m["old_site"], m["site"]) for m in moves
                      if m["renamed_site"] and m["old_category"] == m["category"])
    for (old, new), n in renamed.most_common(limit):
        print(f"  {n:5d}  {old!r} → {new!r}")
    print(f"  … {len(renamed)} distinct site renames")
    print("\n## merged sites (two or more old folders into one new site folder)")
    merge: dict[tuple[str, str], set[str]] = defaultdict(set)
    for m in moves:
        if m["site"]:
            merge[(m["category"], m["site"])].add(m["old_site"])
    many = {k: v for k, v in merge.items() if len(v) > 1}
    for (cat, site), olds in sorted(many.items(), key=lambda kv: -len(kv[1])):
        print(f"  {cat} :: {site} ← " + ", ".join(sorted(olds)))


def path_exists(client, path: str) -> bool:
    """True when ``path`` exists in the vault (one listing of its parent)."""
    parent, name = path.rsplit("/", 1)
    try:
        rows = call(client, "vault.list_folder", {"path": parent}).get("entries", [])
    except VaultError:
        return False
    return any(row["name"] == name for row in rows)


def free_name(client, path: str) -> str:
    """Return ``path`` when it is free, else the first free `name (n).ext` variant."""
    if not path_exists(client, path):
        return path
    parent, name = path.rsplit("/", 1)
    stem, dot, ext = name.rpartition(".")
    stem = stem if dot else name
    ext = ext if dot else ""
    for index in range(2, 60):
        candidate = f"{stem} ({index}){'.' + ext if ext else ''}"
        if not path_exists(client, f"{parent}/{candidate}"):
            return f"{parent}/{candidate}"
    return path


def src_row(client, path: str) -> dict | None:
    """Return the vault row at ``path`` (one listing), or None when it is not there."""
    parent, name = path.rsplit("/", 1)
    try:
        rows = call(client, "vault.list_folder", {"path": parent}).get("entries", [])
    except VaultError:
        return None
    return next((row for row in rows if row["name"] == name), None)


def apply_moves(client, plan2: dict, moves: list[dict], entries: list[dict], *, limit: int) -> int:
    """Create folders, move files, refresh notes, then prune every empty folder.

    Idempotent and swap-tolerant: a move whose source is gone but whose destination exists
    counts as already done, and a move that hits an occupied destination is retried after
    the whole pass (the occupant may itself move away) and otherwise lands under the next
    free `name (n).ext` — merging two folders cannot silently drop a file.
    """
    by_uuid = {e["uuid"]: e for e in entries}
    items_by_path = {i["vault_path"]: i for i in plan2["items"]}
    folders = Counter()
    for item in plan2["items"]:
        if item["flat"]:
            folders[(f"{ROOT}/{item['category']}", "")] += 1
        else:
            folders[(ROOT, item["category"])] += 1
            folders[(f"{ROOT}/{item['category']}", item["site"])] += 1
    for (parent, name) in sorted(folders):
        path = f"{parent}/{name}" if name else parent
        try:
            listing = call(client, "vault.list_folder", {"path": parent})
            if name and name not in {r["name"] for r in listing.get("entries", []) if r.get("is_dir")}:
                call(client, "vault.mkdir", {"path": path})
        except VaultError as exc:
            print(f"  ! mkdir {path}: {exc}")

    def place(move: dict, dst: str) -> None:
        """Move one file to ``dst`` and refresh its note when the site changed."""
        call(client, "vault.file_ops", {"op": "move", "src": move["src"], "dst": dst})
        item = items_by_path.get(move["dst"])
        if dst != move["dst"]:
            item = dict(item or {})
            item["vault_path"] = dst
        if item and (move["renamed_site"] or move["old_category"] != move["category"]):
            entry = by_uuid.get(item["uuid"])
            if entry:
                call(client, "vault.set_file_note", {"path": dst, "text": note_for(entry, item)})
        move["applied_to"] = dst

    done = failed = skipped = 0
    retry: list[dict] = []
    for index, move in enumerate(moves, 1):
        if limit and index > limit:
            break
        row = src_row(client, move["src"])
        try:
            if row is None:
                # the source is gone: either a previous run moved it, or it is a real loss
                if path_exists(client, move["dst"]):
                    skipped += 1
                else:
                    print(f"  ! {move['src']} gone and {move['dst']} missing")
                    failed += 1
            elif move.get("size") and int(row.get("size", -1)) != int(move["size"]):
                # the name now holds a different entry (the previous run bumped names):
                # never relocate a file we do not own
                print(f"  ! {move['src']} holds another file (size {row.get('size')} != "
                      f"{move['size']}) — left alone")
                skipped += 1
            else:
                place(move, move["dst"])
                done += 1
        except VaultError as exc:
            if exc.code == "ALREADY_EXISTS":
                retry.append(move)
            else:
                print(f"  ! move {move['src']} → {move['dst']}: {exc}")
                failed += 1
        if index % 50 == 0 or index == len(moves):
            print(f"  {100 * index / max(1, len(moves)):5.1f}%  moves={done} deferred={len(retry)} "
                  f"already={skipped} failed={failed}", flush=True)

    for move in retry:                 # destinations that were occupied during the pass
        try:
            row = src_row(client, move["src"])
            if row is None:
                skipped += 1
                continue
            if move.get("size") and int(row.get("size", -1)) != int(move["size"]):
                print(f"  ! {move['src']} carries another file (size {row.get('size')} != "
                      f"{move['size']}) — left in place")
                failed += 1
                continue
            dst = free_name(client, move["dst"])
            if dst != move["dst"]:
                print(f"    … {move['dst']} اشغال بود → {dst}")
                item = items_by_path.get(move["dst"])
                if item:
                    item["vault_path"] = dst
            place(move, dst)
            done += 1
        except VaultError as exc:
            print(f"  ! move {move['src']} → {move['dst']}: {exc}")
            failed += 1
    if failed:
        print(f"  {failed} moves failed")

    # every folder note is rebuilt from the final tree (site folders + categories + root)
    print("  … بازنویسی یادداشت پوشهها")
    sites: dict[tuple[str, str], list[str]] = defaultdict(list)
    for item in plan2["items"]:
        if item["flat"]:
            continue
        sites[(item["category"], item["site"])].append(Path(item["vault_path"]).stem)
    for (category, site), names in sorted(sites.items()):
        try:
            call(client, "vault.set_folder_note",
                 {"path": f"{ROOT}/{category}/{site}", "text": site_note(site, category, names)})
        except VaultError as exc:
            print(f"  ! note {category}/{site}: {exc}")
    per_category: dict[str, set[str]] = defaultdict(set)
    for (category, site) in sites:
        per_category[category].add(site)
    for category, names in sorted(per_category.items()):
        try:
            call(client, "vault.set_folder_note",
                 {"path": f"{ROOT}/{category}", "text": category_note(category, sorted(names))})
        except VaultError as exc:
            print(f"  ! note {category}: {exc}")

    pruned = prune_empty_folders(client, ROOT)
    print(f"  پوشه‌های خالی حذف‌شده: {pruned}")
    return failed


def align_names(client, plan2: dict, entries: list[dict]) -> int:
    """Rename files so every target folder matches the plan's names exactly.

    Names inside a folder are arbitrary, but a plan that disagrees with the vault cannot be
    verified by name. Files are matched to planned names by **body size** (falling back to the
    current name), then renamed through a temporary name so a straight swap is safe.
    """
    wanted: dict[str, dict[str, int]] = defaultdict(dict)
    for item in plan2["items"]:
        folder, name = item["vault_path"].rsplit("/", 1)
        wanted[folder][name] = int(item["size"])

    renames = 0
    for folder, plan_names in sorted(wanted.items()):
        try:
            rows = call(client, "vault.list_folder", {"path": folder}).get("entries", [])
        except VaultError as exc:
            print(f"  ! list {folder}: {exc}")
            continue
        actual = {r["name"]: int(r.get("size", -1)) for r in rows if not r["is_dir"]}
        if actual == plan_names:       # same names *and* same sizes → nothing to align
            continue
        mapping: dict[str, str] = {}
        taken_names: set[str] = set()
        for name, size in sorted(plan_names.items()):    # pass 1: a unique size match wins
            cands = [cur for cur, cur_size in actual.items()
                     if cur not in mapping and cur_size == size]
            if len(cands) == 1:
                mapping[cands[0]] = name
                taken_names.add(name)
        for name, size in sorted(plan_names.items()):    # pass 2: fall back to the same name
            if name in taken_names:
                continue
            hit = next((cur for cur in actual if cur not in mapping and cur == name), None)
            if hit is not None:
                mapping[hit] = name
                taken_names.add(name)
        changes = {cur: new for cur, new in mapping.items() if cur != new}
        if not changes:
            continue
        print(f"  {folder}: " + ", ".join(f"{cur} → {new}" for cur, new in sorted(changes.items())))
        # park *every* file of the folder on a temporary name first: after that no planned
        # name can be occupied, so swaps of any length are safe
        targets: dict[str, str] = dict(mapping)
        for cur in actual:
            if cur in targets:
                continue
            name = cur
            while name in taken_names or name in targets.values():
                stem, dot, ext = name.rpartition(".")
                stem = re.sub(r" \(\d+\)$", "", stem)
                name = f"{stem} (2){dot}{ext}" if dot else f"{stem} (2)"
            targets[cur] = name
        parked: dict[str, str] = {}
        try:
            for index, cur in enumerate(sorted(actual), 1):
                tmp = f".curate-tmp-{index:03d}"
                call(client, "vault.file_ops", {"op": "move", "src": f"{folder}/{cur}",
                                                "dst": f"{folder}/{tmp}"})
                parked[tmp] = targets[cur] if cur in targets else cur
            for tmp, new in sorted(parked.items()):
                call(client, "vault.file_ops", {"op": "move", "src": f"{folder}/{tmp}",
                                                "dst": f"{folder}/{new}"})
                renames += 1
        except VaultError as exc:
            print(f"  ! {folder}: {exc}")
    print(f"  نام‌های هم‌ترازشده: {renames}")
    return renames


def prune_empty_folders(client, root: str) -> int:
    """Delete every folder under ``root`` that ended up with no children."""
    removed = 0
    for _ in range(6):  # a folder can become empty only after its child is deleted
        folders: list[str] = []
        stack = [root]
        while stack:
            path = stack.pop()
            try:
                entries = call(client, "vault.list_folder", {"path": path}).get("entries", [])
            except VaultError:
                continue
            for row in entries:
                if row.get("is_dir"):
                    folders.append(row["path"])
                    stack.append(row["path"])
        empties = []
        for folder in sorted(folders, key=len, reverse=True):
            try:
                rows = call(client, "vault.list_folder", {"path": folder}).get("entries", [])
            except VaultError:
                continue
            if not rows:
                empties.append(folder)
        if not empties:
            break
        for folder in empties:
            try:
                call(client, "vault.file_ops", {"op": "delete", "src": folder, "recursive": False})
                removed += 1
            except VaultError as exc:
                print(f"  ! rmdir {folder}: {exc}")
    return removed


def main() -> int:
    """Run the pass (report by default, `--apply` to write)."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--entries", required=True)
    ap.add_argument("--rules", default=str(Path(__file__).with_name("taxonomy.json")))
    ap.add_argument("--out", required=True)
    ap.add_argument("--report-limit", type=int, default=40)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--align-names", action="store_true",
                    help="rename files so every folder matches the plan's names exactly")
    ap.add_argument("--prune-only", action="store_true",
                    help="only delete empty folders (no moves, no notes)")
    args = ap.parse_args()

    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    entries = json.loads(Path(args.entries).read_text(encoding="utf-8"))["entries"]
    rules = json.loads(Path(args.rules).read_text(encoding="utf-8"))
    rules.setdefault("site_canonical", {})
    rules.setdefault("site_category", {})
    rules.setdefault("keep_categories", [])
    for key in ("site_from_host", "site_aliases"):
        rules.setdefault(key, {})

    plan2, moves, stats = build(plan, entries, rules)
    report(plan2, moves, stats, args.report_limit)
    out = Path(args.out)
    out.write_text(json.dumps({"plan": plan2, "moves": moves, "stats": stats},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    out.chmod(0o600)
    print(f"--- {out}")
    if args.prune_only:
        client = RefreshingClient()
        print("pruning empty folders …")
        print(f"  پوشه‌های خالی حذف‌شده: {prune_empty_folders(client, ROOT)}")
        return 0
    if args.apply:
        print("applying …")
        failed = apply_moves(RefreshingClient(), plan2, moves, entries, limit=args.limit)
        return 1 if failed else 0
    if args.align_names:
        print("aligning names …")
        print(f"  نام‌های هم‌ترازشده: {align_names(RefreshingClient(), plan2, entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
