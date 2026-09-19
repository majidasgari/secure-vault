#!/usr/bin/env python3
"""Apply a keepass-migration plan to the live Secure Vault over its Unix socket.

Usage:
    ./.venv/bin/python tools/keepass-migration/apply.py \
        --plan /run/user/1000/kp-migration/plan.json \
        --entries /run/user/1000/kp-migration/entries.json \
        [--dry-run] [--limit N] [--only "دسته"] [--resume]

Secrets stay inside this process: the file bodies are built here from the (0600)
`entries.json` and pushed to the daemon socket, so no credential value ever reaches
an agent transcript.  Each entry is written at `normal` level (the MCP role may not
create a secret directly), then raised to `secretfile`, then given its Persian note
(raising the level drops the note, so the order matters).

Idempotent: an existing `secretfile` with the planned size is skipped.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from vault.api.client import RefreshingClient, VaultClient  # noqa: E402
from vault.errors import VaultError, VaultNotRunning  # noqa: E402

ROOT_NOTE = """**گنجینهٔ رمزها (مهاجرت از KeePass).** هر ورودی یک فایل `secretfile` است: نام و مسیرش دیده
می‌شود ولی محتوایش فقط با درخواست نمایش روی دسکتاپ باز می‌شود (دکمهٔ کپی).

- ساختار: `دسته/<سایت>/<ورودی>.md` — مثلاً `بانک و پرداخت/بلوبانک/کارت بلوبانک.md`.
- برای پیدا کردن: جست‌وجوی نام فایل (`search_filenames`) روی نام سایت یا عنوان ورودی.
- نمایش: `request_open_secret` روی مسیر فایل — محتوا هرگز به عامل برنمی‌گردد.

کی استفاده شود: هر وقت مکس گفت «شماره کارت X را بده»، «رمز Y چیست»، «لاگین Z را بده».
"""

CARD_RE = re.compile(r"(?<!\d)(?:[0-9\u06f0-\u06f9][ -]?){16}(?!\d)")
SHEBA_RE = re.compile(r"IR[0-9]{24}", re.IGNORECASE)
TOTP_RE = re.compile(r"\b\d{6}\b")


def call(client: VaultClient, method: str, params: dict, *, attempts: int = 5) -> dict:
    """Call the daemon, retrying connection failures and a transient read-only lock.

    Two things go wrong on a long bulk run: the app restarts and rotates the socket
    token (handled by ``RefreshingClient``), and a restart can leave the S3 sync layer
    in its read-only fallback for a few seconds (``SYNC_READONLY`` on every write).
    Both are transient, so they are retried instead of aborting the migration.
    """
    delay = 5
    for attempt in range(1, attempts + 1):
        try:
            return client.call(method, params)
        except (VaultNotRunning, ConnectionError, TimeoutError) as exc:
            if attempt == attempts:
                raise
            print(f"    ! {method}: {exc} — retry in {delay}s", flush=True)
            time.sleep(delay)
            delay *= 3
        except VaultError as exc:
            if getattr(exc, "code", "") != "SYNC_READONLY" or attempt == attempts:
                raise
            print(f"    ! {method}: vault read-only (sync) — wait {delay}s", flush=True)
            time.sleep(delay)
            delay = min(delay * 2, 120)
    raise AssertionError("unreachable")


def has(pattern: re.Pattern[str], text: str) -> bool:
    """True when the pattern matches anywhere in text."""
    return bool(text and pattern.search(text))


def entry_blob(entry: dict) -> str:
    """Concatenate every value of an entry (used for the field summary only)."""
    parts = [entry.get("username", ""), entry.get("password", ""), entry.get("notes", ""),
             entry.get("url", ""), " ".join(entry.get("custom", {}).values())]
    return "\n".join(parts)


def field_summary(entry: dict) -> list[str]:
    """Describe which kinds of data an entry carries (no values, just labels)."""
    blob = entry_blob(entry)
    labels = []
    if entry.get("username"):
        labels.append("نام کاربری")
    if entry.get("password"):
        labels.append("گذرواژه")
    if entry.get("url"):
        labels.append("آدرس سایت")
    if any("otp" in k.lower() for k in entry.get("custom", {})):
        labels.append("کد یکبارمصرف")
    if has(CARD_RE, blob):
        labels.append("شماره کارت")
    if has(SHEBA_RE, blob):
        labels.append("شبا")
    if entry.get("notes"):
        labels.append("یادداشت")
    if entry.get("custom"):
        labels.append("فیلدهای تکمیلی")
    if entry.get("attachments"):
        labels.append("ضمیمه")
    return labels


def note_for(entry: dict, item: dict) -> str:
    """Build the Persian one-line file note (what it is + when to reach for it)."""
    labels = field_summary(entry)
    what = "، ".join(labels) if labels else "اطلاعات ورود"
    site = item["site"]
    title = entry["title"].strip()
    head = f"«{site}»" if site and site != title else f"«{title}»"
    return (f"ورودی KeePass برای {head} — شامل {what}. "
            f"برای دیدن مقدار (ورود، کپی شماره کارت/رمز) همین فایل را باز کن.")


def build_body(entry: dict, item: dict) -> str:
    """Render the credential file body (plain label/value lines for easy copying)."""
    lines = [f"# {entry['title'].strip() or item['site']}", ""]
    meta = [f"سایت: {item['site']}", f"دسته: {item['category']}"]
    if item.get("group_path"):
        meta.append(f"گروه در KeePass: {item['group_path']}")
    lines += [" | ".join(meta), ""]
    lines.append(f"نام کاربری: {entry['username']}" if entry["username"] else "نام کاربری: —")
    lines.append(f"گذرواژه: {entry['password']}" if entry["password"] else "گذرواژه: —")
    if entry["url"]:
        lines.append(f"آدرس: {entry['url']}")
    for key, value in entry["custom"].items():
        if "otp" in key.lower() and value:
            lines.append(f"کد یکبارمصرف ({key}): {value}")
        elif value:
            lines.append(f"{key}: {value}")
    if entry["tags"]:
        lines.append(f"برچسب‌ها: {', '.join(entry['tags'])}")
    if entry["notes"]:
        lines += ["", "## یادداشت", entry["notes"].rstrip()]
    if entry["attachments"]:
        lines += ["", "## ضمیمه‌ها"]
        for att in entry["attachments"]:
            lines.append(f"- {att['name']} ({att['bytes']} بایت) — در فایل جدا ذخیره می‌شود")
    return "\n".join(lines).rstrip() + "\n"


def ensure_folder(client: VaultClient, path: str, note: str, cache: dict) -> bool:
    """Create a folder (idempotent) and set its note; False when it must be retried."""
    if cache.get(path):
        return True
    parent = path.rsplit("/", 1)[0] or "/"
    try:
        listing = call(client, "vault.list_folder", {"path": parent})
        names = {row["name"] for row in listing.get("entries", []) if row.get("is_dir")}
        leaf = path.rsplit("/", 1)[1]
        if leaf not in names:
            call(client, "vault.mkdir", {"path": path})
        if note:
            call(client, "vault.set_folder_note", {"path": path, "text": note})
    except VaultError as exc:
        print(f"  ! folder {path}: {exc}")
        return False
    cache[path] = True
    return True


def category_note(category: str, sites: list[str]) -> str:
    """Folder note for a category folder (its map)."""
    listing = "، ".join(f"`{s}`" for s in sorted(sites))
    return (f"**دستهٔ «{category}» در گنجینهٔ رمزها.** سایت‌ها/سرویس‌های این دسته: {listing}.\n\n"
            f"هر سایت یک زیرپوشه و هر ورودی یک فایل `secretfile` است. برای دیدن مقدار، فایل را "
            f"صدا بزن (`request_open_secret`).")


def site_note(site: str, category: str, entries: list[str]) -> str:
    """Folder note for a site folder."""
    listing = "، ".join(f"`{e}`" for e in sorted(entries))
    return (f"**«{site}» — زیرپوشهٔ دستهٔ {category}.** ورودی‌ها: {listing}.\n\n"
            f"کی استفاده شود: وقتی مکس رمز/کارت/لاگین مربوط به {site} را می‌خواهد.")


def main() -> int:
    """Run the migration (or a dry run) and print progress."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--entries", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="only the first N entries")
    ap.add_argument("--only", default="", help="only this category")
    ap.add_argument("--queue-limit", type=int, default=120,
                    help="pause while the semantic queue has more than N pending jobs")
    ap.add_argument("--passes", type=int, default=8, help="whole-plan retries when a pass fails")
    ap.add_argument("--retry-wait", type=int, default=45, help="seconds between passes")
    args = ap.parse_args()

    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    entries = json.loads(Path(args.entries).read_text(encoding="utf-8"))["entries"]
    by_uuid = {e["uuid"]: e for e in entries}

    items = [i for i in plan["items"] if not args.only or i["category"] == args.only]
    # derive the folder tree from the final paths (flat categories have no site level)
    tree: dict[str, dict[str, list[str]]] = {}
    for item in items:
        parts = item["vault_path"].strip("/").split("/")
        category = parts[1]
        site = parts[2] if len(parts) > 3 else ""
        tree.setdefault(category, {}).setdefault(site, []).append(Path(item["vault_path"]).stem)
    total = len(items)
    n_sites = sum(1 for sites in tree.values() for s in sites if s)
    print(f"plan: {total} entries in {len(tree)} categories "
          f"({n_sites} site folders + {sum(1 for s in tree.values() for k in s if not k)} flat)")

    if args.dry_run:
        for category, sites in sorted(tree.items(), key=lambda kv: -sum(len(v) for v in kv[1].values())):
            print(f"  {category}: " + "، ".join(
                f"{s or '(بیپوشه)'}({len(v)})" for s, v in sorted(sites.items())))
        return 0

    # RefreshingClient re-reads the rotated token when the app restarts mid-run
    client: VaultClient = RefreshingClient()

    done = skipped = 0
    failed: list[str] = []
    for attempt in range(1, args.passes + 1):
        done, skipped, failed = run_pass(client, items, by_uuid, tree, args, attempt)
        print(f"pass {attempt}: written={done} skipped={skipped} failed={len(failed)}", flush=True)
        if not failed:
            break
        if attempt < args.passes:
            print(f"  … {len(failed)} ورودی ناموفق — تلاش دوباره در {args.retry_wait}s", flush=True)
            time.sleep(args.retry_wait)
    else:
        print(f"done: written={done} skipped={skipped} planned={total} failed={len(failed)}")
        return 1
    print(f"done: written={done} skipped={skipped} planned={total}")
    return 0


def run_pass(client: VaultClient, items: list[dict], by_uuid: dict, tree: dict,
             args: argparse.Namespace, attempt: int) -> tuple[int, int, list[str]]:
    """One full pass over the plan; returns (written, skipped, failed paths)."""
    folder_cache: dict[str, bool] = {}
    ensure_folder(client, "/رمزها", ROOT_NOTE if attempt == 1 else "", folder_cache)
    for category, sites in sorted(tree.items(), key=lambda kv: -sum(len(v) for v in kv[1].values())):
        names = [s for s in sites if s] or [
            f"فایلهای بدون پوشه ({len(v)} ورودی)" for v in sites.values()
        ]
        ensure_folder(client, f"/رمزها/{category}",
                      category_note(category, names) if attempt == 1 else "", folder_cache)
        for site, filenames in sites.items():
            if site:
                ensure_folder(client, f"/رمزها/{category}/{site}",
                              site_note(site, category, filenames) if attempt == 1 else "",
                              folder_cache)

    total = len(items)
    done = skipped = 0
    failed: list[str] = []
    for index, item in enumerate(items, 1):
        if args.limit and index > args.limit:
            break
        entry = by_uuid.get(item["uuid"])
        if entry is None:
            print(f"  ! missing entry {item['uuid']}")
            continue
        body = build_body(entry, item)
        path = item["vault_path"]
        try:
            row = call(client, "vault.list_folder", {"path": path.rsplit("/", 1)[0]})
            existing = {r["name"]: r for r in row.get("entries", []) if not r.get("is_dir")}
            name = path.rsplit("/", 1)[1]
            if name in existing and existing[name].get("sensitivity") == "secretfile" \
                    and int(existing[name].get("size", 0)) == len(body.encode("utf-8")):
                skipped += 1
                continue
            call(client, "vault.write_file",
                 {"path": path, "content": body, "encoding": "utf-8", "sensitivity": "normal"})
            call(client, "vault.set_sensitivity", {"path": path, "level": "secretfile"})
            call(client, "vault.set_file_note", {"path": path, "text": note_for(entry, item)})
            done += 1
        except VaultError as exc:  # keep going; the next pass retries the failures
            print(f"  ! {path}: {exc}")
            failed.append(path)
            continue
        if index % 10 == 0 or index == total:
            print(f"  {100 * index / total:5.1f}%  {index}/{total}  "
                  f"written={done} skipped={skipped} failed={len(failed)}", flush=True)
        if index % 25 == 0:
            wait_for_semantic_queue(client, args.queue_limit)
    return done, skipped, failed


def wait_for_semantic_queue(client: VaultClient, limit: int, max_wait: int = 900) -> None:
    """Pause the migration while the semantic auto-index queue is backed up.

    Writing at `normal` level (the only level the MCP role may create) queues an
    embedding per file; a few hundred pending jobs peg the CPU and can wedge the
    daemon, so the loop sleeps until the queue drains below `limit`.
    """
    waited = 0
    while waited < max_wait:
        try:
            status = call(client, "vault.semantic_status", {})
        except VaultError:
            return
        pending = int((status.get("queue") or {}).get("pending") or 0)
        if pending <= limit:
            return
        print(f"    … اتو-ایندکس معنایی: {pending} در صف — {waited}s مکث", flush=True)
        time.sleep(20)
        waited += 20


if __name__ == "__main__":
    raise SystemExit(main())
