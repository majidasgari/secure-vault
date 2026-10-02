"""Label the real vault's folders with emoji (one-off maintenance tool).

An emoji label is metadata on the path (SPEC/01 §6): plaintext in ``meta.sqlite``, synced with
the metadata, and shown beside the name while the vault is locked. That is why this tool can
write labels without the master key — it never touches ``secure.store``, only the label column
of an existing row — while the product path (the desktop picker, the web picker,
``vault.set_emoji``) keeps requiring an unlocked, writable session.

Two layers decide each label, both data:

* ``EXPLICIT`` — the curated map, hand-written for the folders that carry the vault's structure
  (top levels, categories, projects). Sibling folders here are chosen to *differ*: a tree whose
  brothers share one glyph reads as a wall, not as a map.
* ``RULES`` — ordered regex families for the long tail (the ~330 credential folders, dates,
  journals). The first match wins, so a specific family must come before a general one.

Folders that match neither stay unlabelled on purpose: a default glyph on everything would
undo the point of labelling. ``--unmatched`` lists them so the table can grow.

Usage::

    ./.venv/bin/python tools/label_folders.py --plan --unmatched
    ./.venv/bin/python tools/label_folders.py --apply --home /data/Vault
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

#: Curated labels for the folders that carry the structure of the vault.
EXPLICIT: dict[str, str] = {
    # ------------------------------------------------------------------ top level
    "# برنامهریزی": "🗓️",
    "$پر استفاده": "⭐",
    "@چرکنویس": "🖊️",
    "attachments": "🖼️",
    "max-profile": "🧠",
    "برنامهنویسی": "🧑‍💻",
    "تحقیقات": "🔬",
    "رمزها": "🔐",
    "شخصی": "🏠",
    "کاری": "💼",
    "یادداشت روزانه": "📔",
    # --------------------------------------------------------------- programme notes
    "برنامهنویسی/AoE4 Database": "🎮",
    "برنامهنویسی/NSATech": "🛠️",
    "برنامهنویسی/متاتریدر": "📈",
    # -------------------------------------------------------------------- research
    "تحقیقات/آرشیو": "🗄️",
    "تحقیقات/ارائه": "📊",
    "تحقیقات/استخراج آزاد دانش": "🧩",
    "تحقیقات/ایده‌های تحقیقاتی": "💡",
    "تحقیقات/دیگر": "📌",
    "تحقیقات/مدیریت فنی": "🧰",
    "تحقیقات/مقاله": "📄",
    "تحقیقات/منتورینگ": "🎓",
    "تحقیقات/پیش‌بینی پیوند": "🔗",
    "تحقیقات/یادگیری ماشین": "🤖",
    "تحقیقات/آرشیو/دفاع دکتری": "🎓",
    "تحقیقات/آرشیو/دفاع دکتری/آغاز پایان": "🏁",
    "تحقیقات/آرشیو/دفاع دکتری/قدیمی": "🗄️",
    "تحقیقات/آرشیو/دفاع دکتری/کارها": "🗂️",
    "تحقیقات/آرشیو/لیست ژورنال": "📑",
    "تحقیقات/منتورینگ/1404": "📅",
    "تحقیقات/منتورینگ/پویا پیروزفر": "🎓",
    "تحقیقات/یادگیری ماشین/DeepSeek": "🤖",
    "تحقیقات/یادگیری ماشین/سیستم‌های پیشنهاددهنده": "📈",
    # ------------------------------------------------------------------ credentials
    "رمزها/آموزش": "📚",
    "رمزها/ابزار و خدمات آنلاین": "🧰",
    "رمزها/ارز دیجیتال و صرافی": "🪙",
    "رمزها/اپل، سامسونگ و دستگاه‌ها": "📱",
    "رمزها/ایمیل": "📧",
    "رمزها/اینترنت، شبکه و VPN": "🌐",
    "رمزها/بازی و سرگرمی": "🎮",
    "رمزها/بانک و پرداخت": "🏦",
    "رمزها/بایگانی LastPass": "🗃️",
    "رمزها/خرید": "🛒",
    "رمزها/سایر": "📌",
    "رمزها/سرور و زیرساخت": "🖥️",
    "رمزها/شبکه‌های اجتماعی و پیام‌رسان": "💬",
    "رمزها/مرورگر — ورودهای ذخیره‌شده": "🧭",
    "رمزها/کار — شرکت‌ها و مشتری‌ها": "🏢",
    "رمزها/کار — نجم": "🎯",
    # ---------------------------------------------------------------------- personal
    "شخصی/آرشیو": "🗄️",
    "شخصی/آرشیو/VPN": "🌐",
    "شخصی/آرشیو/تماس‌ها": "📇",
    "شخصی/آرشیو/رمز": "🔑",
    "شخصی/دارایی - خرید": "💰",
    "شخصی/سرگرمی": "🎬",
    "شخصی/سرگرمی/بازی": "🎮",
    "شخصی/سرگرمی/بازی/AOE4": "🎮",
    "شخصی/سرگرمی/فیلم و سریال": "🎬",
    "شخصی/سرگرمی/فیلم و سریال/نقد فیلم": "📝",
    "شخصی/مذهبی": "🤲",
    "شخصی/مذهبی/بدهی": "🧾",
    "شخصی/مذهبی/نذر": "🤲",
    "شخصی/نویسندگی": "✍️",
    "شخصی/نویسندگی/خواب‌ها": "💤",
    "شخصی/نویسندگی/داستان‌های رسمی": "📕",
    "شخصی/نویسندگی/داستان‌های رسمی/داستان‌های کوتاه": "📗",
    "شخصی/نویسندگی/داستان‌های رسمی/رمان‌ها": "📘",
    "شخصی/نویسندگی/داستان‌های رسمی/رمان‌ها/سایه‌های بلند": "📘",
    "شخصی/نویسندگی/داستان‌های غیررسمی": "📙",
    "شخصی/نویسندگی/داستان‌های غیررسمی/اجرا شده": "🎭",
    "شخصی/نویسندگی/داستان‌های غیررسمی/پرامپت شروع": "💡",
    "شخصی/نویسندگی/نامه‌ها": "✉️",
    "شخصی/نویسندگی/پرامپت _ جم": "💡",
    "شخصی/نویسندگی/پرامپت _ جم/جم": "💬",
    "شخصی/نویسندگی/پرامپت _ جم/خودشناسی": "🧠",
    "شخصی/نویسندگی/پرامپت _ جم/خودشناسی/چت تکاملی": "💬",
    # ------------------------------------------------------------------------ work
    "کاری/آرشیو": "🗄️",
    "کاری/آرشیو/آروشا": "🏢",
    "کاری/آرشیو/کاظمی": "🏢",
    "کاری/آرشیو/نجف": "🤲",
    "کاری/آرشیو/نجف/آرشیو": "🗄️",
    "کاری/آرشیو/نجف/آرشیو/تصنیف": "🎵",
    "کاری/آرشیو/نجف/آرشیو/جهد": "🗂️",
    "کاری/آرشیو/نجف/آرشیو/راهبری علمی": "🎓",
    "کاری/آرشیو/نجف/آرشیو/فانوس": "🗂️",
    "کاری/آرشیو/نجف/آرشیو/قم نت": "🗂️",
    "کاری/آرشیو/نجف/آرشیو/مجلس": "🗂️",
    "کاری/آرشیو/نجف/آرشیو/نجف": "🤲",
    "کاری/آرشیو/نجف/افراد": "👥",
    "کاری/آرشیو/نجف/پروژه‌ها": "🗂️",
    "کاری/آرشیو/نجف/پروژه‌ها/پاسدان": "🛡️",
    "کاری/آرشیو/نجف/کارهای سریع": "⚡",
    "کاری/ایده‌ها": "💡",
    "کاری/ایده‌ها/Interactive Story": "🎮",
    "کاری/ایده‌ها/secure-vault": "🔐",
    "کاری/ایده‌ها/داستان تعاملی": "📖",
    "کاری/رزومه": "📄",
    "کاری/نجم": "🏢",
    "کاری/نجم/تسک‌ها": "✅",
    "کاری/نجم/حر": "👤",
    "کاری/نجم/دیون سید": "👤",
    "کاری/نجم/روانشناسی": "🧠",
    "کاری/نجم/رو ساخت ویدئو": "🎬",
    "کاری/نجم/ساخت ویدئو": "🎬",
    "کاری/نجم/پیشنهادیه": "📄",
    "کاری/نجم/گزارش‌ها": "📊",
    "کاری/نجم/گزارش‌ها/پیکره": "🧱",
    "کاری/نجم/گزارش‌ها/گزارش ماهانه": "📅",
    "کاری/نیک‌کار": "🤝",
    # ------------------------------------------------------------------ daily notes
    "یادداشت روزانه/1390-1400": "📆",
    "یادداشت روزانه/1400-1410": "📆",
    # ----------------------------------------------------------------- max profile
    "max-profile/_source": "📄",
    "max-profile/hermes_knowing_from_max": "🤝",
    "max-profile/max_auto_bio": "📝",
    "@چرک‌نویس/فقط برای بهتر خواندن": "📖",
}

#: ``(name, emoji, why)`` ordered families for the long tail. First match wins.
RULES: tuple[tuple[str, str, str], ...] = (
    (r"presentation\s", "📊", "one presentation session"),
    (r"^\d{1,3}(?:\.\d{1,3}){3}", "🖥️", "a bare IP address: a host, not a service"),
    (r"بانک|بانکینو|بلو|رفاه|صادرات|تجارت|همراز|ملت|ملی|سپه|سامان|پاسارگاد|رسالت|گردشگری|"
     r"iranicard|shaparak|tejarat|refah|blu\b", "🏦", "a bank"),
    (r"تتر|صرافی|بیت‌پین|نوبیتکس|کیف پول|wallet|exodus|metamask|tronlink|binance|coin|"
     r"bitcoin|ethereum|trading|forex|exchange", "🪙", "a wallet or exchange"),
    (r"mail|gmail|proton|yandex|zoho|mailbox", "📧", "a mail account"),
    (r"instagram|اینستاگرام|توییتر|twitter|فیسبوک|facebook|linkedin|telegram|discord|reddit|"
     r"pinterest|tumblr|whatsapp|skype|hipchat|jitsi", "💬", "a social account"),
    (r"\.ac\.ir|\.edu|\.sch|elsevier|springer|wiley|taylorfrancis|overleaf|sharelatex|arxiv|"
     r"researchgate|manuscriptcentral|easychair|softconf|evise|hindawi|sciencedirect|"
     r"orcid|acm\.org|ieee|jstor|journals", "📄", "a paper/journal account"),
    (r"ssh|vps|server|hostiran|iranserver|talahost|arvan|hetzner|digitalocean|linode|vultr|"
     r"gcore|cherryservers|cloud|zabbix|kavenegar|domain|dns|irnic|cpanel|hosting",
     "🖥️", "a server, host or domain panel"),
    (r"github|gitlab|[گ]یت‌(?:هاب|لب)|bitbucket|git\b", "🧰", "a code host"),
    (r"خرید|شاپ|shop|store|digikala|دیجی‌کالا|snapp|tapsi|amazon|ebay|etsy|shopify|paypal|"
     r"پرداخت|gateway|zarinpal", "🛒", "a shop or payment"),
    (r"spotify|youtube|twitch|steam|استیم|soundcloud|last\.fm|deezer|radio|بازی|game|netflix|"
     r"فیلم|film|anime|مانگا", "🎮", "media, games and streaming"),
    (r"figma|notion|trello|asana|jira|slack|zoom|miro|airtable|evernote|onenote|dropbox|"
     r"anytype|clockify|toggl|rescuetime|taskulu|mendeley|zotero", "🧰", "an online tool"),
    (r"openai|chatgpt|claude|deepseek|huggingface|ollama|midjourney|copilot|perplexity|gemini",
     "🤖", "an AI service"),
    (r"^(آقای|خانم)\s|(?:^|\s)(?:مهندس|دکتر)\s", "👤", "a person"),
    (r"trbn|torabian|meysam|arash|changizi|sarvar|asgari|پروین|فطرس|خرم", "👤", "a person"),
    (r"اپل|سامسونگ|samsung|apple|tablet|ipad|iphone|galaxy|session app|sync on", "📱",
     "a device account"),
    (r"metamask|متامسک|چنجلی|کریپتوموس|بیت‌لاکر|nexo|crypto\.|bitlaunch", "🪙", "a wallet"),
    (r"bitwarden|vault|lastpass|keepass|پاسدان|pasdan|wallet backup", "🔐",
     "a password manager or the vault itself"),
    (r"جیمیل|گوگل|gmail|azure portal|outlook|icloud", "📧", "a mail or identity account"),
    (r"huntress|bitdefender|eset|kaspersky|mywot|shield|فایروال", "🛡️", "a security service"),
    (r"atlassian|اتلاسیان|joplin|evernote|miro|firefox|opensuse|linux|ubuntu", "🧰",
     "a tool or its account"),
    (r"ielts|فیدیبو|udemy|coursera|edx|kaggle", "🎓", "a course or exam"),
    (r"رپلیکا|کوییز|قینگز|secondlife|beeptunes|aniplus|footballi|tarafdari|thefa",
     "🎮", "a game or entertainment service"),
    (r"microsoft|backup", "🧰", "a backup of vendor accounts"),
    (r"آروشا|اسنپتیچ|بیلیونز|وی‌کادو|پلاس‌پلنت|اوراکل|پارس‌پک|آراد|oja|snapteach|spark|"
     r"perfomai|performai|nsatech|dmlab|najm|نجم|ثقت|جهد|استوریج|kplab", "🏢",
     "a company or a client folder"),
    (r"vpn|wifi|wlan|مودم|modem|a100|nas\b|loadbalancer|vbox|sso|gmiddleware|loot|findland|"
     r"azure|شکن|کلودفلر|cloudflare|ابرها|هتزنر|hetzner|دیجیتال‌اوشن|digitalocean|"
     r"پارس‌وی‌دی‌اس|localhost|my new key|myvpn", "🖥️",
     "a host, a VPN or an infrastructure account"),
    (r"^تحقیقات/منتورینگ/\d{4}/[^/]+$", "🎓", "a mentee's folder"),
    (r"^کاری/آرشیو/نجف/(?:پروژه‌ها|آرشیو/[^/]+)/[^/]+$", "🗂️", "a project folder"),
    (r"^شخصی/نویسندگی/داستان‌های رسمی/داستان‌های کوتاه/[^/]+$", "📖", "one short story"),
    (r"^شخصی/نویسندگی/داستان‌های غیررسمی/اجرا شده/[^/]+$", "🎭", "one performed story"),
    (r"^[\w.-]+\.[a-z]{2,}$", "🌐", "a site entry"),
)


def _fold(text: str) -> str:
    """Fold a Persian name for table lookup.

    ZWNJ (``\\u200c``), the Arabic ``ي``/``ك``, the alef variants and the tatweel are all
    invisible-or-typing differences, not identity: the vault's own search folds them the same
    way. Folding here means a hand-written key still matches the folder it names, no matter
    which keyboard (or which copy/paste) produced either side.
    """
    table = str.maketrans(
        {
            "\u200c": "",
            "\u200e": "",
            "\u200f": "",
            "\u0640": "",
            "\u064a": "\u06cc",
            "\u0649": "\u06cc",
            "\u0643": "\u06a9",
            "\u0629": "\u0647",
            "\u0622": "\u0627",
            "\u0623": "\u0627",
            "\u0625": "\u0627",
        }
    )
    return re.sub(r"\s+", " ", str(text).translate(table)).strip()


def _key_index() -> tuple[dict[str, str], list[str]]:
    """Return ``{folded path: emoji}`` plus the list of collisions it had to drop.

    Built once: the table is constant, and ``label_for`` runs for every folder in the vault.
    """
    return _build_key_index()


@lru_cache(maxsize=1)
def _build_key_index() -> tuple[dict[str, str], list[str]]:
    """Build the folded lookup table and report keys that fold onto each other."""
    index: dict[str, str] = {}
    collisions: list[str] = []
    for path, glyph in EXPLICIT.items():
        folded = _fold(path)
        if folded in index and index[folded] != glyph:
            collisions.append(path)
            continue
        index[folded] = glyph
    return index, collisions


#: ``RULES`` with both sides folded, so a pattern matches however the name was typed.
_RULES: tuple[tuple[str, str, str], ...] = tuple(
    (_fold(pattern), glyph, why) for pattern, glyph, why in RULES
)


def load_folders(home: Path) -> list[str]:
    """Return every folder path in the vault at ``home`` (read-only, no unlock needed)."""
    conn = sqlite3.connect(f"file:{home / 'meta.sqlite'}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT logical_path FROM files WHERE is_dir=1 ORDER BY logical_path"
        ).fetchall()
    finally:
        conn.close()
    return [str(row[0]) for row in rows]


def label_for(path: str) -> str | None:
    """Return the emoji for ``path``, or ``None`` when the tables have no opinion."""
    index, _collisions = _key_index()
    folded = _fold(path)
    if folded in index:
        return index[folded]
    name = folded.rsplit("/", 1)[-1]
    for pattern, glyph, _why in _RULES:
        # A pattern with a slash talks about the whole path (``تحقیقات/منتورینگ/1404/…``); one
        # without it talks about the folder's own name.
        subject = folded if "/" in pattern else name
        if re.search(pattern, subject, re.IGNORECASE):
            return glyph
    return None


def build_plan(folders: list[str]) -> dict[str, str]:
    """Return ``{path: emoji}`` for every folder a table labels."""
    plan: dict[str, str] = {}
    for path in folders:
        glyph = label_for(path)
        if glyph:
            plan[path] = glyph
    return plan


def main(argv: list[str] | None = None) -> int:
    """Print the plan, or write it into the vault's metadata index."""
    parser = argparse.ArgumentParser(
        prog="label_folders",
        description="Label the folders of a vault with emoji (plaintext path metadata).",
    )
    parser.add_argument("--home", default="/data/Vault", help="vault home (default: /data/Vault)")
    parser.add_argument("--apply", action="store_true", help="write the labels (default: plan)")
    parser.add_argument("--unmatched", action="store_true", help="list folders left unlabelled")
    parser.add_argument("--json", dest="json_out", default=None, help="also write the map here")
    parser.add_argument("--only", default=None, help="limit --apply to this path prefix")
    args = parser.parse_args(argv)

    home = Path(args.home)
    folders = load_folders(home)
    plan = build_plan(folders)
    unmatched = [p for p in folders if p not in plan]
    print(f"folders: {len(folders)}  labelled: {len(plan)}  unlabelled: {len(unmatched)}")

    if args.unmatched:
        for path in unmatched:
            print("  -", path)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"map written to {args.json_out}")

    if not args.apply:
        for path in sorted(plan)[:20]:
            print(f"  {plan[path]}  {path}")
        print("  … (plan only; pass --apply to write)")
        return 0

    targets = {p: g for p, g in plan.items() if not args.only or p.startswith(args.only)}
    if not targets:
        print("nothing to apply")
        return 1
    written = apply_labels(home, targets)
    print(f"applied {written} labels to {home / 'meta.sqlite'}")
    return 0


def apply_labels(home: Path, labels: dict[str, str]) -> int:
    """Write ``labels`` into the metadata index of the vault at ``home``.

    Uses the vault's own ``Index`` (so the schema migration runs first and the writes go
    through the same code the app uses), in one transaction, with a busy timeout: the app may
    be running and holding the write lock for a moment.
    """
    from vault.core.index import Index

    index = Index(home / "meta.sqlite")
    try:
        index.conn.execute("PRAGMA busy_timeout=8000")
        written = 0
        for path, glyph in sorted(labels.items()):
            if index.get_file(path) is None:
                print(f"  ! missing row, skipped: {path}")
                continue
            index.set_emoji(path, glyph)
            written += 1
        index.checkpoint()
        return written
    finally:
        index.close()


if __name__ == "__main__":
    raise SystemExit(main())
