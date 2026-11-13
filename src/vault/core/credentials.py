"""Credential bodies, host matching and the browser-autofill index.

The credential files under ``/رمزها`` are written by ``tools/keepass-migration/apply.py`` as a
``# title`` heading, one meta line (``سایت: … | دسته: …``) and one ``label: value`` line per
field. The Persian labels below are that importer's *data*, exactly like the ones the Joplin
importer writes, so they live here as literals; ``tests/test_browser_autofill.py`` asserts they
stay in sync with the writer.

Two rules this module exists to keep:

* it never writes a password anywhere — :func:`parse_body` returns the values and the caller
  (the browser bridge) hands them to a page, which is the only place they go;
* :class:`CredentialIndex` keeps **metadata only** (path, title, site, url, username and whether
  a password/OTP exists), never a password, so the long-lived in-memory structure is safe to
  hold for the whole session.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from ..util import normalize_fa

#: The vault folder holding the migrated credential entries.
CREDENTIAL_ROOT = "رمزها"

#: Fields a credential search may match, in the order a hit reports them. The password (and the
#: OTP secret) are deliberately absent — a :class:`CredentialEntry` never even holds them.
SEARCHABLE_FIELDS = ("title", "site", "category", "url", "username")

#: Value written for an empty field.
EMPTY_MARKERS = frozenset({"", "—", "-", "–", "n/a", "none", "null"})

#: Label spellings accepted for each field (first present wins, in this order).
USERNAME_LABELS = ("نام کاربری", "نامکاربری", "نام کاربری/ایمیل", "یوزرنیم", "username", "user name", "user", "login")
PASSWORD_LABELS = ("گذرواژه", "گذر واژه", "رمز عبور", "پسورد", "password", "pass")
URL_LABELS = ("آدرس", "نشانی", "آدرس سایت", "url", "website", "web site", "site url", "link")
SITE_LABELS = ("سایت", "وبسایت", "site")
CATEGORY_LABELS = ("دسته", "دسته بندی", "category", "group")
OTP_LABELS = ("کد یکبارمصرف", "کد یک بار مصرف", "کد یکبار مصرف", "otp", "totp", "2fa", "2fa code")

#: The card fields a Shetab (Iranian banking) card carries, as ``(field, label)``: the label is
#: what the body writes and what :func:`parse_body` looks for, exactly like the labels above.
CARD_FIELDS = (
    ("bank", "بانک"),
    ("number", "شماره کارت"),
    ("expiry", "تاریخ انقضا"),
    ("cvv2", "CVV2"),
    ("pin2", "رمز دوم"),
    ("account", "شماره حساب"),
    ("sheba", "شبا"),
    ("holder", "صاحب حساب"),
)

#: Spellings accepted for each card field when *reading* a body (first present wins). The entry
#: may come from the KeePass migration, where the label is whatever the user typed back then.
CARD_LABEL_ALIASES = {
    "bank": ("بانک", "نام بانک", "bank"),
    "number": ("شماره کارت", "شمارهٔ کارت", "کارت", "card number", "card"),
    "expiry": ("تاریخ انقضا", "تاریخ انقضاء", "انقضا", "expiry", "expiry date", "exp"),
    "cvv2": ("cvv2", "cv2", "cvv", "cvv2 (سه رقم)"),
    "pin2": ("رمز دوم", "رمز دوم پویا", "رمز دوم ثابت", "رمز اینترنتی", "pin2", "رمز دوم اینترنتی"),
    "account": ("شماره حساب", "حساب", "account", "account number"),
    "sheba": ("شبا", "شماره شبا", "sheba", "iban"),
    "holder": ("صاحب حساب", "نام صاحب حساب", "card holder", "holder"),
}

#: The category a card created in the desktop app lands in (the treasure's own card folder).
CARD_CATEGORY = "بانک و پرداخت"

#: A line starting with one of these ends the ``label: value`` region.
SECTION_MARKERS = ("##",)

#: A trailing label that is really a file extension, not a TLD (``GitHub.md`` is a file name).
_FILE_EXTENSIONS = frozenset(
    {
        "md", "txt", "json", "csv", "pdf", "png", "jpg", "jpeg", "gif", "svg", "zip",
        "html", "htm", "xml", "yaml", "yml", "log", "doc", "docx", "xls", "xlsx", "bak",
        "key", "ini", "cfg", "conf", "tar", "gz", "mp4", "mp3", "wav", "sqlite", "db",
    }
)

_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*\.[a-z]{2,}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_LOCAL_HOSTS = frozenset({"localhost"})

#: Country-code TLDs whose registries hand out two-label suffixes (``x.ac.ir``, ``x.co.uk``).
_TWO_LABEL_TLDS = frozenset(
    {
        "ir", "uk", "au", "nz", "jp", "br", "tr", "in", "za", "kr", "cn", "tw", "hk", "sg",
        "mx", "ar", "il", "sa", "ae", "my", "id", "th", "vn", "pk", "bd", "ng", "ke", "eg",
        "pl", "ru", "gr", "pt", "es", "it", "se", "no", "nl", "ch", "at", "be", "dk", "fi",
    }
)

#: Recognised second-level labels of those registries.
_SECOND_LEVELS = frozenset(
    {
        "ac", "co", "com", "net", "org", "gov", "go", "edu", "sch", "or", "ne", "gen",
        "firm", "ind", "mil", "id", "web", "info", "biz", "nom", "res", "gob", "gouv",
        "ltd", "plc", "me",
    }
)

#: The category a login saved *from the browser* lands in. It already exists in the treasure
#: (the old browser export lives there) and its shape is ``<سایت>/<سایت>.md`` — so an entry the
#: add-on writes is indistinguishable from the ones the importer produced.
BROWSER_CATEGORY = "مرورگر — ورودهای ذخیره‌شده"

#: Characters a file name may never contain (they would build a path, not a name).
_UNSAFE_NAME = re.compile(r"[/\\:*?\"<>|\x00-\x1f]")

#: Control characters that would break the line-based credential body.
_UNSAFE_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def _clean(value: str) -> str:
    """Return ``value`` stripped, or ``""`` when it is one of the empty markers."""
    text = (value or "").strip()
    return "" if text.lower() in EMPTY_MARKERS else text


def _host_like(value: str) -> str:
    """Return ``value`` when it looks like a hostname/IP, else ``""``."""
    text = _clean(value).lower()
    if not text:
        return ""
    if _IPV4_RE.match(text) or text in _LOCAL_HOSTS:
        return text
    if not _HOST_RE.match(text):
        return ""
    # ``GitHub.md`` is a file name, not a Moldovan domain: a trailing label that is really a
    # document/code extension must never make a file name look like a host.
    if text.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
        return ""
    return text


def normalize_host(value: str) -> str:
    """Return the bare host of a URL or host string (``""`` when there is none).

    Strips the scheme, any userinfo, the path/query/fragment, a port and a leading ``www.``,
    lowercases and IDNA-encodes the result.
    """
    text = _clean(value)
    if not text:
        return ""
    if "://" in text:
        text = text.split("://", 1)[1]
    for separator in ("/", "?", "#", " "):
        text = text.split(separator, 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):  # [::1]:8788
        text = text.split("]", 1)[0].lstrip("[")
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    text = text.strip().strip(".").lower()
    if text.startswith("www."):
        text = text[4:]
    text = _host_like(text)
    if not text:
        return ""
    try:
        return text.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return text


def registrable_domain(host: str) -> str:
    """Return a best-effort eTLD+1 for ``host`` (``""`` for an empty input).

    Handles the two-label suffixes the vault actually contains (``iust.ac.ir`` →
    ``iust.ac.ir``, ``najm.ac`` → ``najm.ac``) without shipping a public-suffix list.
    """
    host = (host or "").strip().lower()
    if not host or _IPV4_RE.match(host) or host in _LOCAL_HOSTS:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if labels[-1] in _TWO_LABEL_TLDS and labels[-2] in _SECOND_LEVELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def match_score(page_host: str, candidate: str) -> int:
    """Score one candidate host against the page's host (0 = no match, higher = better).

    ``100`` exact, ``95`` the candidate is a parent domain of the page (``accounts.google.com``
    vs ``google.com``), ``90`` same registrable domain, ``80`` the candidate is a subdomain of
    the page's host (``gist.github.com`` vs ``github.com``).
    """
    page = normalize_host(page_host)
    other = normalize_host(candidate)
    if not page or not other:
        return 0
    if page == other:
        return 100
    if page.endswith("." + other):
        return 95
    if registrable_domain(page) == registrable_domain(other):
        return 90
    if other.endswith("." + page):
        return 80
    return 0


def build_body(
    *,
    site: str,
    category: str = "",
    username: str = "",
    password: str = "",
    url: str = "",
    otp: str = "",
    notes: str = "",
) -> str:
    """Build a standard credential entry body — the format :func:`parse_body` reads back.

    Empty fields are left out instead of written blank: a blank ``گذرواژه:`` line would read as "this
    entry has no password", which is exactly what a half-filled form must not claim.
    """
    title = (site or "").strip() or "ورودی رمز"
    head = [f"سایت: {title}"]
    if category.strip():
        head.append(f"دسته: {category.strip()}")
    lines = [f"# {title}", " | ".join(head)]
    if username.strip():
        lines.append(f"نام کاربری: {username.strip()}")
    if password:
        lines.append(f"گذرواژه: {password}")
    if url.strip():
        lines.append(f"آدرس: {url.strip()}")
    if otp.strip():
        lines.append(f"کد یکبارمصرف: {otp.strip()}")
    lines.append("")
    lines.append("## یادداشت")
    if notes.strip():
        lines.append(notes.strip())
    return "\n".join(lines) + "\n"


#: Persian/Arabic-Indic digits, so a number typed on a Persian keyboard is stored as ASCII.
_DIGIT_MAP = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")


def digits_only(value: str) -> str:
    """Return a card/account number as plain digits (Persian digits and separators removed)."""
    text = (value or "").translate(_DIGIT_MAP)
    return "".join(char for char in text if char.isdigit())


#: One-line card spellings the KeePass migration produced (a bare number line, `cvv2 3001`, `exp 10/07`).
_FREEFORM_CVV = re.compile(r"^\s*(?:cvv2?|cvc|cv2|کد\s*امنیتی)\D{0,3}(\d{3,4})\s*$", re.IGNORECASE)
_FREEFORM_EXP = re.compile(
    r"^\s*(?:exp(?:iry|ires)?|تاریخ\s*انقضا|انقضا)\D{0,3}([0-9۰-۹]{1,2}\s*[/\-.]\s*[0-9۰-۹]{1,2})\s*$",
    re.IGNORECASE,
)
_FREEFORM_PIN = re.compile(
    r"^\s*(?:pin2?|رمز\s*دوم|رمز\s*اینترنتی|رمز)\D{0,3}(\d{3,10})\s*$", re.IGNORECASE
)
_FREEFORM_SHEBA = re.compile(r"^\s*IR\s*([0-9]{24})\s*$", re.IGNORECASE)
_FREEFORM_BANK = re.compile(r"^\s*(?:بانک|bank)\s*[:：]\s*(.+?)\s*$", re.IGNORECASE)
_FREEFORM_HOLDER = re.compile(
    r"^\s*(?:صاحب\s*حساب|نام\s*دارنده|card\s*holder|holder)\s*[:：]?\s*(.+?)\s*$", re.IGNORECASE
)


def card_from_text(text: str) -> dict[str, str]:
    """Read a card out of a free-form body (the migrated one-liner shape, no Persian labels).

    The KeePass importer kept a card as its own lines — a bare 16-digit number, ``cvv2 3001``,
    ``exp 10/07``, ``pin 6086``, ``IR…`` — so a label-only parser sees nothing at all. This reads
    that shape; it is only ever used for a body that lives in the card folder.
    """
    card = {field: "" for field, _label in CARD_FIELDS}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _FREEFORM_CVV.match(line)
        if match and not card["cvv2"]:
            card["cvv2"] = match.group(1)
            continue
        match = _FREEFORM_EXP.match(line)
        if match and not card["expiry"]:
            card["expiry"] = match.group(1).replace("-", "/").replace(".", "/").replace(" ", "")
            continue
        match = _FREEFORM_SHEBA.match(line)
        if match and not card["sheba"]:
            card["sheba"] = "IR" + match.group(1)
            continue
        match = _FREEFORM_PIN.match(line)
        if match and not card["pin2"]:
            card["pin2"] = match.group(1)
            continue
        match = _FREEFORM_BANK.match(line)
        if match and not card["bank"]:
            card["bank"] = match.group(1)
            continue
        match = _FREEFORM_HOLDER.match(line)
        if match and not card["holder"]:
            card["holder"] = match.group(1)
            continue
        digits = digits_only(line)
        letters = any(char.isalpha() for char in line)
        if not letters and not card["number"] and 16 <= len(digits) <= 19:
            card["number"] = digits
    return card


def parse_entry(
    text: str,
    *,
    logical: str = "",
    fallback_title: str = "",
    fallback_site: str = "",
) -> dict[str, Any]:
    """Parse one entry body; inside the card folder a free-form body still counts as a card."""
    parsed = parse_body(text, fallback_title=fallback_title, fallback_site=fallback_site)
    folder = logical.split("/")
    if not parsed["is_card"] and logical.startswith(f"{CREDENTIAL_ROOT}/{CARD_CATEGORY}/"):
        free = card_from_text(text)
        if free["number"] or free["sheba"]:
            parsed["card"] = free
            parsed["is_card"] = True
    # The migrated cards name the bank by their folder (``…/بانک و پرداخت/بانک ملی/x.md``): when the
    # body itself says nothing, that folder is what the panel should show.
    if parsed["is_card"] and not (parsed["card"] or {}).get("bank") and len(folder) >= 4:
        name = folder[2]
        if name and name != CARD_CATEGORY:
            parsed["card"]["bank"] = name
    return parsed


def build_card_body(
    *,
    bank: str = "",
    number: str = "",
    expiry: str = "",
    cvv2: str = "",
    pin2: str = "",
    account: str = "",
    sheba: str = "",
    holder: str = "",
    notes: str = "",
) -> str:
    """Build a Shetab (bank card) entry in the credential shape — :func:`parse_body` reads it back.

    It is the same ``# title`` / ``سایت: … | دسته: …`` / ``label: value`` body a login uses, so the
    viewer, the search index and the phone need no second format. A card carries no password, so
    the browser bridge never offers it: only a *nickname* for the card is derived from its last four
    digits, and every value is written only when it was filled in.
    """
    digits = digits_only(number)
    title = (bank or "").strip()
    if digits:
        title = f"{title} — کارت {digits[-4:]}" if title else f"کارت {digits[-4:]}"
    title = title or "کارت بانکی"
    values = (
        ("بانک", (bank or "").strip()),
        ("شماره کارت", digits),
        ("تاریخ انقضا", (expiry or "").strip()),
        ("CVV2", digits_only(cvv2)),
        ("رمز دوم", (pin2 or "").strip()),
        ("شماره حساب", digits_only(account)),
        ("شبا", (sheba or "").strip().upper().replace(" ", "")),
        ("صاحب حساب", (holder or "").strip()),
    )
    lines = [f"# {title}", f"سایت: {title} | دسته: {CARD_CATEGORY}"]
    lines.extend(f"{label}: {value}" for label, value in values if value)
    lines.extend(["", "## یادداشت"])
    if notes.strip():
        lines.append(notes.strip())
    return "\n".join(lines) + "\n"


def credential_path(site: str, category: str = "") -> str:
    """Where a new entry goes: ``/رمزها/<دسته>/<سایت>.md``, with no path separators smuggled in.

    The leading ``/`` is the app's absolute path form (the same shape the browser panel shows and
    ``write_file`` accepts); ``CREDENTIAL_ROOT`` itself stays slash-less because the vault's index
    rows and the browser bridge name folders without one.
    """
    folder = (category or "").strip() or "عمومی"
    name = (site or "").strip() or "ورودی رمز"
    return f"/{CREDENTIAL_ROOT}/{folder.replace('/', '-')}/{name.replace('/', '-')}.md"


def parse_body(text: str, *, fallback_title: str = "", fallback_site: str = "") -> dict[str, Any]:
    """Parse one credential body into its fields.

    Returns a dict with ``title``, ``site``, ``category``, ``username``, ``password``, ``url``,
    ``otp``, ``has_password``, ``has_otp`` and ``hosts`` (every host-like value found). Nothing
    is ever logged here.
    """
    title = ""
    fallback = _clean(fallback_title)
    fields: dict[str, str] = {}
    in_notes = False
    heading_seen = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(SECTION_MARKERS):
            in_notes = True
            continue
        if in_notes:
            continue
        if line.startswith("#"):
            # The file's own first heading is the entry's name; the file name is only a fallback
            # (a heading must win over it, otherwise the add-on's list shows file names).
            if not heading_seen:
                heading_seen = True
                title = _clean(line.lstrip("#").strip()) or title
            continue
        for segment in line.split("|"):
            if ":" not in segment:
                continue
            key, value = segment.split(":", 1)
            key = _clean(key).lower()
            value = _clean(value)
            if key and key not in fields:
                fields[key] = value

    def first_of(labels: tuple[str, ...]) -> str:
        """Return the first present value among ``labels`` (case-insensitive)."""
        for label in labels:
            value = fields.get(label.lower())
            if value:
                return value
        return ""

    def by_keyword(keywords: tuple[str, ...]) -> str:
        """Return the first value whose key contains one of ``keywords``."""
        for key, value in fields.items():
            if value and any(word in key for word in keywords):
                return value
        return ""

    site = first_of(SITE_LABELS) or _clean(fallback_site)
    category = first_of(CATEGORY_LABELS)
    username = first_of(USERNAME_LABELS) or by_keyword(("username", "user name", "نام کاربری", "email", "ایمیل"))
    password = first_of(PASSWORD_LABELS) or by_keyword(("password", "pass", "گذرواژه", "رمز عبور"))
    url = first_of(URL_LABELS) or by_keyword(("url", "آدرس", "نشانی", "website"))
    otp = first_of(OTP_LABELS) or by_keyword(("otp", "totp", "2fa", "یکبارمصرف", "یک بار مصرف"))
    hosts = [
        host
        for host in (
            normalize_host(url),
            normalize_host(site),
            normalize_host(title),
            normalize_host(fallback),
        )
        if host
    ]
    seen: dict[str, None] = {}
    for host in hosts:
        seen.setdefault(host, None)
    # A Shetab card lives in the same body shape, so one parser reads both: the card fields are
    # simply reported next to the login ones (a card has no password, so the bridge ignores it).
    card = {field: first_of(aliases) for field, aliases in CARD_LABEL_ALIASES.items()}
    return {
        "title": title or fallback,
        "site": site,
        "category": category,
        "username": username,
        "password": password,
        "url": url,
        "otp": otp,
        "has_password": bool(password),
        "has_otp": bool(otp),
        "hosts": list(seen),
        "card": card,
        "is_card": bool(card["number"] or card["sheba"] or card["cvv2"]),
    }


# ---------------------------------------------------------------------------- writing
def safe_name(value: str, *, fallback: str = "", limit: int = 80) -> str:
    """Return ``value`` as a file/folder name (safe, non-empty when a fallback is given).

    The add-on never supplies a path — only the host, the user name and the page title — so the
    vault builds every name itself. This is the one place that turns a page-supplied string into
    part of a path, hence the strict character set and the length cap.
    """
    text = _UNSAFE_NAME.sub(" ", _clean(value))
    text = text.replace("..", " ")
    text = re.sub(r"\s+", " ", text).strip(" .")
    if len(text) > limit:
        text = text[:limit].rstrip(" .")
    return text or _clean(fallback)


def storable(value: str) -> bool:
    """Return True when ``value`` can live inside a line-based credential body."""
    return not _UNSAFE_VALUE.search(value or "")


def render_body(
    *,
    title: str,
    site: str = "",
    category: str = "",
    username: str = "",
    password: str = "",
    url: str = "",
    otp: str = "",
) -> str:
    """Render one credential body exactly in the shape ``tools/keepass-migration`` writes."""
    head = _clean(title) or _clean(site) or "ورود"
    lines = [f"# {head}", ""]
    meta = []
    if site:
        meta.append(f"{SITE_LABELS[0]}: {site}")
    if category:
        meta.append(f"{CATEGORY_LABELS[0]}: {category}")
    if meta:
        lines += [" | ".join(meta), ""]
    lines.append(f"{USERNAME_LABELS[0]}: {_clean(username) or '—'}")
    lines.append(f"{PASSWORD_LABELS[0]}: {password}" if password else f"{PASSWORD_LABELS[0]}: —")
    if url:
        lines.append(f"{URL_LABELS[0]}: {url}")
    if otp:
        lines.append(f"{OTP_LABELS[0]}: {otp}")
    return "\n".join(lines).rstrip() + "\n"


def set_field(text: str, labels: tuple[str, ...], value: str) -> str:
    """Return ``text`` with the ``label: value`` line of ``labels`` replaced by ``value``.

    Everything else stays byte-for-byte as it was: the heading, the meta line, the other fields
    and the ``##`` notes section. Updating a password must never destroy what the entry's owner
    wrote into that file — the password line is the *only* thing a browser-saved update touches.
    A missing line is inserted after the meta line (or after the heading when there is none).
    """
    wanted = {label.lower() for label in labels}
    out: list[str] = []
    in_notes = False
    replaced = False
    anchor: int | None = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith(SECTION_MARKERS):
            in_notes = True
        if not in_notes and line and not line.startswith("#") and ":" in line:
            key = line.split(":", 1)[0].strip()
            if not replaced and key.lower() in wanted:
                out.append(f"{key}: {value}")
                replaced = True
                continue
            if anchor is None:
                anchor = len(out)          # right after the first field line (the meta line)
        out.append(raw)
    if not replaced:
        if anchor is None:
            anchor = 0
            for index, raw in enumerate(out):
                if raw.strip().startswith("#"):
                    anchor = index + 1
            while anchor < len(out) and not out[anchor].strip():
                anchor += 1
        out.insert(anchor, f"{labels[0]}: {value}")
    return "\n".join(out).rstrip() + "\n"


@dataclass(frozen=True)
class CredentialEntry:
    """One credential file, metadata only — never a password."""

    path: str
    title: str
    site: str
    url: str
    username: str
    has_password: bool
    has_otp: bool
    hosts: tuple[str, ...] = ()
    category: str = ""
    #: The card fields of a Shetab entry (``{"bank", "number", "expiry", "cvv2", "pin2", …}``),
    #: or ``None`` for a login. The full number stays here — :meth:`card_meta` is what leaves the
    #: vault, and it carries only the bank and the last four digits.
    card: dict[str, Any] | None = None

    def to_dict(self, *, score: int = 0) -> dict[str, Any]:
        """Return the caller-facing (password-free) representation."""
        return {
            "path": self.path,
            "title": self.title,
            "site": self.site,
            "url": self.url,
            "username": self.username,
            "has_password": self.has_password,
            "has_otp": self.has_otp,
            "score": int(score),
        }

    def card_meta(self) -> dict[str, Any]:
        """Return the password-free description of a card entry (bank, last four digits, fields)."""
        card = self.card or {}
        return {
            "path": self.path,
            "title": self.title,
            "bank": card.get("bank", ""),
            "last4": (card.get("number") or "")[-4:],
            "holder": card.get("holder", ""),
            "has_expiry": bool(card.get("expiry")),
            "has_cvv2": bool(card.get("cvv2")),
            "has_pin2": bool(card.get("pin2")),
            "has_sheba": bool(card.get("sheba")),
        }


@dataclass
class CredentialIndex:
    """A lazily (re)built, metadata-only index of the credential tree.

    ``entries()`` builds on first use and rebuilds when the tree's signature changes (a file
    added, removed, moved or edited) or when the cache is older than ``ttl_seconds``. The build
    reads every credential body once; the caller is expected to silence the per-file audit rows
    of that internal scan (see ``api/browser.py``) — only the reveal is audited.
    """

    session: Any
    root: str = CREDENTIAL_ROOT
    ttl_seconds: float = 300.0
    _entries: list[CredentialEntry] = field(default_factory=list, init=False, repr=False)
    _signature: tuple[int, int, int] | None = field(default=None, init=False, repr=False)
    _built_ms: int = field(default=0, init=False, repr=False)
    _files: int = field(default=0, init=False, repr=False)
    _scanned: int = field(default=0, init=False, repr=False)

    # ------------------------------------------------------------------- signature
    def _rows(self) -> list[dict[str, Any]]:
        """Return every index row at or below the credential root (metadata only)."""
        try:
            rows = list(self.session.index.walk(self.root))
        except Exception:  # noqa: BLE001 - a missing root simply means "no credentials yet"
            return []
        prefix = self.root + "/"
        return [
            row
            for row in rows
            if row["logical_path"] == self.root or str(row["logical_path"]).startswith(prefix)
        ]

    def signature(self) -> tuple[int, int, int]:
        """Return the cheap freshness signature of the credential tree."""
        rows = self._rows()
        files = [row for row in rows if not int(row.get("is_dir", 0))]
        mtime = max([int(row.get("mtime", 0)) for row in rows], default=0)
        return (len(files), len(rows) - len(files), mtime)

    def is_fresh(self, *, now_ms: int | None = None) -> bool:
        """Return True when the cached index still matches the tree and its TTL."""
        if self._signature is None:
            return False
        stamp = now_ms if now_ms is not None else _now_ms()
        if self.ttl_seconds and stamp - self._built_ms > int(self.ttl_seconds * 1000):
            return False
        return self._signature == self.signature()

    # ----------------------------------------------------------------------- build
    def build(self, *, force: bool = False) -> dict[str, Any]:
        """Rebuild the index when needed and return its status dict."""
        if not force and self.is_fresh():
            return self.status()
        rows = [row for row in self._rows() if not int(row.get("is_dir", 0))]
        entries: list[CredentialEntry] = []
        scanned = 0
        for row in rows:
            logical = str(row["logical_path"])
            parent = logical.rsplit("/", 1)[0] if "/" in logical else ""
            fallback_site = parent.rsplit("/", 1)[-1] if parent and parent != self.root else ""
            try:
                data = self.session.read_file("/" + logical, source=_browser_source())
                text = data.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - one unreadable entry must not kill the index
                continue
            scanned += 1
            parsed = parse_entry(
                text, logical=logical, fallback_title=_stem(logical), fallback_site=fallback_site
            )
            entries.append(
                CredentialEntry(
                    path="/" + logical,
                    title=parsed["title"] or _stem(logical),
                    site=parsed["site"],
                    url=parsed["url"],
                    username=parsed["username"],
                    has_password=parsed["has_password"],
                    has_otp=parsed["has_otp"],
                    hosts=tuple(parsed["hosts"]),
                    category=parsed["category"],
                    card=dict(parsed["card"]) if parsed["is_card"] else None,
                )
            )
        entries.sort(key=lambda item: item.path)
        self._entries = entries
        self._scanned = scanned
        self._files = len(rows)
        self._signature = self.signature()
        self._built_ms = _now_ms()
        return self.status()

    # ----------------------------------------------------------------------- query
    def entries(self, *, force: bool = False) -> list[CredentialEntry]:
        """Return the current entries, rebuilding first when the cache is stale."""
        self.build(force=force)
        return list(self._entries)

    def match(self, host: str, *, limit: int = 25, force: bool = False) -> list[dict[str, Any]]:
        """Return the entries for ``host``, best match first (metadata only)."""
        page = normalize_host(host)
        if not page:
            return []
        scored: list[tuple[int, CredentialEntry]] = []
        for entry in self.entries(force=force):
            score = max((match_score(page, candidate) for candidate in entry.hosts), default=0)
            if score:
                scored.append((score, entry))
        scored.sort(key=lambda item: (-item[0], not item[1].username, item[1].title.lower(), item[1].path))
        return [entry.to_dict(score=score) for score, entry in scored[: max(1, int(limit))]]

    def cards(self) -> list[dict[str, Any]]:
        """Return every card entry of the index, metadata only (no number, no CVV2, no PIN2)."""
        return [entry.card_meta() for entry in self.entries() if entry.card]

    def search(self, query: str, *, limit: int = 50) -> list[dict[str, Any]]:
        """Return ``[{"path", "fields"}]`` for entries whose *fields* match ``query``.

        Only what a :class:`CredentialEntry` keeps is matched — a password can never be found
        here, which is also why the caller gets field names and a path, never a value.
        """
        needle = normalize_fa(query).casefold()
        tokens = [token.casefold() for token in needle.split(" ") if token]
        if not tokens:
            return []
        hits: list[dict[str, Any]] = []
        for entry in self.entries():
            matched = [
                name
                for name in SEARCHABLE_FIELDS
                if (folded := normalize_fa(str(getattr(entry, name) or "")).casefold())
                and (needle in folded or all(token in folded for token in tokens))
            ]
            if matched:
                hits.append({"path": entry.path, "fields": matched})
            if len(hits) >= max(1, int(limit)):
                break
        return hits

    def status(self) -> dict[str, Any]:
        """Return a small, honest description of the index state."""
        return {
            "root": self.root,
            "ready": self._signature is not None,
            "entries": len(self._entries),
            "files": self._files,
            "scanned": self._scanned,
            "built_at_ms": self._built_ms,
            "hosts": sum(1 for entry in self._entries if entry.hosts),
            "usernames": sum(1 for entry in self._entries if entry.username),
            "passwords": sum(1 for entry in self._entries if entry.has_password),
        }


def _stem(logical: str) -> str:
    """Return the file stem of a logical path."""
    name = logical.rsplit("/", 1)[-1]
    return name[:-3] if name.lower().endswith(".md") else name


@contextlib.contextmanager
def quiet_scan(session: Any) -> Iterator[None]:
    """Silence the per-file audit rows of a bulk metadata scan.

    Reading every credential file to build the index is internal bookkeeping: it must not write
    one access-log row per entry (that is what the reveal is for) nor one activity event per
    entry. Both flags are already the codebase's mechanism for exactly this (``_suppress_log``
    is what :meth:`Service.dispatch` sets around its own single row); a reveal runs outside
    this context and is always audited.
    """
    previous_log = bool(getattr(session, "_suppress_log", False))
    previous_activity = bool(getattr(session, "_suppress_activity", False))
    session._suppress_log = True
    session._suppress_activity = True
    try:
        yield
    finally:
        session._suppress_log = previous_log
        session._suppress_activity = previous_activity


def _browser_source() -> str:
    """Return the policy ``source`` used for the index's own reads."""
    from .security import SOURCE_BROWSER  # noqa: PLC0415 - avoids an import cycle at module load

    return SOURCE_BROWSER


def _now_ms() -> int:
    """Return the current epoch in milliseconds."""
    from ..util import now_ms  # noqa: PLC0415 - keeps this module import-light

    return now_ms()


__all__ = [
    "BROWSER_CATEGORY",
    "CARD_CATEGORY",
    "CARD_FIELDS",
    "CREDENTIAL_ROOT",
    "CredentialEntry",
    "CredentialIndex",
    "build_card_body",
    "card_from_text",
    "digits_only",
    "parse_entry",
    "match_score",
    "normalize_host",
    "parse_body",
    "registrable_domain",
    "render_body",
    "quiet_scan",
    "safe_name",
    "set_field",
    "storable",
]
