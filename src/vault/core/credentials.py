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

import re
from dataclasses import dataclass, field
from typing import Any

#: The vault folder holding the migrated credential entries.
CREDENTIAL_ROOT = "رمزها"

#: Value written for an empty field.
EMPTY_MARKERS = frozenset({"", "—", "-", "–", "n/a", "none", "null"})

#: Label spellings accepted for each field (first present wins, in this order).
USERNAME_LABELS = ("نام کاربری", "نامکاربری", "نام کاربری/ایمیل", "یوزرنیم", "username", "user name", "user", "login")
PASSWORD_LABELS = ("گذرواژه", "گذر واژه", "رمز عبور", "پسورد", "password", "pass")
URL_LABELS = ("آدرس", "نشانی", "آدرس سایت", "url", "website", "web site", "site url", "link")
SITE_LABELS = ("سایت", "وبسایت", "site")
CATEGORY_LABELS = ("دسته", "دسته بندی", "category", "group")
OTP_LABELS = ("کد یکبارمصرف", "کد یک بار مصرف", "کد یکبار مصرف", "otp", "totp", "2fa", "2fa code")

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
    }


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
            parsed = parse_body(text, fallback_title=_stem(logical), fallback_site=fallback_site)
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


def _browser_source() -> str:
    """Return the policy ``source`` used for the index's own reads."""
    from .security import SOURCE_BROWSER  # noqa: PLC0415 - avoids an import cycle at module load

    return SOURCE_BROWSER


def _now_ms() -> int:
    """Return the current epoch in milliseconds."""
    from ..util import now_ms  # noqa: PLC0415 - keeps this module import-light

    return now_ms()


__all__ = [
    "CREDENTIAL_ROOT",
    "CredentialEntry",
    "CredentialIndex",
    "match_score",
    "normalize_host",
    "parse_body",
    "registrable_domain",
]
