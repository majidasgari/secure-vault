"""The browser-autofill bridge: a narrow credential surface for a browser add-on.

The Firefox add-on talks to this bridge over the **loopback** HTTP API (the browser cannot read
``web.token`` from the snap-sandboxed profile, and a native-messaging host spawned by the snap
browser cannot reach ``/data`` or ``/run/user/…`` at all), so the bridge owns its own token:
``runtime_dir()/browser.token`` (mode ``0600``), handed out only by the loopback ``claim`` flow.

What the token buys is deliberately small. The ``browser`` role's method table in
:mod:`vault.api.service` holds five methods — ``vault.browser_status``, ``vault.browser_match``,
``vault.browser_reveal``, ``vault.browser_save_check`` and ``vault.browser_save`` — so a browser
(or anything else holding this token) can never call ``vault.read_file``, ``vault.write_file`` or
any other command, and every path it *can* name has to live under the credential root. Matching
answers metadata only; a reveal returns the fields of **one already-matched entry** and is always
audited (one access-log row with ``source="browser"`` plus one activity event, so the tray shows
it).

Saving is the one write this bridge owns, and it is as small as the read: the add-on may propose
a credential it just watched the user type (host, user name, password, page title — never a path
of its own choosing) and the vault decides what that means. ``save_check`` only reports the
verdict — ``new`` (no entry for this host + user name), ``changed`` (that user name holds another
password) or ``same`` — so a *successful login with the stored password* writes nothing at all.
``save`` then either rewrites the ``گذرواژه`` line of exactly that one entry (leaving every other
line, including the notes, untouched) or creates a new ``secretfile`` in the browser category.
Both are refused while the vault is locked, while the bridge or the saving switch is off, past a
per-minute limit, and for a value a line-based body cannot hold.

The bridge never logs a password and never returns one to a caller that did not name the entry.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Iterator

from .. import __version__
from ..config import runtime_dir as default_runtime_dir
from ..core.credentials import (
    BROWSER_CATEGORY,
    CREDENTIAL_ROOT,
    PASSWORD_LABELS,
    USERNAME_LABELS,
    CredentialIndex,
    match_score,
    normalize_host,
    parse_body,
    render_body,
    safe_name,
    set_field,
    storable,
)
from ..core.security import SOURCE_BROWSER
from ..errors import BadRequest, PermissionDenied, VaultLocked
from ..util import atomic_write_bytes, normalize_vault_path, now_ms

LOG = logging.getLogger(__name__)

#: Token file name inside the runtime directory (``0600``, like ``web.token``).
TOKEN_FILENAME = "browser.token"

#: Reveals allowed per rolling minute; a loop asking for far more than a human can click is
#: either a broken client or a page scraping the vault through a compromised extension.
REVEALS_PER_MINUTE = 40

#: ``save_check`` lookups allowed per rolling minute (one per real login attempt, at most).
CHECKS_PER_MINUTE = 30

#: Saves allowed per rolling minute — writing to the vault is the most consequential call here.
SAVES_PER_MINUTE = 12

#: Default and maximum number of candidates a match call returns.
DEFAULT_LIMIT = 25
MAX_LIMIT = 100

#: Longest values the bridge will store (a login form cannot make the vault grow without bound).
MAX_USERNAME = 256
MAX_PASSWORD = 512
MAX_TITLE = 200
MAX_URL = 1024
MAX_PATH = 512

#: Note texts the vault's own convention asks for (what it is + when to reach for it).
FOLDER_NOTE = (
    "**«{host}» — زیرپوشهٔ دستهٔ «مرورگر — ورودهای ذخیره‌شده».** ورودهایی که از مرورگر "
    "ذخیره شده‌اند.\n\nکی استفاده شود: وقتی گذرواژه یا نام کاربری {host} لازم شد."
)
FILE_NOTE = (
    "ورود «{host}» که از مرورگر ذخیره شده — نام کاربری و گذرواژه. برای دیدن مقدار "
    "(کپی نام کاربری/گذرواژه) همین فایل را باز کن."
)


@contextlib.contextmanager
def quiet_scan(session: Any) -> Iterator[None]:
    """Silence the per-file audit rows of the bridge's bulk metadata scan.

    Reading every credential file to build the index is internal bookkeeping: it must not write
    one access-log row per entry (that is what the reveal is for) nor one activity event per
    entry. Both flags are already the codebase's mechanism for exactly this (``_suppress_log``
    is what :meth:`Service.dispatch` sets around its own single row); the reveal runs outside
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


class BrowserBridge:
    """Owns the browser token, the credential index and the two credential commands."""

    def __init__(
        self,
        service: Any,
        *,
        runtime_dir: Path | str | None = None,
        token: str | None = None,
        index: CredentialIndex | None = None,
        reveal_limit: int = REVEALS_PER_MINUTE,
        check_limit: int = CHECKS_PER_MINUTE,
        save_limit: int = SAVES_PER_MINUTE,
        clock: Any = time.monotonic,
    ) -> None:
        """Bind the bridge to ``service``; nothing is created until :meth:`start`."""
        self.service = service
        self.runtime_dir = (
            Path(runtime_dir) if runtime_dir is not None else default_runtime_dir()
        )
        self.token = token or secrets.token_hex(32)
        self.token_file = self.runtime_dir / TOKEN_FILENAME
        self.index = index if index is not None else CredentialIndex(service.session)
        self.reveal_limit = max(1, int(reveal_limit))
        self.check_limit = max(1, int(check_limit))
        self.save_limit = max(1, int(save_limit))
        self._clock = clock
        self._reveals: deque[float] = deque()
        self._checks: deque[float] = deque()
        self._saves: deque[float] = deque()
        self._lock = threading.RLock()
        self._started = False
        self.started_ms = 0

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Write the token file (``0600``); safe to call twice."""
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.runtime_dir, 0o700)
        except OSError:  # pragma: no cover - best effort on exotic filesystems
            pass
        payload = json.dumps(
            {"token": self.token, "created_at": now_ms()}, ensure_ascii=False
        ).encode("utf-8")
        atomic_write_bytes(self.token_file, payload)
        try:
            os.chmod(self.token_file, 0o600)
        except OSError:  # pragma: no cover - best effort
            pass
        self._started = True
        self.started_ms = now_ms()

    def stop(self) -> None:
        """Remove the token file (best effort) — a stopped bridge cannot be talked to."""
        self._started = False
        try:
            self.token_file.unlink()
        except FileNotFoundError:
            pass

    @property
    def session(self) -> Any:
        """The vault session the bridge serves."""
        return self.service.session

    # ------------------------------------------------------------------- settings
    def settings(self) -> dict[str, Any]:
        """Return the ``browser`` settings block (empty when the vault cannot be read)."""
        try:
            raw = self.session.meta.settings.get("browser")
        except Exception:  # noqa: BLE001 - a locked/absent vault uses the defaults
            return {}
        return dict(raw) if isinstance(raw, dict) else {}

    def enabled(self) -> bool:
        """Whether browser autofill is switched on (default: on)."""
        return bool(self.settings().get("enabled", True))

    def save_enabled(self) -> bool:
        """Whether the add-on may *offer to save* a credential it saw the user type (default: on)."""
        return bool(self.settings().get("save_enabled", True))

    def _require_usable(self) -> None:
        """Raise when the bridge is switched off or the vault is locked."""
        if not self.enabled():
            raise PermissionDenied("browser_autofill_disabled")
        if self.session.is_locked:
            raise VaultLocked("vault_locked")

    def _require_saving(self) -> None:
        """Raise when this vault may not accept a credential from the browser at all."""
        self._require_usable()
        if not self.save_enabled():
            raise PermissionDenied("browser_save_disabled")

    # ---------------------------------------------------------------- rate limiting
    def _note(self, bucket: deque[float], limit: int, code: str) -> None:
        """Record one call in ``bucket`` and refuse it when the rolling limit is exhausted."""
        with self._lock:
            stamp = self._clock()
            while bucket and stamp - bucket[0] > 60.0:
                bucket.popleft()
            if len(bucket) >= limit:
                raise PermissionDenied(
                    code, details={"limit": limit, "window_seconds": 60}
                )
            bucket.append(stamp)

    def _note_reveal(self) -> None:
        """Record one reveal and refuse the call when the rolling limit is exhausted."""
        self._note(self._reveals, self.reveal_limit, "too_many_reveals")

    def _note_check(self) -> None:
        """Record one ``save_check`` and refuse the call when the rolling limit is exhausted."""
        self._note(self._checks, self.check_limit, "too_many_checks")

    def _note_save(self) -> None:
        """Record one save and refuse the call when the rolling limit is exhausted."""
        self._note(self._saves, self.save_limit, "too_many_saves")

    def _recent(self, bucket: deque[float]) -> int:
        """Return how many calls of ``bucket`` happened in the last rolling minute."""
        with self._lock:
            stamp = self._clock()
            while bucket and stamp - bucket[0] > 60.0:
                bucket.popleft()
            return len(bucket)

    def reveals_last_minute(self) -> int:
        """Return how many reveals happened in the last rolling minute."""
        return self._recent(self._reveals)

    def saves_last_minute(self) -> int:
        """Return how many saves happened in the last rolling minute."""
        return self._recent(self._saves)

    # ---------------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        """Return the bridge state the add-on shows in its popup (metadata only).

        Works while locked (the add-on needs to say *why* it cannot fill); the index numbers are
        withheld in that case, exactly like the rest of the app withholds counts while locked.
        """
        locked = bool(self.session.is_locked)
        data: dict[str, Any] = {
            "enabled": self.enabled(),
            "save_enabled": self.save_enabled(),
            "locked": locked,
            "started": self._started,
            "started_ms": self.started_ms,
            "root": "/" + CREDENTIAL_ROOT,
            "app_version": __version__,
            "reveals_last_minute": self.reveals_last_minute(),
            "reveal_limit": self.reveal_limit,
            "saves_last_minute": self.saves_last_minute(),
            "save_limit": self.save_limit,
        }
        if not locked and self.enabled():
            # Build (when stale) so the popup can show an honest entry count instead of "0"
            # right after the app started. The scan reads metadata only and audits nothing.
            with quiet_scan(self.session):
                data["index"] = self.index.build()
        return data

    # ----------------------------------------------------------------------- match
    def match(self, host: str, *, url: str | None = None, limit: int | None = None) -> dict[str, Any]:
        """Return the credential candidates for one page (metadata only, never a password).

        Raises:
            PermissionDenied: when autofill is switched off.
            VaultLocked: when the vault is locked.
            BadRequest: when no usable host was supplied.
        """
        self._require_usable()
        page = normalize_host(host) or normalize_host(url or "")
        if not page:
            raise BadRequest("missing_host")
        try:
            value = int(limit) if limit is not None else DEFAULT_LIMIT
        except (TypeError, ValueError):
            value = DEFAULT_LIMIT
        value = max(1, min(MAX_LIMIT, value))
        with quiet_scan(self.session):
            self.index.build()
            candidates = self.index.match(page, limit=value)
        return {
            "host": page,
            "url": url or "",
            "count": len(candidates),
            "candidates": candidates,
            "index": self.index.status(),
            "ts": now_ms(),
        }

    # ---------------------------------------------------------------------- reveal
    def reveal(self, path: str, *, host: str | None = None, session_id: str = "") -> dict[str, Any]:
        """Return the fields of one credential entry (the only call that yields a password).

        The entry must live under the credential root and, when ``host`` is supplied (the add-on
        always supplies it), it must actually match that host — so a page can only ever receive
        an entry that belongs to it.

        Raises:
            PermissionDenied: autofill off, path outside the credential root, a host mismatch or
                too many reveals in the last minute.
            VaultLocked: the vault is locked.
            NotFound: no such entry.
        """
        self._require_usable()
        logical = normalize_vault_path(path)
        if not self._in_root(logical):
            raise PermissionDenied(
                "path_outside_credentials",
                details={"path": "/" + logical if logical else path, "root": "/" + CREDENTIAL_ROOT},
            )
        row = self.session.index.require_file(logical)
        if int(row.get("is_dir", 0)):
            raise BadRequest("is_directory", details={"path": "/" + logical})
        self._note_reveal()
        data = self.session.read_file("/" + logical, source=SOURCE_BROWSER, session=session_id)
        parsed = parse_body(
            data.decode("utf-8", errors="replace"),
            fallback_title=logical.rsplit("/", 1)[-1],
            fallback_site=(logical.rsplit("/", 1)[0] if "/" in logical else "").rsplit("/", 1)[-1],
        )
        page = normalize_host(host or "")
        if page:
            score = max((match_score(page, candidate) for candidate in parsed["hosts"]), default=0)
            if not score:
                raise PermissionDenied(
                    "host_mismatch", details={"host": page, "path": "/" + logical}
                )
        return {
            "path": "/" + logical,
            "title": parsed["title"],
            "site": parsed["site"],
            "username": parsed["username"],
            "password": parsed["password"],
            "otp": parsed["otp"],
            "url": parsed["url"],
            "has_password": parsed["has_password"],
            "has_otp": parsed["has_otp"],
            "ts": now_ms(),
        }

    # ----------------------------------------------------------------- save: check
    def save_check(
        self,
        host: str,
        *,
        username: str = "",
        password: str = "",
        url: str = "",
        title: str = "",
    ) -> dict[str, Any]:
        """Answer what saving this credential *would* mean — without writing anything.

        The add-on calls this right after a login looks successful. ``state`` is ``same`` when the
        entry that belongs to this host and user name already holds exactly this password (then
        nothing is written and the user is told so), ``changed`` when that entry holds another
        password, and ``new`` when no entry matches.

        Raises:
            PermissionDenied: the bridge or the saving switch is off, or too many checks a minute.
            VaultLocked: the vault is locked.
            BadRequest: no usable host, or a value too long to store.
        """
        self._require_saving()
        page = normalize_host(host) or normalize_host(url or "")
        if not page:
            raise BadRequest("missing_host")
        self._validate(username=username, password=password, title=title, url=url)
        self._note_check()
        with quiet_scan(self.session):
            entry, state = self._resolve(
                page, username=username, password=password, hint=""
            )
        return self._verdict(page, entry, state, username=username, title=title)

    # ------------------------------------------------------------------- save: write
    def save(
        self,
        host: str,
        *,
        username: str = "",
        password: str = "",
        url: str = "",
        title: str = "",
        path: str = "",
        session_id: str = "",
    ) -> dict[str, Any]:
        """Store one credential the add-on watched the user type.

        The target is chosen here, never by the caller: with ``path`` the entry must still be a
        credential of *this* host, otherwise the entry of this host whose user name matches (a new
        file in the browser category when none does). An update rewrites the ``گذرواژه`` line of
        that one file and nothing else. ``same`` writes nothing at all.

        Raises:
            PermissionDenied: saving is off, the path is outside the credential root or belongs to
                another host, or too many saves in the last minute.
            VaultLocked: the vault is locked.
            BadRequest: no usable host, no password, or a value too long/unsuitable to store.
        """
        self._require_saving()
        page = normalize_host(host) or normalize_host(url or "")
        if not page:
            raise BadRequest("missing_host")
        if not password:
            raise BadRequest("missing_password")
        self._validate(
            username=username, password=password, title=title, url=url, path=path
        )
        hint = normalize_vault_path(path) if path else ""
        if hint and not self._in_root(hint):
            raise PermissionDenied(
                "path_outside_credentials",
                details={"path": path, "root": "/" + CREDENTIAL_ROOT},
            )
        self._note_save()
        with quiet_scan(self.session):
            entry, state = self._resolve(
                page, username=username, password=password, hint=hint
            )
        if entry is not None and state == "same":
            # The vault already holds exactly this password: a save here would be a no-op write,
            # so it is reported as such (the add-on tells the user instead of pretending).
            return self._verdict(page, entry, "same", username=username, title=title)
        if entry is not None:
            body = set_field(self._read_text(entry.path), PASSWORD_LABELS, password)
            if not (entry.username or "").strip() and (username or "").strip():
                # Only an entry that has no user name at all takes the one that was typed: a
                # *different* user name is a different account, which is created next to it.
                body = set_field(body, USERNAME_LABELS, username)
            self.session.write_file(
                entry.path.lstrip("/"), body.encode("utf-8"), source=SOURCE_BROWSER
            )
            with quiet_scan(self.session):
                self.index.build(force=True)
            return self._verdict(page, entry, "updated", username=username, title=title, saved=True)
        logical = self._free_path(page)
        folder = logical.rsplit("/", 1)[0]
        existed = self.session.index.get_file(folder) is not None
        body = render_body(
            title=title or page,
            site=page,
            category=BROWSER_CATEGORY,
            username=username,
            password=password,
            url=url,
        )
        self.session.write_file(
            logical,
            body.encode("utf-8"),
            source=SOURCE_BROWSER,
            sensitivity="secretfile",
        )
        self._annotate(logical, page, folder_is_new=not existed)
        with quiet_scan(self.session):
            self.index.build(force=True)
        return self._verdict(
            page,
            None,
            "created",
            username=username,
            title=title,
            path="/" + logical,
            saved=True,
        )

    # -------------------------------------------------------------------- save: helpers
    def _validate(
        self,
        *,
        username: str = "",
        password: str = "",
        title: str = "",
        url: str = "",
        path: str = "",
    ) -> None:
        """Refuse a value the bridge will not store (too long, or breaking the line format)."""
        for name, value, limit in (
            ("username", username, MAX_USERNAME),
            ("password", password, MAX_PASSWORD),
            ("title", title, MAX_TITLE),
            ("url", url, MAX_URL),
            ("path", path, MAX_PATH),
        ):
            if value is None:
                continue
            if not isinstance(value, str):
                raise BadRequest("invalid_field", details={"field": name})
            if len(value) > limit:
                raise BadRequest("field_too_long", details={"field": name, "limit": limit})
        for name, value in (("username", username), ("password", password), ("title", title)):
            if value and not storable(value):
                # A newline (or another control character) would silently split the label line;
                # storing a *changed* password instead of the real one is worse than refusing.
                raise BadRequest("unstorable_value", details={"field": name})

    def _resolve(
        self, page: str, *, username: str, password: str, hint: str
    ) -> tuple[Any | None, str]:
        """Return ``(entry, state)`` for a credential submitted for ``page``.

        ``hint`` is the entry the add-on believes the user chose (the bar's "update this one");
        it is only honoured when that entry really is a credential of ``page``. Without it, the
        entry whose user name matches is meant — except when the page's entries carry exactly one
        user name-less credential, which is then the obvious target.
        """
        scored: list[tuple[int, Any]] = []
        for entry in self.entries():
            score = max((match_score(page, candidate) for candidate in entry.hosts), default=0)
            if score and entry.has_password:
                scored.append((score, entry))
        scored.sort(key=lambda item: (-item[0], item[1].path))
        entries = [entry for _, entry in scored]
        user = (username or "").strip().casefold()
        chosen = None
        if hint:
            chosen = next((entry for entry in entries if entry.path == "/" + hint), None)
            if chosen is None:
                raise PermissionDenied(
                    "path_not_for_host", details={"path": "/" + hint, "host": page}
                )
        elif user:
            chosen = next(
                (entry for entry in entries if (entry.username or "").strip().casefold() == user),
                None,
            )
        elif len(entries) == 1:
            chosen = entries[0]
        if chosen is None:
            return None, "new"
        state = "same" if self._read_password(chosen.path) == password else "changed"
        return chosen, state

    def _verdict(
        self,
        page: str,
        entry: Any | None,
        state: str,
        *,
        username: str = "",
        title: str = "",
        path: str = "",
        saved: bool = False,
    ) -> dict[str, Any]:
        """Shape the answer both save calls return (never a password, never another entry's)."""
        target = path or (entry.path if entry is not None else "/" + self._free_path(page))
        return {
            "host": page,
            "state": state,
            "saved": bool(saved),
            "path": target,
            "title": entry.title if entry is not None else (title or page),
            "site": entry.site if entry is not None else page,
            "username": entry.username if entry is not None else username,
            "has_otp": bool(entry.has_otp) if entry is not None else False,
            "ts": now_ms(),
        }

    def _free_path(self, page: str) -> str:
        """Return the logical path a *new* entry for ``page`` gets.

        The shape is the browser category's own: ``<دسته>/<سایت>/<سایت>.md``, then
        ``<سایت> (2).md`` and so on — exactly how the entries already in that category are named.
        """
        folder = safe_name(page, fallback="entry")
        stem = safe_name(folder, fallback="entry")
        base = f"{CREDENTIAL_ROOT}/{BROWSER_CATEGORY}/{folder}"
        index = 0
        while index < 200:                    # a page cannot make the vault spin forever
            name = f"{stem}.md" if not index else f"{stem} ({index + 1}).md"
            logical = f"{base}/{name}"
            if self.session.index.get_file(logical) is None:
                return logical
            index += 1
        raise BadRequest("too_many_entries", details={"path": "/" + base})

    def _read_text(self, path: str) -> str:
        """Read one credential body *inside* the vault (never handed back to the caller)."""
        with quiet_scan(self.session):
            data = self.session.read_file(path, source=SOURCE_BROWSER)
        return data.decode("utf-8", errors="replace")

    def _read_password(self, path: str) -> str:
        """Return one entry's stored password — used only for the same/changed verdict."""
        return parse_body(self._read_text(path))["password"]

    def _annotate(self, logical: str, page: str, *, folder_is_new: bool) -> None:
        """Give a new entry (and a folder the vault just created) the convention's one-line note."""
        if folder_is_new:
            folder = logical.rsplit("/", 1)[0]
            self.session.set_folder_note(
                "/" + folder, FOLDER_NOTE.format(host=page), source=SOURCE_BROWSER
            )
        self.session.set_file_note(
            "/" + logical, FILE_NOTE.format(host=page), source=SOURCE_BROWSER
        )

    # ---------------------------------------------------------------------- helper
    @staticmethod
    def _in_root(logical: str) -> bool:
        """Return True when ``logical`` is the credential root or a descendant of it."""
        if logical == CREDENTIAL_ROOT:
            return False                      # the root itself is a folder, never an entry
        return logical.startswith(CREDENTIAL_ROOT + "/")

    def entries(self, *, force: bool = False) -> list[Any]:
        """Return the credential index entries, rebuilding it when stale (internal/testing)."""
        with quiet_scan(self.session):
            return self.index.entries(force=force)


__all__ = [
    "BrowserBridge",
    "CHECKS_PER_MINUTE",
    "REVEALS_PER_MINUTE",
    "SAVES_PER_MINUTE",
    "TOKEN_FILENAME",
    "quiet_scan",
]
