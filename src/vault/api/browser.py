"""The browser-autofill bridge: a narrow, read-only credential surface for a browser add-on.

The Firefox add-on talks to this bridge over the **loopback** HTTP API (the browser cannot read
``web.token`` from the snap-sandboxed profile, and a native-messaging host spawned by the snap
browser cannot reach ``/data`` or ``/run/user/…`` at all), so the bridge owns its own token:
``runtime_dir()/browser.token`` (mode ``0600``), handed out only by the loopback ``claim`` flow.

What the token buys is deliberately small. The ``browser`` role's method table in
:mod:`vault.api.service` holds exactly three methods — ``vault.browser_status``,
``vault.browser_match`` and ``vault.browser_reveal`` — so a browser (or anything else holding
this token) can never call ``vault.read_file``, ``vault.write_file`` or any other command, and
every path it *can* name has to live under the credential root. Matching answers metadata only;
a reveal returns the fields of **one already-matched entry** and is always audited (one
access-log row with ``source="browser"`` plus one activity event, so the tray shows it).

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
from ..core.credentials import CREDENTIAL_ROOT, CredentialIndex, match_score, normalize_host, parse_body
from ..core.security import SOURCE_BROWSER
from ..errors import BadRequest, PermissionDenied, VaultLocked
from ..util import atomic_write_bytes, normalize_vault_path, now_ms

LOG = logging.getLogger(__name__)

#: Token file name inside the runtime directory (``0600``, like ``web.token``).
TOKEN_FILENAME = "browser.token"

#: Reveals allowed per rolling minute; a loop asking for far more than a human can click is
#: either a broken client or a page scraping the vault through a compromised extension.
REVEALS_PER_MINUTE = 40

#: Default and maximum number of candidates a match call returns.
DEFAULT_LIMIT = 25
MAX_LIMIT = 100


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
        self._clock = clock
        self._reveals: deque[float] = deque()
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

    def _require_usable(self) -> None:
        """Raise when the bridge is switched off or the vault is locked."""
        if not self.enabled():
            raise PermissionDenied("browser_autofill_disabled")
        if self.session.is_locked:
            raise VaultLocked("vault_locked")

    # ---------------------------------------------------------------- rate limiting
    def _note_reveal(self) -> None:
        """Record one reveal and refuse the call when the rolling limit is exhausted."""
        with self._lock:
            stamp = self._clock()
            while self._reveals and stamp - self._reveals[0] > 60.0:
                self._reveals.popleft()
            if len(self._reveals) >= self.reveal_limit:
                raise PermissionDenied(
                    "too_many_reveals", details={"limit": self.reveal_limit, "window_seconds": 60}
                )
            self._reveals.append(stamp)

    def reveals_last_minute(self) -> int:
        """Return how many reveals happened in the last rolling minute."""
        with self._lock:
            stamp = self._clock()
            while self._reveals and stamp - self._reveals[0] > 60.0:
                self._reveals.popleft()
            return len(self._reveals)

    # ---------------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        """Return the bridge state the add-on shows in its popup (metadata only).

        Works while locked (the add-on needs to say *why* it cannot fill); the index numbers are
        withheld in that case, exactly like the rest of the app withholds counts while locked.
        """
        locked = bool(self.session.is_locked)
        data: dict[str, Any] = {
            "enabled": self.enabled(),
            "locked": locked,
            "started": self._started,
            "started_ms": self.started_ms,
            "root": "/" + CREDENTIAL_ROOT,
            "app_version": __version__,
            "reveals_last_minute": self.reveals_last_minute(),
            "reveal_limit": self.reveal_limit,
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
    "TOKEN_FILENAME",
    "REVEALS_PER_MINUTE",
    "quiet_scan",
]
