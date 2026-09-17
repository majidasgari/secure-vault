"""Token authentication and login throttling for the web UI (SPEC/07 §2).

The token is generated once per process, written to ``runtime_dir()/web.token`` with
mode ``0600`` and compared in constant time. It is the only thing between the network
and the vault: every ``/api/*`` request must carry it in the ``X-Vault-Token`` header
(the cookie alone is never enough, which is the CSRF defence).
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Callable

from ..config import runtime_dir as default_runtime_dir
from ..util import atomic_write_bytes, now_ms

LOG = logging.getLogger(__name__)

TOKEN_FILENAME = "web.token"
COOKIE_NAME = "vault_token"

SleepFunc = Callable[[float], None]


def cookie_header(token: str) -> str:
    """Return the ``Set-Cookie`` value for the access token.

    The cookie is ``HttpOnly`` and ``SameSite=Strict``; it is set for the
    "click the printed link" flow but is deliberately **never** used to authorise an
    API call (that always requires the ``X-Vault-Token`` header).
    """
    return f"{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/"


class TokenAuth:
    """Owns the web access token and its ``0600`` token file."""

    def __init__(
        self,
        *,
        runtime_dir: Path | str | None = None,
        token: str | None = None,
    ) -> None:
        """Create the token (random 32-byte hex unless ``token`` is supplied)."""
        self.runtime_dir = (
            Path(runtime_dir) if runtime_dir is not None else default_runtime_dir()
        )
        self.token = token or secrets.token_hex(32)
        self.token_file = self.runtime_dir / TOKEN_FILENAME

    def write_token_file(self, extra: dict | None = None) -> None:
        """Atomically write ``web.token`` (``{"token", "created_at"}``) with mode ``0600``.

        ``extra`` carries non-secret metadata (the effective port) so the tray can
        point at an already-running instance.
        """
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.runtime_dir, 0o700)
        except OSError:  # pragma: no cover - best effort on exotic filesystems
            pass
        document: dict = {"token": self.token, "created_at": now_ms()}
        if extra:
            document.update(extra)
        payload = json.dumps(document, ensure_ascii=False).encode("utf-8")
        atomic_write_bytes(self.token_file, payload)
        try:
            os.chmod(self.token_file, 0o600)
        except OSError:  # pragma: no cover - best effort
            pass

    def remove_token_file(self) -> None:
        """Remove the token file on a clean shutdown (best effort)."""
        try:
            self.token_file.unlink()
        except FileNotFoundError:
            pass

    def check(self, candidate: object) -> bool:
        """Return True iff ``candidate`` is a non-empty string equal to the token."""
        if not isinstance(candidate, str) or not candidate:
            return False
        return hmac.compare_digest(candidate, self.token)


class LoginThrottle:
    """In-memory, per-IP unlock throttle (SPEC/07 §2).

    The first ``threshold`` failures are answered immediately; from the
    ``threshold``-th failure on, the caller sleeps ``base_seconds * n`` (capped at
    ``cap_seconds``) where ``n`` counts the failures past the threshold. Nothing is
    persisted: a restart forgets the counters.
    """

    def __init__(
        self,
        *,
        threshold: int = 5,
        base_seconds: float = 5.0,
        cap_seconds: float = 60.0,
        sleep: SleepFunc = time.sleep,
    ) -> None:
        """Configure the throttle; ``sleep`` is injectable so tests stay fast."""
        self.threshold = int(threshold)
        self.base_seconds = float(base_seconds)
        self.cap_seconds = float(cap_seconds)
        self._sleep = sleep
        self._failures: dict[str, int] = {}
        self._lock = threading.Lock()

    def failures(self, ip: str) -> int:
        """Return the recorded failure count for ``ip``."""
        with self._lock:
            return self._failures.get(ip, 0)

    def delay(self, ip: str) -> float:
        """Return the seconds to wait before the next attempt from ``ip`` (0 = none)."""
        with self._lock:
            count = self._failures.get(ip, 0)
        if count < self.threshold:
            return 0.0
        return min(
            self.base_seconds * (count - self.threshold + 1), self.cap_seconds
        )

    def is_throttled(self, ip: str) -> bool:
        """Return True when ``ip`` is currently delayed."""
        return self.delay(ip) > 0.0

    def register_failure(self, ip: str) -> float:
        """Record a failure, sleep the resulting delay and return it."""
        with self._lock:
            self._failures[ip] = self._failures.get(ip, 0) + 1
        delay = self.delay(ip)
        if delay > 0:
            self._sleep(delay)
        return delay

    def reset(self, ip: str) -> None:
        """Forget the failures for ``ip`` after a successful unlock."""
        with self._lock:
            self._failures.pop(ip, None)


__all__ = [
    "TokenAuth",
    "LoginThrottle",
    "cookie_header",
    "TOKEN_FILENAME",
    "COOKIE_NAME",
]
