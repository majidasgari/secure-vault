"""The JSON API of the web UI, built on ``Service.dispatch(role="ui")`` (SPEC/07 §3).

The method/param/result shapes are exactly ``SPEC/02 §1``. Two methods are reachable
only through the dedicated session endpoints (``vault.unlock`` / ``vault.lock``) and
``vault.read_secret`` is deliberately not exposed at all; everything else goes through
``/api/call`` with a ``web-<n>`` session id and one access-log row per call.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import DEFAULT_LANGUAGE, app_paths
from ..errors import (
    BadRequest,
    DowngradeForbidden,
    PermissionDenied,
    SyncReadOnly,
    Unauthorized,
    VaultError,
    VaultLocked,
)
from ..util import is_loopback, normalize_vault_path
from .auth import LoginThrottle, TokenAuth, cookie_header
from .events import EventBus

LOG = logging.getLogger(__name__)

#: Methods that must not be called through ``/api/call``. ``unlock``/``lock`` live in
#: the session endpoints. ``vault.read_secret`` *is* allowed for the web role, but only
#: after the SPA has run the approval flow: a plain ``vault.read_file`` on a
#: ``secret``/``secretfile`` path is answered with ``requires_approval`` (SPEC/09 §5).
FORBIDDEN_METHODS = frozenset({"vault.unlock", "vault.lock"})

#: Levels whose content is gated behind the explicit approval flow.
SECRET_LEVELS = frozenset({"secret", "secretfile"})

#: Methods whose success invalidates the browser's cached listing.
MUTATING_METHODS = frozenset(
    {
        "vault.write_file",
        "vault.write_lines",
        "vault.mkdir",
        "vault.file_ops",
        "vault.set_sensitivity",
        "vault.set_tags",
        "vault.set_emoji",
        "vault.set_folder_note",
        "vault.set_file_note",
        "vault.set_settings",
        "vault.semantic_index",
        "vault.sync_now",
        "vault.sync_acquire",
        "vault.sync_release",
    }
)


@dataclass
class Response:
    """A prepared HTTP response (status, body and content type)."""

    status: int
    body: bytes = b""
    content_type: str = "application/json; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)


def json_response(status: int, obj: Any, **headers: str) -> Response:
    """Build a JSON :class:`Response` from a Python object."""
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return Response(status=status, body=body, headers=dict(headers))


def _bad_request(message: str, **details: Any) -> Response:
    """Build a ``400 BAD_REQUEST`` response."""
    return json_response(
        400,
        {
            "ok": False,
            "error": {"code": "BAD_REQUEST", "message": message, "details": details},
        },
    )


def _outcome_for(exc: VaultError) -> str:
    """Map a vault error to the access-log outcome it represents."""
    if isinstance(exc, (PermissionDenied, DowngradeForbidden, SyncReadOnly, VaultLocked)):
        return "deny"
    return "error"


class WebAPI:
    """Transport-independent handlers behind the HTTP layer."""

    def __init__(
        self,
        service: Any,
        auth: TokenAuth,
        events: EventBus,
        *,
        throttle: LoginThrottle | None = None,
        i18n_dir: Path | str | None = None,
        browser: Any | None = None,
    ) -> None:
        """Bind the API to a :class:`~vault.api.service.Service` and its collaborators."""
        self.service = service
        self.auth = auth
        self.events = events
        self.throttle = throttle if throttle is not None else LoginThrottle()
        #: The browser-autofill bridge (``None`` = the autofill endpoints answer 503).
        self.browser = browser
        self.i18n_dir = (
            Path(i18n_dir) if i18n_dir is not None else app_paths().i18n_dir
        )
        self._counter = 0
        self._counter_lock = threading.Lock()
        self._browser_counter = 0

    # ------------------------------------------------------------------- helpers
    @property
    def session(self) -> Any:
        """The underlying :class:`~vault.core.session.VaultSession`."""
        return self.service.session

    def session_id(self) -> str:
        """Return the next ``web-<n>`` transport session id."""
        with self._counter_lock:
            self._counter += 1
            return f"web-{self._counter}"

    def browser_session_id(self) -> str:
        """Return the next ``brw-<n>`` transport session id (browser autofill calls)."""
        with self._counter_lock:
            self._browser_counter += 1
            return f"brw-{self._browser_counter}"

    def _log(
        self,
        tool: str,
        *,
        outcome: str,
        target: str | None = None,
        code: str | None = None,
        reason: str | None = None,
        role: str = "ui",
        source: str | None = None,
    ) -> None:
        """Append one access-log row with ``source="web"`` (never logs a secret).

        ``role``/``source`` are overridden for the browser-autofill traffic so the log names the
        add-on (``source="browser"``) instead of the web UI.
        """
        self.service._log(
            role=role,
            tool=tool,
            target=target,
            outcome=outcome,
            code=code,
            session_id=self.browser_session_id() if role == "browser" else self.session_id(),
            source=source or ("browser" if role == "browser" else "web"),
        )
        if reason:  # pragma: no cover - reason is folded into the code for the log
            LOG.debug("web deny for %s: %s", tool, reason)

    def log_bad_token(self, tool: str) -> None:
        """Record a denied request that carried no/wrong token."""
        self._log(tool, outcome="deny", code="UNAUTHORIZED")

    def log_bad_browser_token(self, tool: str) -> None:
        """Record a denied ``/api/autofill/*`` request that carried no/wrong browser token."""
        self._log(
            tool, outcome="deny", code="UNAUTHORIZED", role="browser", source="browser"
        )

    def _approval_required(self, params: dict) -> tuple[str, str] | None:
        """Return ``(logical_path, level)`` when a plain read needs approval.

        Secret and secretfile content may not be returned by ``vault.read_file``: the
        SPA must run the confirm/show step and then call ``vault.read_secret`` (SPEC/09
        §5). Returns None for normal files, directories, missing paths and while locked.
        """
        path = params.get("path")
        if not isinstance(path, str) or not path:
            return None
        try:
            logical = normalize_vault_path(path)
            row = self.session.index.require_file(logical)
        except VaultError:
            return None
        if int(row.get("is_dir", 0)):
            return None
        level = str(row.get("sensitivity", "normal"))
        if level in SECRET_LEVELS:
            return logical, level
        return None

    def _requires_approval(self, logical: str, level: str) -> Response:
        """Answer a gated ``read_file`` with ``requires_approval`` (one deny row)."""
        self._log(
            "read_file", outcome="deny", target=logical, code="PERMISSION_DENIED"
        )
        self.events.publish(
            "log",
            {"tool": "vault.read_file", "outcome": "deny", "code": "PERMISSION_DENIED"},
        )
        return json_response(
            200,
            {
                "ok": False,
                "error": {
                    "code": "PERMISSION_DENIED",
                    "message": "requires_approval",
                    "details": {
                        "path": logical,
                        "sensitivity": level,
                        "requires_approval": True,
                    },
                },
            },
        )

    # -------------------------------------------------------------------- /api/call
    def handle_call(self, payload: Any) -> Response:
        """Dispatch one ``/api/call`` body and return the documented envelope."""
        if not isinstance(payload, dict):
            return _bad_request("invalid_body")
        method = payload.get("method")
        params = payload.get("params") or {}
        if not isinstance(method, str) or not method:
            return _bad_request("missing_method")
        if not isinstance(params, dict):
            return _bad_request("params_must_be_object")
        if method in FORBIDDEN_METHODS:
            return _bad_request("method_not_allowed_via_call", method=method)
        if not self.session.is_locked:
            self.session.touch()
        if method == "vault.read_file":
            approval = self._approval_required(params)
            if approval is not None:
                return self._requires_approval(*approval)
        try:
            result = self.service.dispatch(
                method, params, role="ui", session_id=self.session_id(), source="web"
            )
        except VaultError as exc:
            self.events.publish(
                "log", {"tool": method, "outcome": _outcome_for(exc), "code": exc.code}
            )
            if isinstance(exc, BadRequest):
                status = 400
            elif isinstance(exc, Unauthorized):
                status = 401
            else:
                status = 200
            return json_response(status, {"ok": False, "error": exc.to_dict()})
        except Exception:  # noqa: BLE001 - never leak a traceback to the browser
            LOG.exception("internal error handling %s", method)
            self.events.publish("log", {"tool": method, "outcome": "error", "code": "ERROR"})
            return json_response(
                500,
                {
                    "ok": False,
                    "error": {
                        "code": "ERROR",
                        "message": "internal_error",
                        "details": {},
                    },
                },
            )
        self.events.publish("log", {"tool": method, "outcome": "allow"})
        if method in MUTATING_METHODS:
            self.events.publish("data_changed", {"method": method})
        return json_response(200, {"ok": True, "result": result})

    # --------------------------------------------------------------- /api/session
    def session_info(self) -> Response:
        """Return the session snapshot; counts are withheld while locked."""
        session = self.session
        locked = bool(session.is_locked)
        settings = session.meta.settings
        counts: dict[str, Any] | None = None
        if not locked:
            raw = session.index.count()
            counts = {
                "files": int(raw["files"]),
                "folders": int(raw["dirs"]),
                "by_level": raw["by_level"],
            }
        language = settings.get("language")
        if not isinstance(language, str) or not language:
            language = DEFAULT_LANGUAGE
        ui = {
            "plain_threshold_bytes": int(
                settings.get("plain_threshold_bytes", 0) or 0
            ),
            "default_sensitivity": settings.get("default_sensitivity", "normal"),
            "semantic": settings.get("semantic", {}),
        }
        try:
            sync = session.sync_manager().status()
        except Exception:  # noqa: BLE001 - sync state must never break the session call
            sync = {"configured": False, "enabled": False, "readonly": False}
        return json_response(
            200,
            {
                "locked": locked,
                "home": str(session.home),
                "language": language,
                "auto_lock_seconds": int(settings.get("auto_lock_seconds", 0) or 0),
                "counts": counts,
                "version": __version__,
                "ui": ui,
                "sync": sync,
            },
        )

    # ------------------------------------------------------------------- /api/i18n
    def i18n(self, lang: str | None) -> Response:
        """Return the requested catalogue (single source of truth: ``i18n/*.json``)."""
        available = {path.stem for path in self.i18n_dir.glob("*.json")}
        if lang not in available:
            lang = DEFAULT_LANGUAGE if DEFAULT_LANGUAGE in available else (
                sorted(available)[0] if available else DEFAULT_LANGUAGE
            )
        path = self.i18n_dir / f"{lang}.json"
        if not path.is_file():
            return json_response(
                404,
                {
                    "ok": False,
                    "error": {
                        "code": "NOT_FOUND",
                        "message": "catalogue_missing",
                        "details": {"lang": lang},
                    },
                },
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):  # pragma: no cover - corrupt catalogue
            return json_response(
                500,
                {
                    "ok": False,
                    "error": {
                        "code": "ERROR",
                        "message": "catalogue_invalid",
                        "details": {"lang": lang},
                    },
                },
            )
        # The SPA builds its language selector from the catalogues on disk, so adding
        # ``i18n/xx.json`` is enough to offer another language.
        if isinstance(data, dict):
            data["_languages"] = sorted(available)
        return json_response(200, data)

    # ---------------------------------------------------------- /api/session/login
    def login(self, payload: Any) -> Response:
        """Validate a body token and set the (non-authorising) cookie."""
        token = payload.get("token") if isinstance(payload, dict) else None
        if not self.auth.check(token):
            self.log_bad_token("session.login")
            return json_response(
                401,
                {
                    "ok": False,
                    "error": {
                        "code": "UNAUTHORIZED",
                        "message": "invalid_token",
                        "details": {},
                    },
                },
            )
        return json_response(
            200, {"ok": True}, **{"Set-Cookie": cookie_header(self.auth.token)}
        )

    def claim(self, headers: Any, ip: str, port: int, payload: Any = None) -> Response:
        """Hand an access token to a loopback client that explicitly asks for it.

        The desktop app writes ``runtime_dir()/web.token`` (mode 0600) and a browser cannot read
        that file, so the SPA asks here instead of making the user copy a 64-hex token by hand.
        Two guards, both required:

        * the client address must be loopback (a request from the network never gets a token);
        * the ``X-Vault-Claim`` header must be present. A cross-origin page cannot read this
          reply anyway (no CORS headers are ever sent), and a non-simple header would need a
          preflight this server never approves.

        ``payload == {"scope": "browser"}`` asks for the *browser autofill* token instead: it is
        a different secret, valid only for the three ``vault.browser_*`` methods, so a browser
        holding it cannot read or write anything else in the vault (``api/browser.py``).

        The reply carries the token, the lock flag and the port — never vault content.
        """
        header = ""
        try:
            header = str(headers.get("X-Vault-Claim") or "")
        except Exception:  # noqa: BLE001 - a malformed header object simply fails the check
            header = ""
        scope = ""
        if isinstance(payload, dict):
            raw = payload.get("scope")
            scope = str(raw).strip().lower() if isinstance(raw, str) else ""
        browser_scope = scope == "browser"
        if not is_loopback(str(ip)) or header != "1":
            self._log(
                "session.claim",
                outcome="deny",
                code="FORBIDDEN",
                role="browser" if browser_scope else "ui",
                source="browser" if browser_scope else "web",
            )
            return json_response(
                403,
                {
                    "ok": False,
                    "error": {
                        "code": "FORBIDDEN",
                        "message": "claim_denied",
                        "details": {"reason": "loopback_only"},
                    },
                },
            )
        browser = self.browser
        if browser_scope and browser is None:
            return json_response(
                503,
                {
                    "ok": False,
                    "error": {
                        "code": "PROVIDER_UNAVAILABLE",
                        "message": "browser_bridge_unavailable",
                        "details": {},
                    },
                },
            )
        session = self.session
        locked = bool(session.is_locked)
        if browser_scope and browser is not None:
            self._log(
                "session.claim",
                outcome="allow",
                role="browser",
                source="browser",
            )
            return json_response(
                200,
                {
                    "ok": True,
                    "scope": "browser",
                    "token": browser.token,
                    "unlocked": not locked,
                    "port": int(port),
                },
            )
        self._log("session.claim", outcome="allow", code=None)
        return json_response(
            200,
            {
                "ok": True,
                "scope": "vault",
                "token": self.auth.token,
                "unlocked": not locked,
                "port": int(port),
            },
        )

    # --------------------------------------------------------------- /api/autofill
    def autofill_status(self) -> Response:
        """Return the browser-bridge state for the add-on (metadata only)."""
        return self._autofill_call("vault.browser_status", {})

    def autofill_match(self, payload: Any) -> Response:
        """Return the credential candidates for one page host (never a password)."""
        params: dict[str, Any] = {}
        if isinstance(payload, dict):
            for key in ("host", "url", "limit"):
                value = payload.get(key)
                if isinstance(value, (str, int)) and not isinstance(value, bool):
                    params[key] = value
        return self._autofill_call("vault.browser_match", params)

    def autofill_reveal(self, payload: Any) -> Response:
        """Return the fields of one matched credential entry (the audited reveal)."""
        params: dict[str, Any] = {}
        if isinstance(payload, dict):
            for key in ("path", "host"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    params[key] = value
        return self._autofill_call("vault.browser_reveal", params)

    def _autofill_call(self, method: str, params: dict[str, Any]) -> Response:
        """Dispatch one browser-role call and shape its errors like the rest of the API.

        The caller has already been authenticated with the *browser* token (see
        ``web/server.py``); this only routes, maps errors and publishes the same ``log`` event
        the web UI's own calls publish.
        """
        if self.browser is None:
            return json_response(
                503,
                {
                    "ok": False,
                    "error": {
                        "code": "PROVIDER_UNAVAILABLE",
                        "message": "browser_bridge_unavailable",
                        "details": {},
                    },
                },
            )
        if not self.session.is_locked:
            self.session.touch()
        try:
            result = self.service.dispatch(
                method,
                params,
                role="browser",
                session_id=self.browser_session_id(),
                source="browser",
            )
        except VaultError as exc:
            self.events.publish(
                "log", {"tool": method, "outcome": _outcome_for(exc), "code": exc.code}
            )
            if isinstance(exc, BadRequest):
                status = 400
            elif isinstance(exc, Unauthorized):
                status = 401
            elif isinstance(exc, VaultLocked):
                status = 423
            elif isinstance(exc, (PermissionDenied, DowngradeForbidden, SyncReadOnly)):
                status = 403
            else:
                status = 200
            return json_response(status, {"ok": False, "error": exc.to_dict()})
        except Exception:  # noqa: BLE001 - never leak a traceback to the add-on
            LOG.exception("internal error handling %s", method)
            self.events.publish(
                "log", {"tool": method, "outcome": "error", "code": "ERROR"}
            )
            return json_response(
                500,
                {
                    "ok": False,
                    "error": {
                        "code": "ERROR",
                        "message": "internal_error",
                        "details": {},
                    },
                },
            )
        self.events.publish("log", {"tool": method, "outcome": "allow"})
        return json_response(200, {"ok": True, "result": result})

    # --------------------------------------------------------- /api/session/unlock
    def unlock(self, payload: Any, ip: str) -> Response:
        """Verify the master password in-process, throttling bad attempts per IP."""
        password = payload.get("password") if isinstance(payload, dict) else None
        if not isinstance(password, str) or not password:
            return _bad_request("missing_password")
        session_id = self.session_id()
        with self.service._lock:
            try:
                self.session.unlock(password)
            except Unauthorized:
                delay = self.throttle.register_failure(ip)
                self.service._log(
                    role="ui",
                    tool="vault.unlock",
                    target=None,
                    outcome="deny",
                    code="UNAUTHORIZED",
                    session_id=session_id,
                    source="web",
                )
                self.events.publish(
                    "log",
                    {"tool": "vault.unlock", "outcome": "deny", "code": "UNAUTHORIZED"},
                )
                return json_response(
                    401,
                    {
                        "ok": False,
                        "code": "UNAUTHORIZED",
                        "details": {"reason": "bad_password"},
                        "error": {
                            "code": "UNAUTHORIZED",
                            "message": "bad_password",
                            "details": {
                                "reason": "bad_password",
                                "retry_after": int(delay) if delay else 0,
                            },
                        },
                    },
                )
            except VaultError as exc:
                return json_response(400, {"ok": False, "error": exc.to_dict()})
        self.throttle.reset(ip)
        self.session.touch()
        self.service._log(
            role="ui",
            tool="vault.unlock",
            target=None,
            outcome="allow",
            session_id=session_id,
            source="web",
        )
        self.events.publish("unlock", {"locked": False})
        return json_response(200, {"ok": True, "locked": False})

    # ----------------------------------------------------------- /api/session/lock
    def lock(self) -> Response:
        """Lock the vault and notify SSE subscribers."""
        session_id = self.session_id()
        with self.service._lock:
            self.session.lock()
        self.service._log(
            role="ui",
            tool="vault.lock",
            target=None,
            outcome="allow",
            session_id=session_id,
            source="web",
        )
        self.events.publish("lock", {"locked": True})
        return json_response(200, {"ok": True, "locked": True})

    # ------------------------------------------------------- /api/session/quick-unlock
    def quick_unlock_info(self) -> Response:
        """Return the fingerprint quick-unlock state (sensor, record, loopback flag)."""
        from ..core import fingerprint

        session = self.session
        state = fingerprint.quick_unlock_state(session.home)
        state["loopback"] = True  # the route is only reachable from this machine
        return json_response(200, {"ok": True, **state})

    def quick_unlock_unlock(self, ip: str) -> Response:
        """Unlock after a fingerprint scan on this machine (loopback clients only).

        The blocked call is a ``fprintd`` verification running in this process (the web
        server owns the vault, exactly like the desktop app), so it is restricted to
        loopback: a phone on the LAN can never trigger a scan on your desk.
        """
        from ..core import fingerprint

        if not is_loopback(str(ip)):
            return self._quick_unlock_denied("loopback_only")
        session = self.session
        state = fingerprint.quick_unlock_state(session.home)
        if not state.get("enabled"):
            return self._quick_unlock_denied("not_enabled")
        verification = fingerprint.verify()
        if not verification.matched:
            self._log("vault.quick_unlock", outcome="deny", code="UNAUTHORIZED", reason=verification.reason)
            return json_response(
                401,
                {
                    "ok": False,
                    "code": "UNAUTHORIZED",
                    "error": {
                        "code": "UNAUTHORIZED",
                        "message": "fingerprint_not_verified",
                        "details": {"reason": verification.reason},
                    },
                },
            )
        try:
            key = fingerprint.release_master_key(session.home, verification)
        except VaultError as exc:
            self._log("vault.quick_unlock", outcome="deny", code=exc.code)
            return json_response(401, {"ok": False, "error": exc.to_dict()})
        with self.service._lock:
            try:
                session.unlock_with_master_key(key)
            except VaultError as exc:
                return json_response(401, {"ok": False, "error": exc.to_dict()})
        self._log("vault.quick_unlock", outcome="allow")
        self.events.publish("unlock", {"locked": False})
        return json_response(200, {"ok": True, "locked": False})

    def quick_unlock_enable(self, ip: str) -> Response:
        """Store the quick-unlock record after a scan (loopback, vault unlocked)."""
        from ..core import fingerprint

        if not is_loopback(str(ip)):
            return self._quick_unlock_denied("loopback_only")
        session = self.session
        if session.is_locked:
            return json_response(
                409,
                {"ok": False, "error": {"code": "VAULT_LOCKED", "message": "vault_locked", "details": {}}},
            )
        verification = fingerprint.verify()
        if not verification.matched:
            self._log(
                "vault.quick_unlock_enable", outcome="deny", code="UNAUTHORIZED",
                reason=verification.reason,
            )
            return json_response(
                401,
                {
                    "ok": False,
                    "error": {
                        "code": "UNAUTHORIZED",
                        "message": "fingerprint_not_verified",
                        "details": {"reason": verification.reason},
                    },
                },
            )
        state = session.quick_unlock_enable(verification)
        self._log("vault.quick_unlock_enable", outcome="allow")
        return json_response(200, {"ok": True, **state})

    def quick_unlock_disable(self, ip: str) -> Response:
        """Forget the quick-unlock record (loopback, vault unlocked)."""
        if not is_loopback(str(ip)):
            return self._quick_unlock_denied("loopback_only")
        session = self.session
        removed = session.quick_unlock_disable()
        self._log(
            "vault.quick_unlock_disable", outcome="allow" if removed else "no_record"
        )
        return json_response(200, {"ok": True, "removed": bool(removed)})

    def _quick_unlock_denied(self, reason: str) -> Response:
        """Answer a refused quick-unlock request (never leaks anything about the vault)."""
        LOG.info("quick unlock refused: %s", reason)
        return json_response(
            403,
            {
                "ok": False,
                "error": {
                    "code": "FORBIDDEN",
                    "message": "quick_unlock_denied",
                    "details": {"reason": reason},
                },
            },
        )

    # ------------------------------------------------------------------- /api/blob
    def blob(self, path: str | None) -> Response:
        """Return the raw bytes of a ``normal`` file (403 for anything else)."""
        session = self.session
        if session.is_locked:
            return json_response(
                423,
                {
                    "ok": False,
                    "error": {
                        "code": "VAULT_LOCKED",
                        "message": "vault_locked",
                        "details": {},
                    },
                },
            )
        try:
            logical = normalize_vault_path(path or "")
        except VaultError as exc:
            return json_response(400, {"ok": False, "error": exc.to_dict()})
        try:
            row = session.index.require_file(logical)
        except VaultError as exc:
            status = 404 if exc.code == "NOT_FOUND" else 400
            return json_response(status, {"ok": False, "error": exc.to_dict()})
        if row["sensitivity"] != "normal":
            self._log(
                "read_file", outcome="deny", target=logical, code="PERMISSION_DENIED"
            )
            return json_response(
                403,
                {
                    "ok": False,
                    "error": {
                        "code": "PERMISSION_DENIED",
                        "message": "blob_forbidden",
                        "details": {"path": logical},
                    },
                },
            )
        try:
            data = session.read_file(logical, source="ui")
        except VaultError as exc:
            return json_response(409, {"ok": False, "error": exc.to_dict()})
        content_type = mimetypes.guess_type(logical)[0] or "application/octet-stream"
        return Response(
            status=200,
            body=data,
            content_type=content_type,
            headers={"Cache-Control": "no-store"},
        )

    # ------------------------------------------------------------ /api/raw
    def raw(self, path: str | None) -> Response:
        """Return a ``normal`` file as ``text/plain`` (same 403 rules as blob)."""
        response = self.blob(path)
        if response.status == 200:
            return Response(
                status=200,
                body=response.body,
                content_type="text/plain; charset=utf-8",
                headers={"Cache-Control": "no-store"},
            )
        return response

    # ------------------------------------------------------------- /api/index
    def index(self) -> Response:
        """Return the folder tree, the tag list and the vault counts in one call."""
        tree = self.service.dispatch(
            "vault.tree", {}, role="ui", session_id=self.session_id(), source="web"
        )
        tags = self.service.dispatch(
            "vault.all_tags", {}, role="ui", session_id=self.session_id(), source="web"
        )
        return json_response(
            200,
            {
                "tree": tree.get("tree", []),
                "tags": tags.get("tags", []),
                "counts": tree.get("counts", {}),
            },
        )

    # ------------------------------------------------------------- /api/search
    def search(self, q: str | None, tag: str | None, limit: str | int | None) -> Response:
        """Parity search over names, tags and (``normal``) bodies.

        ``q`` may contain ``tag:<name>``; a bare ``tag`` argument filters too. Secret
        and secretfile files can match by name or tag, but never by body, because only
        ``normal`` content is indexed.
        """
        session = self.session
        query = (q or "").strip()
        tag_filter = (tag or "").strip()
        try:
            limit_value = max(1, min(int(limit or 200), 500))
        except (TypeError, ValueError):
            limit_value = 200
        tokens: list[str] = []
        for token in query.split():
            if token.lower().startswith("tag:") and len(token) > 4:
                tag_filter = token[4:].strip()
            else:
                tokens.append(token)
        text = " ".join(tokens).strip()
        priority = {"body": 3, "name": 2, "tag": 1}
        results: dict[str, dict[str, Any]] = {}

        def add(
            logical: str,
            sensitivity: str,
            match: str,
            *,
            snippet: str = "",
            score: float = 0.0,
            mtime: int = 0,
        ) -> None:
            """Record a hit, keeping the strongest match kind for each path."""
            path = "/" if logical == "/" else "/" + logical
            current = results.get(path)
            if current is None or priority.get(match, 0) > priority.get(
                current["match"], 0
            ):
                results[path] = {
                    "path": path,
                    "title": logical.rsplit("/", 1)[-1] if logical != "/" else "/",
                    "sensitivity": sensitivity,
                    "match": match,
                    "snippet": snippet[:220],
                    "score": float(score or 0.0),
                    "mtime": int(mtime),
                }

        if tag_filter:
            try:
                rows = session.index.files_by_tag(tag_filter)
            except VaultError:
                rows = []
            for row in rows:
                add(
                    row["logical_path"],
                    row["sensitivity"],
                    "tag",
                    mtime=row["mtime"],
                )
        if text:
            try:
                for hit in session.search_filenames(text, limit=limit_value, source="ui"):
                    add(
                        hit["logical_path"],
                        hit["sensitivity"],
                        "name",
                        mtime=hit.get("mtime", 0),
                    )
            except VaultError:
                pass
            if not session.is_locked:
                try:
                    for hit in session.search_text(text, limit=limit_value, source="ui"):
                        add(
                            hit["logical_path"],
                            hit["sensitivity"],
                            "body",
                            snippet=hit.get("snippet", ""),
                            score=hit.get("score", 0.0),
                            mtime=hit.get("mtime", 0),
                        )
                except VaultError:
                    pass
        ordered = sorted(
            results.values(),
            key=lambda item: (-priority[item["match"]], item["path"]),
        )[:limit_value]
        return json_response(
            200,
            {
                "query": query,
                "tag": tag_filter or None,
                "count": len(ordered),
                "results": ordered,
            },
        )

    # ----------------------------------------------------- /api/export/access-log.csv
    def export_csv(self) -> Response:
        """Export the access log as ``text/csv`` (generated via the index helper)."""
        with tempfile.TemporaryDirectory(prefix="sv-web-csv-") as tmp:
            dest = Path(tmp) / "access-log.csv"
            try:
                self.session.index.export_access_log_csv(dest)
                data = dest.read_bytes()
            except OSError:  # pragma: no cover - temp filesystem failure
                return json_response(
                    500,
                    {
                        "ok": False,
                        "error": {
                            "code": "ERROR",
                            "message": "export_failed",
                            "details": {},
                        },
                    },
                )
        return Response(
            status=200,
            body=data,
            content_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="access-log.csv"',
                "Cache-Control": "no-store",
            },
        )


__all__ = ["WebAPI", "Response", "json_response", "FORBIDDEN_METHODS", "MUTATING_METHODS"]
