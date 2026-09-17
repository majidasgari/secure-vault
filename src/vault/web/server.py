"""The HTTP server for the web UI (SPEC/07 §1, §3).

Serves the SPA and its static assets without a token, and the JSON API + SSE stream
with the ``X-Vault-Token`` header. ``ThreadingHTTPServer`` with daemon threads: vault
work serialises on the ``Service`` lock, while slow SSE connections never block the
API.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..config import app_paths
from ..util import now_ms
from .api import Response, WebAPI, json_response
from .auth import LoginThrottle, TokenAuth, cookie_header
from .events import EventBus, Subscription

LOG = logging.getLogger(__name__)

WEBUI_DIR = Path(__file__).resolve().parents[1] / "webui"

_STATIC_TYPES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "styles.css": "text/css; charset=utf-8",
    "icons.svg": "image/svg+xml",
}

FONT_FILENAME = "Vazirmatn-Regular.ttf"
FONT_ROUTE = f"/api/fonts/{FONT_FILENAME}"


class _ThreadingHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server carrying a back-reference to the :class:`WebServer`."""

    daemon_threads = True
    allow_reuse_address = True
    web: "WebServer"


class _Handler(BaseHTTPRequestHandler):
    """One request handler; every method is read-only or explicitly routed."""

    protocol_version = "HTTP/1.0"
    server_version = "SecureVaultWeb/0.1"
    sys_version = ""

    # ------------------------------------------------------------------ plumbing
    def log_message(self, fmt: str, *args: Any) -> None:
        """Route the access log through ``logging`` instead of stderr prints."""
        LOG.debug("%s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        """Handle GET requests."""
        self._handle("GET")

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        """Handle HEAD requests."""
        self._handle("HEAD")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        """Handle POST requests."""
        self._handle("POST")

    def _handle(self, method: str) -> None:
        """Route one request, swallowing client disconnects."""
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        try:
            if method in ("GET", "HEAD") and path in ("/", "/index.html"):
                token = (query.get("token") or [None])[0]
                if token:
                    self._token_link(token)
                else:
                    self._serve_static("index.html")
                return
            if method in ("GET", "HEAD") and path.startswith("/static/"):
                self._serve_static(path[len("/static/") :])
                return
            if method in ("GET", "HEAD") and path == "/favicon.ico":
                self._serve_favicon()
                return
            if method == "POST" and path == "/api/session/login":
                self._send(self.server.web.api.login(self._read_json()))
                return
            if method in ("GET", "HEAD") and path == "/api/i18n":
                # Public on purpose: the unlock screen needs its labels *before* a token exists
                # (asking for a token first left every field and button on that screen blank).
                # The payload is the UI catalogue from i18n/*.json — never vault content.
                self._send(self.server.web.api.i18n((query.get("lang") or [None])[0]))
                return
            if method == "POST" and path == "/api/session/claim":
                # Loopback-only convenience: a browser on this machine gets the token instead of
                # asking the user to copy it out of runtime_dir()/web.token.
                self._send(
                    self.server.web.api.claim(
                        self.headers, self.client_address[0], self.server.web.port
                    )
                )
                return
            if path.startswith("/api/"):
                if not self._authorized():
                    return
                self._route_api(method, path, query)
                return
            self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "not_found"}})
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception:  # noqa: BLE001 - never crash a handler thread
            LOG.exception("unhandled error for %s %s", method, self.path)
            try:
                self._send_json(
                    500, {"error": {"code": "ERROR", "message": "internal_error"}}
                )
            except OSError:
                pass

    def _route_api(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        """Route an authenticated ``/api/*`` request."""
        web = self.server.web
        if method in ("GET", "HEAD") and path == "/api/session":
            self._send(web.api.session_info())
            return
        if method in ("GET", "HEAD") and path == "/api/i18n":
            self._send(web.api.i18n((query.get("lang") or [None])[0]))
            return
        if method in ("GET", "HEAD") and path == "/api/events":
            self._stream_events()
            return
        if method in ("GET", "HEAD") and path == "/api/blob":
            self._send(web.api.blob((query.get("path") or [None])[0]))
            return
        if method in ("GET", "HEAD") and path == "/api/raw":
            self._send(web.api.raw((query.get("path") or [None])[0]))
            return
        if method in ("GET", "HEAD") and path == "/api/index":
            self._send(web.api.index())
            return
        if method in ("GET", "HEAD") and path == "/api/search":
            self._send(
                web.api.search(
                    (query.get("q") or [None])[0],
                    (query.get("tag") or [None])[0],
                    (query.get("limit") or [None])[0],
                )
            )
            return
        if method in ("GET", "HEAD") and path == "/api/export/access-log.csv":
            self._send(web.api.export_csv())
            return
        if method in ("GET", "HEAD") and path == FONT_ROUTE:
            self._serve_font()
            return
        if method == "POST" and path == "/api/call":
            self._send(web.api.handle_call(self._read_json()))
            return
        if method == "POST" and path == "/api/session/unlock":
            self._send(web.api.unlock(self._read_json(), self.client_address[0]))
            return
        if method == "POST" and path == "/api/session/lock":
            self._send(web.api.lock())
            return
        self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "unknown_endpoint"}})

    # --------------------------------------------------------------------- auth
    def _authorized(self) -> bool:
        """Require a valid ``X-Vault-Token`` header; cookies never authorise."""
        token = self.headers.get("X-Vault-Token")
        if self.server.web.auth.check(token):
            return True
        self.server.web.api.log_bad_token(self.path.split("?", 1)[0])
        self._send_json(
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
        return False

    def _token_link(self, token: str) -> None:
        """``GET /?token=…``: set the cookie and redirect to ``/``."""
        web = self.server.web
        if not web.auth.check(token):
            web.api.log_bad_token("session.link")
            self._send_json(
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
            return
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", cookie_header(web.auth.token))
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    # ------------------------------------------------------------------- writing
    def _read_json(self) -> dict[str, Any]:
        """Read and decode a small JSON object body (``{}`` on any problem)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            return {}
        if length <= 0 or length > 8_000_000:
            return {}
        raw = self.rfile.read(length)
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}
        return obj if isinstance(obj, dict) else {}

    def _send(self, response: Response) -> None:
        """Send a prepared :class:`Response` (``no-store`` for API answers)."""
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.end_headers()
        if response.body and self.command != "HEAD":
            self.wfile.write(response.body)

    def _send_json(self, status: int, obj: Any) -> None:
        """Send a JSON object with the given status."""
        self._send(json_response(status, obj))

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        *,
        cache: str = "no-store",
        extra: dict[str, str] | None = None,
    ) -> None:
        """Send raw bytes with an explicit content type and cache policy."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # -------------------------------------------------------------------- static
    def _serve_static(self, name: str) -> None:
        """Serve one of the known SPA assets (never a token-protected resource)."""
        if name in ("", "/"):
            name = "index.html"
        content_type = _STATIC_TYPES.get(name)
        if content_type is None:
            self._send_json(
                404,
                {"error": {"code": "NOT_FOUND", "message": "static_not_found", "details": {"name": name}}},
            )
            return
        path = self.server.web.webui_dir / name
        if not path.is_file():
            self._send_json(
                404,
                {"error": {"code": "NOT_FOUND", "message": "static_missing", "details": {"name": name}}},
            )
            return
        self._send_bytes(200, path.read_bytes(), content_type, cache="no-store")

    def _serve_favicon(self) -> None:
        """Serve the app icon as the favicon (or 404 when the asset is absent)."""
        icon = self.server.web.assets_dir / "icon.svg"
        if icon.is_file():
            self._send_bytes(
                200, icon.read_bytes(), "image/svg+xml", cache="max-age=86400"
            )
        else:
            self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "no_favicon"}})

    def _serve_font(self) -> None:
        """Serve the bundled Vazirmatn font (token-protected, like all ``/api/*``)."""
        font = self.server.web.assets_dir / FONT_FILENAME
        if font.is_file():
            self._send_bytes(200, font.read_bytes(), "font/ttf", cache="max-age=86400")
        else:
            self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "font_missing"}})

    # ----------------------------------------------------------------------- SSE
    def _stream_events(self) -> None:
        """Stream Server-Sent Events until the client disconnects."""
        web = self.server.web
        sub: Subscription = web.events.subscribe()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self._sse_write({"event": "ping", "ts": now_ms()})
            while True:
                try:
                    event = sub.get(web.keepalive)
                except queue.Empty:
                    event = {"event": "ping", "ts": now_ms()}
                self._sse_write(event)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            web.events.unsubscribe(sub)

    def _sse_write(self, event: dict[str, Any]) -> None:
        """Write one ``data:``-only SSE frame (the JSON carries the event name)."""
        data = json.dumps(event, ensure_ascii=False)
        self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
        self.wfile.flush()


class WebServer:
    """Owns the HTTP listener, the token, the event bus and the API."""

    def __init__(
        self,
        service: Any,
        *,
        host: str = "127.0.0.1",
        port: int = 8788,
        runtime_dir: Path | str | None = None,
        token: str | None = None,
        webui_dir: Path | str | None = None,
        i18n_dir: Path | str | None = None,
        assets_dir: Path | str | None = None,
        throttle: LoginThrottle | None = None,
        keepalive: float = 10.0,
    ) -> None:
        """Create the server; nothing is bound until :meth:`start`."""
        self.service = service
        self.host = host
        self.port = int(port)
        self.auth = TokenAuth(runtime_dir=runtime_dir, token=token)
        self.events = EventBus()
        self.throttle = throttle if throttle is not None else LoginThrottle()
        self.api = WebAPI(
            service,
            self.auth,
            self.events,
            throttle=self.throttle,
            i18n_dir=i18n_dir,
        )
        self.webui_dir = Path(webui_dir) if webui_dir is not None else WEBUI_DIR
        self.assets_dir = (
            Path(assets_dir) if assets_dir is not None else app_paths().assets_dir
        )
        self.keepalive = float(keepalive)
        self._httpd: _ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._autolock_thread: threading.Thread | None = None

    # ------------------------------------------------------------------ lifecycle
    @property
    def token(self) -> str:
        """The access token (never logged, never placed in an HTML response)."""
        return self.auth.token

    @property
    def url(self) -> str:
        """The base URL the server is reachable at."""
        return f"http://{self.host}:{self.port}/"

    def attach_activity(self, session: Any | None = None) -> None:
        """Relay ``VaultSession.on_activity`` events onto the SSE bus (SPEC/09 §9).

        Chains any existing callback (the Qt app installs one first) so both the tray
        and the browser see the same metadata-only feed.
        """
        target = session if session is not None else self.service.session
        previous = getattr(target, "on_activity", None)

        def _relay(event: dict[str, Any]) -> None:
            """Forward one activity event to the previous hook and the SSE bus."""
            if previous is not None:
                try:
                    previous(event)
                except Exception:  # noqa: BLE001 - never break the reader
                    pass
            try:
                self.events.publish("activity", dict(event))
            except Exception:  # noqa: BLE001 - a dead subscriber must not matter
                pass

        target.on_activity = _relay

    def start(self) -> None:
        """Write the token file, bind ``host:port`` and serve in a background thread."""
        self.attach_activity()
        self._httpd = _ThreadingHTTPServer((self.host, self.port), _Handler)
        self._httpd.web = self
        self.port = int(self._httpd.server_address[1])
        self.auth.write_token_file(extra={"port": self.port})
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="vault-web", daemon=True
        )
        self._thread.start()
        self._stopping.clear()
        self._autolock_thread = threading.Thread(
            target=self._autolock_loop, name="vault-web-autolock", daemon=True
        )
        self._autolock_thread.start()

    def stop(self) -> None:
        """Stop serving, close the listener and remove the token file."""
        self._stopping.set()
        if self._autolock_thread is not None:
            self._autolock_thread.join(timeout=2.0)
            self._autolock_thread = None
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self.auth.remove_token_file()

    def _autolock_loop(self) -> None:
        """Lock the vault once the UI idle time passes ``auto_lock_seconds``."""
        while not self._stopping.wait(1.0):
            try:
                if self.service.session.auto_lock_due():
                    with self.service._lock:
                        self.service.session.lock()
                    self.service._log(
                        role="ui",
                        tool="vault.lock",
                        target=None,
                        outcome="allow",
                        session_id=self.api.session_id(),
                        source="web",
                    )
                    self.events.publish("lock", {"locked": True})
            except Exception:  # noqa: BLE001 - a tick must never kill the thread
                LOG.debug("auto-lock tick failed", exc_info=True)

    def serve_forever(self) -> None:
        """Serve in the current thread (used by the entry point)."""
        if self._httpd is None:
            raise RuntimeError("server not started")
        self._httpd.serve_forever()


__all__ = ["WebServer", "WEBUI_DIR", "FONT_ROUTE"]
