"""Local JSON-RPC server for the daemon (SPEC/02 §2).

Newline-delimited JSON: one request per line, one response per line, in order per
connection. Authentication is a per-daemon ``mcp`` token written to
``runtime_dir()/tokens.json`` (mode ``0600``); the UI never uses the socket because it
calls :class:`~vault.api.service.Service` in-process.

The listening socket is a Unix-domain socket on POSIX and a loopback TCP port on Windows
(which has no ``AF_UNIX`` in CPython) — see :mod:`vault.api.transport`. Both publish
``runtime_dir()/endpoint.json`` so the bridge and the tools find the daemon the same way.
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets
import socket
import socketserver
import threading
from pathlib import Path
from typing import Any

from ..config import runtime_dir as default_runtime_dir
from ..errors import AlreadyExists, VaultError
from ..util import atomic_write_bytes, now_ms, restrict
from .service import ROLE_MCP, Service
from .transport import (
    ENDPOINT_FILENAME,
    SOCKET_FILENAME,
    Endpoint,
    read_endpoint,
    unix_sockets_available,
    write_endpoint,
)

LOG = logging.getLogger(__name__)

TOKENS_FILENAME = "tokens.json"


def _error_response(request_id: Any, exc: VaultError) -> dict[str, Any]:
    """Build an ``ok: false`` response from a :class:`VaultError`."""
    return {
        "id": request_id,
        "ok": False,
        "error": {
            "code": exc.code,
            "message": exc.message,
            "details": exc.details,
        },
    }


class _RequestHandler(socketserver.StreamRequestHandler):
    """Reads newline-delimited requests from one client connection."""

    def handle(self) -> None:
        """Serve requests until the client disconnects or sends EOF."""
        owner: "VaultSocketServer" = self.server.service  # type: ignore[attr-defined]
        session_id = owner.next_session_id()
        owner.connection_opened()
        try:
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                line = line.strip()
                if not line:
                    continue
                response = owner.process_line(line, session_id)
                payload = json.dumps(response, ensure_ascii=False) + "\n"
                try:
                    self.wfile.write(payload.encode("utf-8"))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
        finally:
            owner.connection_closed()


if unix_sockets_available():  # pragma: no cover - platform switch

    class _ThreadingUnixServer(socketserver.ThreadingUnixStreamServer):  # type: ignore[misc]
        """Threading Unix stream server with per-connection handler threads."""

        daemon_threads = True
        allow_reuse_address = True

else:  # Windows: socketserver has no UnixStreamServer at all.

    class _ThreadingUnixServer:  # type: ignore[no-redef]
        """Placeholder for the POSIX server; never instantiated without ``AF_UNIX``."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("AF_UNIX sockets are not available on this platform")


class _ThreadingTcpServer(socketserver.ThreadingTCPServer):
    """Threading TCP server bound to the loopback interface (the Windows endpoint)."""

    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET


class VaultSocketServer:
    """Owns the local endpoint, the ``mcp`` token file and the request loop."""

    def __init__(
        self,
        service: Service,
        *,
        socket_path: Path | str | None = None,
        runtime_dir: Path | str | None = None,
        token: str | None = None,
        endpoint: Endpoint | dict[str, Any] | str | None = None,
    ) -> None:
        """Bind the server to ``service``; nothing is created until :meth:`start`."""
        self.service = service
        self.runtime_dir = (
            Path(runtime_dir) if runtime_dir is not None else default_runtime_dir()
        )
        self.socket_path = (
            Path(socket_path)
            if socket_path is not None
            else self.runtime_dir / SOCKET_FILENAME
        )
        self.endpoint = self._resolve_endpoint(endpoint)
        self.endpoint_file = self.runtime_dir / ENDPOINT_FILENAME
        self.token_file = self.runtime_dir / TOKENS_FILENAME
        self.mcp_token = token or secrets.token_hex(32)
        self._server: Any = None
        self._thread: threading.Thread | None = None
        self._counter = 0
        self._counter_lock = threading.Lock()
        self._active = 0
        self._active_lock = threading.Lock()

    def _resolve_endpoint(
        self, endpoint: Endpoint | dict[str, Any] | str | None
    ) -> Endpoint:
        """Return the endpoint to listen on, adapting a POSIX path for Windows.

        A Unix-socket endpoint cannot be honoured where CPython has no ``AF_UNIX`` (Windows),
        so there it is replaced by the loopback TCP transport — the only local transport the
        platform offers — and the caller reads the real port back from :attr:`endpoint`.
        """
        if endpoint is not None:
            requested = Endpoint.parse(endpoint)
        elif unix_sockets_available():
            requested = Endpoint.unix(self.socket_path)
        else:
            requested = Endpoint.tcp()
        if requested.is_unix and not unix_sockets_available():
            LOG.debug("AF_UNIX unavailable; using the loopback TCP endpoint instead")
            return Endpoint.tcp()
        return requested

    @property
    def address(self) -> str:
        """Return a display string for the live endpoint (real port once bound)."""
        return self.endpoint.display()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Write the token file, bind the endpoint and start serving in a thread.

        Raises:
            AlreadyExists: when another live daemon already answers on the endpoint.
        """
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        restrict(self.runtime_dir, 0o700)
        # Bind first: publishing a token for a socket someone else serves left the bridge
        # authenticating against the *other* daemon, which answers UNAUTHORIZED (and the app's
        # tray never sees the calls).
        self._bind()
        self._write_endpoint()
        self._write_tokens()
        assert self._server is not None
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="vault-socket", daemon=True
        )
        self._thread.start()

    def _write_endpoint(self) -> None:
        """Publish the live endpoint (with the port the OS actually gave us)."""
        write_endpoint(self.runtime_dir, self.endpoint)

    def _write_tokens(self) -> None:
        """Atomically write ``tokens.json`` with mode ``0600``."""
        payload = json.dumps(
            {"mcp": self.mcp_token, "created_at": now_ms()}, ensure_ascii=False
        ).encode("utf-8")
        atomic_write_bytes(self.token_file, payload)
        restrict(self.token_file, 0o600)

    def _probe_existing(self) -> None:
        """Raise :class:`AlreadyExists` when a live daemon already serves this runtime dir."""
        if self.endpoint.is_unix:
            path = self.socket_path
            if not path.exists():
                return
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            published = read_endpoint(self.runtime_dir)
            if published is None or not published.port:
                return
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.5)
        try:
            if self.endpoint.is_unix:
                probe.connect(str(self.socket_path))
            else:
                probe.connect((str(published.host), int(published.port)))  # type: ignore[union-attr]
        except OSError:
            probe.close()
            if self.endpoint.is_unix:
                try:
                    self.socket_path.unlink()
                except FileNotFoundError:  # pragma: no cover - race
                    pass
        else:
            probe.close()
            raise AlreadyExists(
                "daemon_already_running", details={"socket": self.endpoint.display()}
            )

    def _bind(self) -> None:
        """Bind the endpoint, refusing to clobber a live daemon."""
        self._probe_existing()
        if self.endpoint.is_unix:
            self.socket_path.parent.mkdir(parents=True, exist_ok=True)
            self._server = _ThreadingUnixServer(str(self.socket_path), _RequestHandler)
            restrict(self.socket_path, 0o600)
        else:
            self._server = _ThreadingTcpServer(
                (str(self.endpoint.host), int(self.endpoint.port or 0)), _RequestHandler
            )
            host, port = self._server.server_address[:2]
            self.endpoint = self.endpoint.with_port(int(port))
            LOG.debug("daemon listening on %s", self.endpoint.display())
        self._server.service = self  # type: ignore[attr-defined]

    def stop(self) -> None:
        """Stop serving, remove the endpoint file, the socket and the token file."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        for path in (self.endpoint_file, self.socket_path, self.token_file):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:  # pragma: no cover - e.g. a locked file on Windows
                LOG.debug("could not remove %s", path)

    def serve_forever(self) -> None:
        """Serve in the current thread (used by the headless daemon)."""
        if self._server is None:
            raise RuntimeError("server not started")
        self._server.serve_forever()

    # -------------------------------------------------------------------- request
    def next_session_id(self) -> str:
        """Return a monotonically increasing ``sock-<n>`` session id."""
        with self._counter_lock:
            self._counter += 1
            return f"sock-{self._counter}"

    def connection_opened(self) -> None:
        """Record a newly accepted client connection (additive UI status counter)."""
        with self._active_lock:
            self._active += 1

    def connection_closed(self) -> None:
        """Record a closed client connection (additive UI status counter)."""
        with self._active_lock:
            if self._active > 0:
                self._active -= 1

    def connection_count(self) -> int:
        """Return the number of currently connected clients."""
        with self._active_lock:
            return self._active

    def process_line(self, line: bytes, session_id: str) -> dict[str, Any]:
        """Parse and handle one request line, returning the response object."""
        try:
            request = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {
                "id": None,
                "ok": False,
                "error": {"code": "BAD_REQUEST", "message": "malformed_json", "details": {}},
            }
        if not isinstance(request, dict):
            return {
                "id": None,
                "ok": False,
                "error": {"code": "BAD_REQUEST", "message": "malformed_request", "details": {}},
            }
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}
        token = request.get("token")
        if not isinstance(method, str) or not method:
            return {
                "id": request_id,
                "ok": False,
                "error": {"code": "BAD_REQUEST", "message": "missing_method", "details": {}},
            }
        if not isinstance(token, str) or not hmac.compare_digest(token, self.mcp_token):
            self.service._log(
                role=ROLE_MCP,
                tool=method,
                target=Service._target_path(params if isinstance(params, dict) else {}),
                outcome="deny",
                code="UNAUTHORIZED",
                session_id=session_id,
                source="socket",
            )
            return {
                "id": request_id,
                "ok": False,
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "invalid_token",
                    "details": {},
                },
            }
        try:
            result = self.service.dispatch(
                method, params, role=ROLE_MCP, session_id=session_id
            )
        except VaultError as exc:
            return _error_response(request_id, exc)
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the client
            LOG.debug("internal error handling %s: %r", method, exc)
            return {
                "id": request_id,
                "ok": False,
                "error": {"code": "BAD_REQUEST", "message": "internal_error", "details": {}},
            }
        return {"id": request_id, "ok": True, "result": result}


__all__ = [
    "VaultSocketServer",
    "ENDPOINT_FILENAME",
    "SOCKET_FILENAME",
    "TOKENS_FILENAME",
]
