"""Local Unix-socket JSON-RPC server (SPEC/02 §2).

Newline-delimited JSON: one request per line, one response per line, in order per
connection. Authentication is a per-daemon ``mcp`` token written to
``runtime_dir()/tokens.json`` (mode ``0600``); the UI never uses the socket because it
calls :class:`~vault.api.service.Service` in-process.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import socket
import socketserver
import threading
from pathlib import Path
from typing import Any

from ..config import runtime_dir as default_runtime_dir
from ..errors import AlreadyExists, VaultError
from ..util import atomic_write_bytes, now_ms
from .service import ROLE_MCP, Service

LOG = logging.getLogger(__name__)

SOCKET_FILENAME = "daemon.sock"
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


class _ThreadingUnixServer(socketserver.ThreadingUnixStreamServer):
    """Threading Unix stream server with per-connection handler threads."""

    daemon_threads = True
    allow_reuse_address = True


class VaultSocketServer:
    """Owns the Unix socket, the ``mcp`` token file and the request loop."""

    def __init__(
        self,
        service: Service,
        *,
        socket_path: Path | str | None = None,
        runtime_dir: Path | str | None = None,
        token: str | None = None,
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
        self.token_file = self.runtime_dir / TOKENS_FILENAME
        self.mcp_token = token or secrets.token_hex(32)
        self._server: _ThreadingUnixServer | None = None
        self._thread: threading.Thread | None = None
        self._counter = 0
        self._counter_lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Write the token file, bind the socket and start serving in a thread.

        Raises:
            AlreadyExists: when another live daemon already answers on the socket.
        """
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.runtime_dir, 0o700)
        except OSError:  # pragma: no cover - best effort
            pass
        self._write_tokens()
        self._bind()
        assert self._server is not None
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="vault-socket", daemon=True
        )
        self._thread.start()

    def _write_tokens(self) -> None:
        """Atomically write ``tokens.json`` with mode ``0600``."""
        payload = json.dumps(
            {"mcp": self.mcp_token, "created_at": now_ms()}, ensure_ascii=False
        ).encode("utf-8")
        atomic_write_bytes(self.token_file, payload)
        try:
            os.chmod(self.token_file, 0o600)
        except OSError:  # pragma: no cover - best effort
            pass

    def _bind(self) -> None:
        """Bind the socket, refusing to clobber a live daemon."""
        path = self.socket_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(0.5)
            try:
                probe.connect(str(path))
            except OSError:
                probe.close()
                try:
                    path.unlink()
                except FileNotFoundError:  # pragma: no cover - race
                    pass
            else:
                probe.close()
                raise AlreadyExists(
                    "daemon_already_running", details={"socket": str(path)}
                )
        self._server = _ThreadingUnixServer(str(path), _RequestHandler)
        self._server.service = self  # type: ignore[attr-defined]
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - best effort
            pass

    def stop(self) -> None:
        """Stop serving, remove the socket and the token file."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        for path in (self.socket_path, self.token_file):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

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
    "SOCKET_FILENAME",
    "TOKENS_FILENAME",
]
