"""Client for the local Unix-socket JSON-RPC server (SPEC/02 §3).

Used by the MCP bridge and by any external agent. One short-lived connection per call
keeps the client stateless; responses are newline-delimited JSON.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from .. import errors
from ..config import runtime_dir
from ..errors import VaultError, VaultNotRunning
from .socket_server import SOCKET_FILENAME, TOKENS_FILENAME

_DEFAULT_TIMEOUT = 30.0


def _error_class(code: str) -> type[VaultError]:
    """Return the :class:`VaultError` subclass carrying ``code`` (or the base class)."""
    for name in errors.__all__:
        obj = getattr(errors, name)
        if isinstance(obj, type) and issubclass(obj, VaultError) and obj.code == code:
            return obj
    return VaultError


class VaultClient:
    """Thin JSON-RPC client for ``runtime_dir()/daemon.sock``."""

    def __init__(
        self,
        *,
        socket_path: Path | str | None = None,
        token: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        """Create a client for ``socket_path`` presenting ``token``."""
        self.socket_path = (
            Path(socket_path) if socket_path is not None else runtime_dir() / SOCKET_FILENAME
        )
        self.token = token
        self.timeout = float(timeout)

    @classmethod
    def from_runtime(cls, *, role: str = "mcp") -> "VaultClient":
        """Build a client by reading the token from ``runtime_dir()/tokens.json``.

        Raises:
            VaultNotRunning: when the daemon has not written its runtime files.
        """
        runtime = runtime_dir()
        token_file = runtime / TOKENS_FILENAME
        try:
            data = json.loads(token_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VaultNotRunning(
                "daemon is not running — start `secure-vault`",
                details={"socket": str(runtime / SOCKET_FILENAME)},
            ) from exc
        token = data.get(role) if isinstance(data, dict) else None
        return cls(socket_path=runtime / SOCKET_FILENAME, token=token)

    # ---------------------------------------------------------------------- calls
    def call(self, method: str, params: dict | None = None) -> dict:
        """Send one request and return its result.

        Raises:
            VaultNotRunning: when the socket is missing or refuses the connection.
            VaultError: the subclass matching the server's error ``code``.
        """
        request = {
            "id": 1,
            "token": self.token,
            "method": method,
            "params": params or {},
        }
        response = self._roundtrip(request)
        if not isinstance(response, dict):
            raise VaultError("bad_response", details={"method": method})
        if response.get("ok"):
            result = response.get("result")
            return result if isinstance(result, dict) else {}
        error = response.get("error") or {}
        code = str(error.get("code", "ERROR"))
        message = str(error.get("message", code))
        details = error.get("details")
        exc_type = _error_class(code)
        raise exc_type(message, details=details if isinstance(details, dict) else {})

    def ping(self) -> dict:
        """Call ``vault.ping`` and return the liveness payload."""
        return self.call("vault.ping", {})

    def close(self) -> None:
        """Release resources (connections are per-call, so this is a no-op)."""
        return None

    # ------------------------------------------------------------------- internal
    def _roundtrip(self, request: dict) -> dict:
        """Open a connection, send one request line and read one response line."""
        payload = json.dumps(request, ensure_ascii=False).encode("utf-8") + b"\n"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(str(self.socket_path))
        except (FileNotFoundError, ConnectionRefusedError, NotADirectoryError) as exc:
            sock.close()
            raise VaultNotRunning(
                "daemon is not running — start `secure-vault`",
                details={"socket": str(self.socket_path)},
            ) from exc
        except OSError as exc:
            sock.close()
            raise VaultNotRunning(
                "daemon is not running — start `secure-vault`",
                details={"socket": str(self.socket_path), "reason": str(exc)},
            ) from exc
        try:
            sock.sendall(payload)
            line = self._read_line(sock)
        finally:
            sock.close()
        if not line:
            raise VaultNotRunning(
                "daemon closed the connection",
                details={"socket": str(self.socket_path)},
            )
        try:
            return json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise VaultError("bad_response", details={"reason": str(exc)}) from exc

    @staticmethod
    def _read_line(sock: socket.socket) -> bytes:
        """Read bytes from ``sock`` until the first newline."""
        buffer = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                return bytes(buffer)
            if not chunk:
                return bytes(buffer)
            buffer.extend(chunk)
            if b"\n" in buffer:
                line, _, _ = bytes(buffer).partition(b"\n")
                return line
            if len(buffer) > 8 * 1024 * 1024:  # pragma: no cover - defensive
                raise VaultError("response_too_large")


class RefreshingClient(VaultClient):
    """Lazy ``VaultClient`` that re-reads the runtime token after the app restarts.

    The app rotates ``runtime_dir()/tokens.json`` on every start, so a bridge spawned by
    an agent runtime (Hermes/Claude, a long-lived gateway) is left holding a dead token
    after the user restarts the app — every call then answers ``UNAUTHORIZED: invalid_token``
    until the agent itself restarts. This subclass resolves the token on first use and
    re-resolves it (then retries once) when the daemon rejects the one it holds, so no
    denied row is ever written to the access log.
    """

    def __init__(self) -> None:
        """Start without credentials; they are read from the runtime dir on first use."""
        super().__init__(socket_path=None, token=None)
        self._resolved = False

    def _resolve(self) -> None:
        """Copy socket path and token out of ``runtime_dir()`` (raises VaultNotRunning)."""
        fresh = VaultClient.from_runtime(role="mcp")
        self.socket_path = fresh.socket_path
        self.token = fresh.token
        self._resolved = True

    def call(self, method: str, params: dict | None = None) -> dict:
        """Forward one call, re-reading the token once if the daemon rotated it."""
        if not self._resolved:
            self._resolve()
        try:
            return super().call(method, params)
        except VaultError as exc:
            if exc.code != "UNAUTHORIZED":
                raise
            self._resolved = False
            self._resolve()
            return super().call(method, params)


__all__ = ["RefreshingClient", "VaultClient"]
