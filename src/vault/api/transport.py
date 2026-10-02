"""Transport for the local daemon endpoint (SPEC/02 §2/§3, Windows port).

On POSIX the daemon listens on a Unix-domain socket (``runtime_dir()/daemon.sock``) and the
filesystem permissions are what keeps other users out. Windows has no ``AF_UNIX`` support in
CPython, so there the daemon binds a **loopback TCP** port (``127.0.0.1``) with an ephemeral
port number instead. In both cases the endpoint is published as JSON next to the token, in
``runtime_dir()/endpoint.json``:

.. code-block:: json

    {"kind": "unix", "path": ".../daemon.sock"}
    {"kind": "tcp", "host": "127.0.0.1", "port": 51234}

Authentication is unchanged and transport-independent: every request must carry the ``mcp``
token from ``runtime_dir()/tokens.json`` (written with mode ``0600``), so a TCP endpoint is
not a wider door than the socket it replaces — an unauthenticated local process gets
``UNAUTHORIZED`` on both. The port is bound to the loopback interface only.

Two environment overrides exist for tests, tools and the MCP bridge:

* ``SECURE_VAULT_SOCKET`` — a Unix socket path (POSIX only, kept for compatibility);
* ``SECURE_VAULT_ENDPOINT`` — the endpoint as JSON or as ``host:port``.

Both ``vault.mcp --socket`` and ``vault.mcp --endpoint`` also accept them on the command line.
"""

from __future__ import annotations

import json
import os
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..util import atomic_write_bytes

SOCKET_FILENAME = "daemon.sock"
ENDPOINT_FILENAME = "endpoint.json"
DEFAULT_TCP_HOST = "127.0.0.1"

UNIX = "unix"
TCP = "tcp"


def unix_sockets_available() -> bool:
    """Return True when this interpreter can create ``AF_UNIX`` sockets (all POSIX)."""
    return hasattr(socket, "AF_UNIX")


@dataclass(frozen=True)
class Endpoint:
    """Where the local daemon listens: a Unix socket path or a loopback TCP port."""

    kind: str
    path: Path | None = None
    host: str | None = None
    port: int | None = None

    @classmethod
    def unix(cls, path: Path | str) -> "Endpoint":
        """Return a Unix-socket endpoint for ``path``."""
        return cls(kind=UNIX, path=Path(path))

    @classmethod
    def tcp(cls, host: str = DEFAULT_TCP_HOST, port: int = 0) -> "Endpoint":
        """Return a loopback TCP endpoint (``port 0`` means "the server picks one")."""
        return cls(kind=TCP, host=host, port=int(port))

    @classmethod
    def parse(cls, value: Any) -> "Endpoint":
        """Parse a JSON mapping, an ``Endpoint``, a ``host:port`` string or a path.

        Raises:
            ValueError: when the value cannot be understood as an endpoint.
        """
        if isinstance(value, Endpoint):
            return value
        if isinstance(value, dict):
            kind = str(value.get("kind") or "").strip().lower()
            if kind == TCP:
                return cls.tcp(
                    str(value.get("host") or DEFAULT_TCP_HOST), int(value.get("port") or 0)
                )
            if kind == UNIX or value.get("path"):
                return cls.unix(value.get("path"))
            raise ValueError(f"unknown endpoint kind: {value!r}")
        if isinstance(value, (str, os.PathLike)):
            text = str(value)
            if text.endswith(".json"):
                return cls.parse(json.loads(Path(text).read_text(encoding="utf-8")))
            # ``host:port`` only when it cannot be a filesystem path: no separators, a
            # numeric port. Anything else (``/tmp/x.sock``, ``C:\...\daemon.sock``) is a path.
            match = re.fullmatch(r"[^\s/\\]+:(\d+)", text)
            if match:
                host, _, port = text.rpartition(":")
                return cls.tcp(host or DEFAULT_TCP_HOST, int(port))
            return cls.unix(text)
        raise ValueError(f"cannot parse endpoint: {value!r}")

    # ------------------------------------------------------------------ helpers
    @property
    def is_unix(self) -> bool:
        """True for a Unix-socket endpoint."""
        return self.kind == UNIX

    def display(self) -> str:
        """Return a short human-readable description (used in errors and the UI)."""
        if self.is_unix:
            return str(self.path)
        return f"{self.host}:{self.port}"

    def to_json(self) -> dict[str, Any]:
        """Return the JSON-serialisable form written to ``endpoint.json``."""
        if self.is_unix:
            return {"kind": UNIX, "path": str(self.path)}
        return {"kind": TCP, "host": self.host, "port": int(self.port or 0)}

    def with_port(self, port: int) -> "Endpoint":
        """Return a copy of a TCP endpoint bound to the server's real port."""
        return Endpoint(kind=self.kind, path=self.path, host=self.host, port=int(port))

    def connect(self, timeout: float) -> socket.socket:
        """Return a connected socket to this endpoint.

        Raises:
            OSError: when nothing is listening (the caller maps it to ``VaultNotRunning``).
        """
        if self.is_unix and not unix_sockets_available():
            raise OSError("AF_UNIX sockets are not available on this platform")
        if self.is_unix:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if self.is_unix:
                sock.connect(str(self.path))
            else:
                sock.connect((str(self.host or DEFAULT_TCP_HOST), int(self.port or 0)))
        except OSError:
            sock.close()
            raise
        return sock


def endpoint_path(runtime_dir: Path | str) -> Path:
    """Return the published endpoint file inside ``runtime_dir``."""
    return Path(runtime_dir) / ENDPOINT_FILENAME


def write_endpoint(runtime_dir: Path | str, endpoint: Endpoint) -> Path:
    """Atomically publish ``endpoint`` into ``runtime_dir`` and return the file path."""
    path = endpoint_path(runtime_dir)
    payload = json.dumps(endpoint.to_json(), ensure_ascii=False, indent=2).encode("utf-8")
    atomic_write_bytes(path, payload)
    return path


def read_endpoint(runtime_dir: Path | str) -> Endpoint | None:
    """Return the published endpoint, or ``None`` when it is missing/unreadable."""
    path = endpoint_path(runtime_dir)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    try:
        return Endpoint.parse(data)
    except (ValueError, TypeError):
        return None


def default_endpoint(runtime_dir: Path | str) -> Endpoint:
    """Return the endpoint to use when nothing was published yet.

    POSIX falls back to the traditional Unix socket path (that is what a bridge started
    before the app was unlocked expects); Windows has no socket path to fall back to, so it
    returns the conventional loopback port of the *published* endpoint only — a missing
    ``endpoint.json`` on Windows means "no daemon", which the caller reports honestly.
    """
    if unix_sockets_available():
        return Endpoint.unix(Path(runtime_dir) / SOCKET_FILENAME)
    return Endpoint.tcp(DEFAULT_TCP_HOST, 0)


def resolve_endpoint(
    runtime_dir: Path | str, *, socket_path: Path | str | None = None
) -> Endpoint:
    """Return the endpoint for ``runtime_dir``, honouring env overrides and the file.

    Precedence: an explicit ``socket_path`` argument, then ``SECURE_VAULT_ENDPOINT``, then
    ``SECURE_VAULT_SOCKET``, then the published ``endpoint.json``, then the platform default.
    """
    if socket_path is not None:
        return Endpoint.unix(socket_path)
    value = os.environ.get("SECURE_VAULT_ENDPOINT")
    if value:
        try:
            return Endpoint.parse(value)
        except (ValueError, OSError, TypeError):
            pass
    socket_env = os.environ.get("SECURE_VAULT_SOCKET")
    if socket_env:
        return Endpoint.unix(socket_env)
    published = read_endpoint(runtime_dir)
    if published is not None and (published.is_unix or published.port):
        return published
    return default_endpoint(runtime_dir)


__all__ = [
    "DEFAULT_TCP_HOST",
    "ENDPOINT_FILENAME",
    "SOCKET_FILENAME",
    "TCP",
    "UNIX",
    "Endpoint",
    "default_endpoint",
    "endpoint_path",
    "read_endpoint",
    "resolve_endpoint",
    "unix_sockets_available",
    "write_endpoint",
]
