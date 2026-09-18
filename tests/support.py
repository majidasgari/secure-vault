"""Shared test helpers (SPEC/06 §1).

Phase P1 helpers (``tmp_vault``/``scratch_home``/...) plus the P2 socket/MCP helpers
``fake_daemon`` and ``mcp_stdio``. Tests never touch the user's real vault home or the
real Joplin mirror.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

from vault.core.session import VaultSession
from vault.core.store import SecureStore
from vault.core.vaultfs import VaultFS

DEFAULT_PASSWORD = "correct horse battery staple"

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"


def scratch_home(tmpdir: Path | str | None = None) -> Path:
    """Return a fresh scratch directory, never the user's real vault home."""
    if tmpdir is not None:
        base = Path(tmpdir) / f"scratch-{uuid.uuid4().hex[:8]}"
        base.mkdir(parents=True, exist_ok=True)
        return base
    return Path(tempfile.mkdtemp(prefix="sv-scratch-"))


def tmp_vault(
    tmpdir: Path | str | None = None,
    *,
    password: str = DEFAULT_PASSWORD,
    settings: dict | None = None,
    plain_threshold: int | None = None,
) -> VaultSession:
    """Create an unlocked vault in a scratch directory and return its session."""
    base = scratch_home(tmpdir)
    home = base / "vault"
    runtime = base / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    os.chmod(runtime, 0o700)
    session = VaultSession.create(home, password, settings=settings)
    session._runtime = runtime
    if session._store is not None:
        master_key = session._master_key
        session._store.close()
        session._store = SecureStore.open(home, master_key, runtime)
    if plain_threshold is not None:
        session._plain_threshold_override = plain_threshold
        session._fs = VaultFS(
            home, session._index, session._master_key, plain_threshold=plain_threshold
        )
    # Keep the semantic cache inside the scratch dir instead of the user's home.
    semantic = session.meta.settings.setdefault("semantic", {})
    if not semantic.get("db_path"):
        semantic["db_path"] = str(base / "semantic.db")
        session.meta.save()
    return session


def assert_no_plaintext(root: Path | str, needles: list[bytes]) -> None:
    """Assert none of ``needles`` appear in any file under ``root``."""
    root = Path(root)
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:  # pragma: no cover - transient files
            continue
        for needle in needles:
            if needle and needle in data:
                raise AssertionError(f"plaintext {needle!r} found in {path}")


def assert_under(path: Path | str, root: Path | str) -> None:
    """Assert ``path`` resolves to a location inside ``root``."""
    resolved = Path(path).resolve()
    root_resolved = Path(root).resolve()
    if root_resolved != resolved and root_resolved not in resolved.parents:
        raise AssertionError(f"{resolved} is not under {root_resolved}")


# --------------------------------------------------------------------------- socket
class FakeDaemon:
    """An in-process socket server with a known ``mcp`` token (SPEC/06 §1)."""

    def __init__(
        self,
        session: VaultSession,
        *,
        runtime: Path | str | None = None,
        token: str | None = None,
    ) -> None:
        """Start a :class:`VaultSocketServer` for ``session`` on a scratch runtime dir."""
        from vault.api.service import Service
        from vault.api.socket_server import VaultSocketServer

        self.session = session
        self.runtime = Path(runtime) if runtime is not None else Path(session._runtime)
        self.runtime.mkdir(parents=True, exist_ok=True)
        os.chmod(self.runtime, 0o700)
        self.server = VaultSocketServer(
            Service(session), runtime_dir=self.runtime, token=token
        )
        self.server.start()

    @property
    def socket_path(self) -> Path:
        """The daemon socket path."""
        return self.server.socket_path

    @property
    def token(self) -> str:
        """The ``mcp`` role token."""
        return self.server.mcp_token

    def client(self, *, role: str = "mcp") -> Any:
        """Return a :class:`VaultClient` bound to this fake daemon."""
        from vault.api.client import VaultClient

        token = self.token if role == "mcp" else None
        return VaultClient(socket_path=self.socket_path, token=token)

    def stop(self) -> None:
        """Stop the server."""
        self.server.stop()

    def __enter__(self) -> "FakeDaemon":
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


def fake_daemon(session: VaultSession, **kwargs: Any) -> FakeDaemon:
    """Start an in-process socket server for ``session`` (see :class:`FakeDaemon`)."""
    return FakeDaemon(session, **kwargs)


# ------------------------------------------------------------------------------ MCP
class MCPProcess:
    """Context manager driving a real ``python -m vault.mcp`` subprocess over stdio."""

    def __init__(
        self,
        env_overrides: dict[str, str] | None = None,
        *,
        args: list[str] | None = None,
    ) -> None:
        """Spawn the bridge with ``env_overrides`` merged into the environment."""
        env = os.environ.copy()
        pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            f"{SRC_ROOT}{os.pathsep}{pythonpath}" if pythonpath else str(SRC_ROOT)
        )
        if env_overrides:
            env.update({str(key): str(value) for key, value in env_overrides.items()})
        command = [sys.executable, "-m", "vault.mcp", *(args or [])]
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(REPO_ROOT),
        )
        self._buffer = b""

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> "MCPProcess":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close stdin and terminate the bridge if it is still running."""
        try:
            if self.proc.stdin is not None:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5.0)

    # ------------------------------------------------------------------- transport
    def send(self, message: dict) -> None:
        """Write one JSON message line to the bridge."""
        self.send_raw(json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n")

    def send_raw(self, data: bytes) -> None:
        """Write raw bytes to the bridge's stdin."""
        assert self.proc.stdin is not None
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def read_line(self, timeout: float = 10.0) -> bytes:
        """Read one stdout line from the bridge, or raise on timeout/EOF."""
        deadline = time.time() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for an MCP response")
            assert self.proc.stdout is not None
            ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if not ready:
                raise TimeoutError("timed out waiting for an MCP response")
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if not chunk:
                raise EOFError("the MCP bridge exited unexpectedly")
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return line

    def read_response(self, timeout: float = 10.0) -> dict:
        """Read one stdout line and decode it as JSON."""
        return json.loads(self.read_line(timeout).decode("utf-8"))

    def request(self, method: str, params: dict | None = None, *, id: Any = 1) -> dict:
        """Send a request and return the decoded response."""
        self.send({"jsonrpc": "2.0", "id": id, "method": method, "params": params or {}})
        return self.read_response()

    def notify(self, method: str, params: dict | None = None) -> None:
        """Send a notification (no response is expected)."""
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def tool(self, name: str, arguments: dict | None = None, *, id: Any = 1) -> dict:
        """Call one MCP tool and return the raw response."""
        return self.request(
            "tools/call", {"name": name, "arguments": arguments or {}}, id=id
        )

    def stderr_text(self) -> str:
        """Return whatever the bridge has written to stderr so far."""
        assert self.proc.stderr is not None
        try:
            ready, _, _ = select.select([self.proc.stderr], [], [], 0)
        except (ValueError, OSError):
            return ""
        if not ready:
            return ""
        return os.read(self.proc.stderr.fileno(), 65536).decode("utf-8", "replace")


def mcp_stdio(
    env_overrides: dict[str, str] | None = None, *, args: list[str] | None = None
) -> MCPProcess:
    """Spawn ``python -m vault.mcp`` over stdio (see :class:`MCPProcess`)."""
    return MCPProcess(env_overrides, args=args)


def iter_json_lines(process: MCPProcess) -> Iterator[dict]:
    """Yield decoded JSON objects from the bridge's stdout (for protocol assertions)."""
    while True:
        try:
            yield process.read_response(timeout=0.5)
        except (TimeoutError, EOFError):
            return


__all__ = [
    "DEFAULT_PASSWORD",
    "REPO_ROOT",
    "SRC_ROOT",
    "scratch_home",
    "tmp_vault",
    "assert_no_plaintext",
    "assert_under",
    "FakeDaemon",
    "fake_daemon",
    "MCPProcess",
    "mcp_stdio",
    "iter_json_lines",
]
