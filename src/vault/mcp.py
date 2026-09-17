"""Console entry for the MCP stdio bridge (``python -m vault.mcp``).

A thin, stateless process spawned by the agent runtime: it speaks MCP JSON-RPC on stdio
and forwards each call to the daemon over the Unix socket with the ``mcp`` role token.
It never touches the vault files and never prints anything but protocol JSON on stdout.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Iterator

from .api.client import VaultClient
from .api.mcp_server import MCPServer

LOG = logging.getLogger(__name__)


@contextlib.contextmanager
def _selftest_daemon() -> Iterator[object]:
    """Run an in-process fake daemon on a scratch vault (``--selftest``)."""
    from .api.service import Service
    from .api.socket_server import VaultSocketServer
    from .core.session import VaultSession

    base = Path(tempfile.mkdtemp(prefix="sv-mcp-selftest-"))
    previous = os.environ.get("XDG_RUNTIME_DIR")
    os.environ["XDG_RUNTIME_DIR"] = str(base)
    try:
        session = VaultSession.create(base / "vault", "selftest-password")
        server = VaultSocketServer(Service(session))
        server.start()
        try:
            yield server
        finally:
            server.stop()
            session.close()
    finally:
        if previous is None:
            os.environ.pop("XDG_RUNTIME_DIR", None)
        else:
            os.environ["XDG_RUNTIME_DIR"] = previous
        shutil.rmtree(base, ignore_errors=True)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the bridge command line."""
    parser = argparse.ArgumentParser(
        prog="vault.mcp", description="Secure Vault MCP stdio bridge."
    )
    parser.add_argument("--socket", default=None, help="daemon socket path")
    parser.add_argument("--token", default=None, help="mcp role token")
    parser.add_argument(
        "--selftest", action="store_true", help="run an in-process fake daemon"
    )
    parser.add_argument("--debug", action="store_true", help="diagnostics on stderr")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the MCP bridge and return the process exit code."""
    args = _parse_args(argv)
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if args.selftest:
        with _selftest_daemon() as server:
            client = VaultClient(
                socket_path=server.socket_path, token=server.mcp_token  # type: ignore[attr-defined]
            )
            return MCPServer(client, debug=args.debug).serve()

    socket_path = args.socket or os.environ.get("SECURE_VAULT_SOCKET")
    token = args.token or os.environ.get("SECURE_VAULT_TOKEN")
    if socket_path and token:
        client = VaultClient(socket_path=Path(socket_path), token=token)
    else:
        client = VaultClient.from_runtime(role="mcp")
    return MCPServer(client, debug=args.debug).serve()


if __name__ == "__main__":
    raise SystemExit(main())
