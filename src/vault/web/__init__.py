"""Secure Vault web UI (phase P7; SPEC/07).

``python -m vault.web`` starts an HTTP server that owns the :class:`VaultSession`
(the web process is the key holder, exactly like the GUI) and serves a browser SPA
plus a JSON API built on :meth:`~vault.api.service.Service.dispatch` with
``role="ui"``. The vault is unlocked from the browser, but the derived keys never
leave the process.

Usage::

    python -m vault.web --home /path/to/vault --port 8788
    python -m vault.web --host 0.0.0.0 --port 8788 --allow-lan   # explicit opt-in
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import signal
import sys
import threading
from pathlib import Path

from .auth import LoginThrottle, TokenAuth
from .events import EventBus
from .server import WebServer
from ..util import is_loopback

LOG = logging.getLogger("vault.web")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8788


def _is_loopback(host: str) -> bool:
    """Return True for ``localhost`` and any loopback IP literal (shared with the HTTP layer)."""
    return is_loopback(host)


def _setup_logging(debug: bool) -> None:
    """Configure stderr logging (the token is never written to a log file)."""
    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)
    if not any(
        isinstance(handler, logging.StreamHandler) for handler in root.handlers
    ):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        root.addHandler(handler)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the web server command line."""
    parser = argparse.ArgumentParser(
        prog="vault.web", description="Secure Vault web UI server."
    )
    parser.add_argument("--home", default=None, help="vault home directory")
    parser.add_argument(
        "--host", default=DEFAULT_HOST, help="bind address (loopback by default)"
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help="TCP port (0 = pick a free one)"
    )
    parser.add_argument(
        "--allow-lan",
        action="store_true",
        help="allow binding a non-loopback host (exposes the vault on the network)",
    )
    parser.add_argument(
        "--unlock-file", default=None, help="0600 file containing the master password"
    )
    parser.add_argument(
        "--no-mcp",
        action="store_true",
        help="do not start the local MCP socket server",
    )
    parser.add_argument(
        "--json-events", action="store_true", help="emit a JSON ready event on stdout"
    )
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Start the web UI server and block until SIGTERM/SIGINT."""
    args = _parse_args(argv)
    _setup_logging(args.debug)

    if not _is_loopback(args.host) and not args.allow_lan:
        print(
            f"vault.web: refusing to bind non-loopback host {args.host!r}; "
            "pass --allow-lan to expose the vault on the network",
            file=sys.stderr,
        )
        return 2

    from ..api.service import Service
    from ..api.socket_server import VaultSocketServer
    from ..core.session import VaultSession
    from ..daemon import _read_unlock_file, _resolve_home

    home = _resolve_home(args.home)
    password: str | None = None
    if args.unlock_file:
        try:
            password = _read_unlock_file(args.unlock_file)
        except (OSError, PermissionError) as exc:
            LOG.error("refusing --unlock-file: %s", exc)
            return 2

    try:
        if VaultSession.is_initialised(home):
            session = VaultSession(home)
            if password is not None:
                session.unlock(password)
        else:
            if password is None:
                LOG.error(
                    "vault at %s is not initialised and no --unlock-file was given",
                    home,
                )
                return 2
            session = VaultSession.create(home, password)
    except Exception as exc:  # noqa: BLE001 - report startup failures clearly
        LOG.error("could not open the vault at %s: %s", home, exc)
        return 1

    service = Service(session)
    server = WebServer(service, host=args.host, port=args.port)

    def _on_secret_request(request: dict) -> str:
        """Fan an agent's secret request out to the browser over SSE."""
        server.events.publish(
            "secret_request",
            {
                "request_id": request.get("request_id"),
                "path": request.get("path"),
                "status": request.get("status", "pending"),
            },
        )
        return "pending"

    session.on_secret_request = _on_secret_request

    socket_server = None
    if not args.no_mcp:
        try:
            socket_server = VaultSocketServer(service)
            socket_server.start()
        except Exception as exc:  # noqa: BLE001 - MCP is best effort here
            LOG.warning("could not start the MCP socket server: %s", exc)
            socket_server = None

    try:
        server.start()
    except OSError as exc:
        LOG.error("could not bind %s:%s: %s", args.host, args.port, exc)
        server.stop()
        if socket_server is not None:
            socket_server.stop()
        session.close()
        return 1

    url = server.url
    token = server.token
    if not _is_loopback(args.host):
        print(
            f"WARNING: the vault is exposed on the network at {url} — anyone with "
            "the token can read it.",
            file=sys.stderr,
        )
    print(f"Secure Vault web UI: {url}", file=sys.stderr)
    print(f"Access token: {token}", file=sys.stderr, flush=True)
    if args.json_events:
        event = {
            "event": "ready",
            "url": url,
            "home": str(home),
            "locked": bool(session.is_locked),
            "token_file": str(server.auth.token_file),
        }
        print(json.dumps(event, ensure_ascii=False), flush=True)

    stop = threading.Event()

    def _handle(signum: int, frame: object) -> None:
        LOG.info("received signal %s, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    try:
        stop.wait()
    finally:
        server.stop()
        if socket_server is not None:
            socket_server.stop()
        session.close()
    return 0


__all__ = [
    "main",
    "WebServer",
    "TokenAuth",
    "LoginThrottle",
    "EventBus",
]
