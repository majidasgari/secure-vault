"""Headless daemon entry point (``python -m vault.daemon``; SPEC/02 §5).

Runs the same service as the GUI without Qt: it owns a :class:`VaultSession` and serves
the local Unix socket for agents. Used by the smoke tests and by anyone who wants the
vault available without a GUI.
"""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import signal
import sys
import threading
from pathlib import Path

from .api.service import Service
from .api.socket_server import VaultSocketServer
from .config import DEFAULT_VAULT_HOME, user_config, user_state_dir
from .core.session import VaultSession

LOG = logging.getLogger("vault.daemon")


def _resolve_home(explicit: str | None) -> Path:
    """Resolve the vault home from the CLI, the environment or the user config."""
    if explicit:
        return Path(explicit)
    env_home = os.environ.get("SECURE_VAULT_HOME")
    if env_home:
        return Path(env_home)
    try:
        last = user_config().data.get("last_vault_home")
    except Exception:  # noqa: BLE001 - config must never stop the daemon
        last = None
    if isinstance(last, str) and last:
        return Path(last)
    return Path(DEFAULT_VAULT_HOME)


def _read_unlock_file(path: str) -> str:
    """Read the master password from a ``0600`` file (never from argv).

    On Windows there are no POSIX mode bits (``st_mode`` always reports ``0o666``), so the
    permission check is POSIX-only; keep the file inside your user profile there.
    """
    unlock_path = Path(path)
    stat = unlock_path.stat()
    mode = stat.st_mode & 0o777
    if os.name != "nt" and mode != 0o600:
        raise PermissionError(
            f"unlock file {unlock_path} has mode {oct(mode)}; expected 0o600"
        )
    return unlock_path.read_text(encoding="utf-8").rstrip("\n")


def _setup_logging(debug: bool) -> None:
    """Log to stderr and to a rotating file under the per-user state directory."""
    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    root.addHandler(stream)
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            user_state_dir() / "daemon.log", maxBytes=1_000_000, backupCount=3
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as exc:  # pragma: no cover - best effort
        LOG.warning("could not open the daemon log file: %s", exc)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the daemon command line."""
    parser = argparse.ArgumentParser(
        prog="vault.daemon", description="Secure Vault headless daemon."
    )
    parser.add_argument("--home", default=None, help="vault home directory")
    parser.add_argument(
        "--unlock-file", default=None, help="0600 file containing the master password"
    )
    parser.add_argument("--socket", default=None, help="socket path override")
    parser.add_argument(
        "--json-events", action="store_true", help="emit JSON events on stdout"
    )
    parser.add_argument(
        "--import-s3",
        action="store_true",
        help=(
            "restore the vault stored in the S3 bucket into --home before serving "
            "(coordinates come from the saved credentials; see secure-vault-import)"
        ),
    )
    parser.add_argument(
        "--import-replace",
        action="store_true",
        help="with --import-s3: park a different vault already in --home instead of refusing",
    )
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    return parser.parse_args(argv)


def _restore_from_s3(
    home: Path, *, password: str | None = None, replace: bool = False
) -> int:
    """Adopt the vault stored in the S3 bucket into ``home`` (0 on success).

    Coordinates and credentials are the machine-local ones (the same file the app writes),
    so a headless host is brought up with ``--import-s3`` after the bucket has been set up
    once with ``secure-vault-import``.
    """
    from .config import load_sync_config
    from .core import remote_import
    from .core.s3 import S3Client, S3Config
    from .errors import VaultError

    saved = load_sync_config()
    source = saved.get("last_source")
    source = source if isinstance(source, dict) else {}
    config = S3Config(
        enabled=True,
        bucket=str(source.get("bucket") or ""),
        prefix=str(source.get("prefix") or ""),
        endpoint=str(source.get("endpoint") or ""),
        region=str(source.get("region") or ""),
        access_key=str(saved.get("access_key") or ""),
        secret_key=str(saved.get("secret_key") or ""),
    )
    if not config.configured:
        LOG.error(
            "--import-s3 needs saved S3 coordinates and credentials "
            "(run secure-vault-import once, or set them in the app)"
        )
        return 2

    def progress(phase: str, done: int, total: int) -> None:
        """Log every phase change at INFO."""
        if phase == "files" and total:
            LOG.info("restoring: %d/%d files", done, total)
        else:
            LOG.info("restoring: %s", phase)

    try:
        report = remote_import.import_vault(
            S3Client(config), config, home, password=password, progress=progress, replace=replace
        )
    except VaultError as exc:
        LOG.error("restore from S3 failed: %s", getattr(exc, "message", str(exc)))
        return 2
    LOG.info(
        "restored vault %s: %d files + %d folders into %s",
        report.vault_id,
        report.files,
        report.folders,
        report.home,
    )
    if report.replaced:
        LOG.info("the previous vault was parked at %s", report.parked_at)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Start the headless daemon and block until SIGTERM/SIGINT."""
    args = _parse_args(argv)
    _setup_logging(args.debug)
    home = _resolve_home(args.home)

    password: str | None = None
    if args.unlock_file:
        try:
            password = _read_unlock_file(args.unlock_file)
        except (OSError, PermissionError) as exc:
            LOG.error("refusing --unlock-file: %s", exc)
            return 2

    if args.import_s3:
        restored = _restore_from_s3(home, password=password, replace=args.import_replace)
        if restored != 0:
            return restored

    if VaultSession.is_initialised(home):
        session = VaultSession(home)
        if password is not None:
            session.unlock(password)
    else:
        if password is None:
            LOG.error(
                "vault at %s is not initialised and no --unlock-file was given "
                "(use --import-s3 to adopt a vault that is already in the bucket)",
                home,
            )
            return 2
        session = VaultSession.create(home, password)

    runtime_dir = Path(args.socket).parent if args.socket else None
    server = VaultSocketServer(
        Service(session), socket_path=args.socket, runtime_dir=runtime_dir
    )
    try:
        server.start()
    except Exception as exc:  # noqa: BLE001 - report startup failures clearly
        LOG.error("could not start the socket server: %s", exc)
        session.close()
        return 1

    LOG.info(
        "daemon ready on %s (home=%s, locked=%s)", server.address, home, session.is_locked
    )
    if args.json_events:
        event = {
            "event": "ready",
            "socket": str(server.socket_path),
            "endpoint": server.endpoint.to_json(),
            "home": str(home),
            "locked": bool(session.is_locked),
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
        session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
