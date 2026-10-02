"""``secure-vault-import`` — restore a vault from S3 without the desktop app.

The GUI offers the same thing on its unlock screen (``بازیابی از S3``); this entry point
exists for headless machines and for the recovery case where the app cannot be started: a
fresh machine (or an empty folder) plus bucket coordinates is all it needs.

Examples::

    # restore into D:\\Vault from ArvanCloud, verifying the master password first
    secure-vault-import --home D:\\Vault --bucket majid-secure-vault --prefix sync \\
        --endpoint https://s3.ir-thr-at1.arvanstorage.ir --region ir-thr-at1

    # look at the bucket without writing anything
    secure-vault-import --home D:\\Vault --bucket ... --check

Credentials come from the machine-local ``s3.json`` unless ``--access-key``/``--secret-key``
are given, and the password is read from the terminal (or ``--password-env``) so it never
has to appear in the shell history.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from .config import DEFAULT_VAULT_HOME, load_sync_config
from .core import remote_import
from .core.s3 import S3Client, S3Config
from .errors import VaultError


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        prog="secure-vault-import",
        description="Restore a Secure Vault that is already stored in an S3 bucket.",
    )
    parser.add_argument("--home", default=str(DEFAULT_VAULT_HOME), help="vault folder")
    parser.add_argument("--bucket", required=True, help="bucket name")
    parser.add_argument("--prefix", default="", help="folder inside the bucket")
    parser.add_argument("--endpoint", default="", help="S3 endpoint URL (non-AWS providers)")
    parser.add_argument("--region", default="", help="region")
    parser.add_argument("--access-key", default="", help="access key (default: saved credentials)")
    parser.add_argument("--secret-key", default="", help="secret key (default: saved credentials)")
    parser.add_argument(
        "--password-env",
        default="SECURE_VAULT_PASSWORD",
        help="environment variable holding the master password (default: ask on the terminal)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="only describe the vault in the bucket (writes nothing)",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="park a different vault already in the folder instead of refusing",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser.parse_args(argv)


def _config(args: argparse.Namespace) -> S3Config:
    """Build the S3 config from the arguments and the saved credentials."""
    saved = load_sync_config()
    return S3Config(
        enabled=True,
        bucket=args.bucket.strip(),
        prefix=args.prefix.strip(),
        endpoint=args.endpoint.strip(),
        region=args.region.strip(),
        access_key=(args.access_key or str(saved.get("access_key") or "")).strip(),
        secret_key=(args.secret_key or str(saved.get("secret_key") or "")).strip(),
    )


def _password(args: argparse.Namespace) -> str | None:
    """Return the master password to verify (from the environment or the terminal)."""
    from_env = os.environ.get(args.password_env or "")
    if from_env:
        return from_env
    if not sys.stdin or not sys.stdin.isatty():
        return None
    typed = getpass.getpass("master password of the vault in the bucket (empty to skip): ")
    return typed or None


def _describe(info: remote_import.RemoteVaultInfo) -> str:
    """Render the probe result for a human."""
    lines = [
        f"prefix            : {info.prefix}",
        f"vault id          : {info.vault_id}",
        f"files             : {info.files}",
        f"folders           : {info.folders}",
        f"versions          : {info.versions}",
        f"indexed content   : {info.payload_bytes / 1024 / 1024:.1f} MB",
        f"index / store     : {info.index_bytes / 1024:.0f} KB / {info.store_bytes / 1024 / 1024:.1f} MB",
        f"blobs in bucket   : {info.blobs} ({info.blob_bytes / 1024 / 1024:.1f} MB)",
        f"referenced blobs  : {info.referenced_blobs}",
    ]
    if info.lock:
        lines.append(f"write lock held by: {info.lock.get('host') or info.lock.get('owner')}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Run the restore and return the process exit code."""
    args = _parse_args(argv)
    config = _config(args)
    if not config.configured:
        print(
            "error: the bucket and both keys are required "
            "(pass --access-key/--secret-key or save them in the app first)",
            file=sys.stderr,
        )
        return 2

    client = S3Client(config)
    home = Path(args.home)

    def progress(phase: str, done: int, total: int) -> None:
        """Print a one-line progress indicator."""
        if args.json:
            return
        if phase == "files" and total:
            print(f"\r  fetching {done}/{total}", end="", flush=True)
        elif phase == "index":
            print("\r  reading the index…", end="", flush=True)
        elif phase == "store":
            print("\r  fetching the encrypted store…", end="", flush=True)
        elif phase == "install":
            print("\r  installing…", end="", flush=True)

    try:
        info, _identity = remote_import.probe_remote(client, config)
        if args.check:
            if args.json:
                print(json.dumps(info.to_dict(), ensure_ascii=False, indent=2))
            else:
                print(_describe(info))
            return 0

        password = _password(args)
        print(f"restoring {info.vault_id or '?'} into {home}")
        report = remote_import.import_vault(
            client, config, home, password=password, progress=progress, replace=args.replace
        )
        print("\r" + " " * 40, end="\r")
        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(
                f"restored {report.files} files + {report.folders} folders "
                f"({report.payload_bytes / 1024 / 1024:.1f} MB) into {report.home}"
            )
            print(
                f"  fetched {report.downloaded} file(s) "
                f"({report.downloaded_bytes / 1024 / 1024:.1f} MB), "
                f"reused {report.reused}, metadata {report.metadata_bytes / 1024 / 1024:.1f} MB"
            )
            if report.replaced:
                print(f"  previous vault parked at {report.parked_at}")
            if not password:
                print("  unlock it with the vault's ORIGINAL master password")
        remote_import.persist_sync_credentials(config)
        return 0
    except VaultError as exc:
        reason = str(getattr(exc, "message", "") or exc)
        if args.json:
            print(json.dumps({"ok": False, "reason": reason, "details": exc.details}, indent=2))
        else:
            print(f"\rerror: {reason}", file=sys.stderr)
            for key, value in (exc.details or {}).items():
                print(f"  {key}: {value}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
