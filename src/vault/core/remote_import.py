"""Import an existing vault from an S3 bucket (docs/SYNC.md §9).

The ordinary path to a synced vault is *create a vault, then sync*. That is fine for an
empty bucket and catastrophic for a bucket that already holds a vault: the two vaults have
different ``vault_id`` values and different KDF salts, so the brand-new vault's empty index
and fresh identity overwrite the good ones in the bucket. (``SyncManager._guard_identity``
now refuses exactly that.)

This module implements the correct path. It reads the vault that is **already** in the
bucket and adopts it:

* ``.vault-meta.json`` — the identity (vault id, KDF salt, password canary, settings),
* ``meta.sqlite`` — the plaintext index (names, paths, levels, tags, history),
* ``secure.store`` — the encrypted content store (folder notes, full-text index),
* ``files/**`` — the encrypted blobs the index references,

so the folder is then ready to unlock with the **original** master password. Nothing of the
local folder is deleted: an existing vault with a different identity is parked *next to* the
vault home (``<home>.replaced-<stamp>/``) and its ``files/`` blobs stay in place, which lets
the import reuse any blob the two vaults share.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..config import load_sync_config, save_sync_config, sync_client_id, user_data_dir
from ..errors import AlreadyExists, NotFound, SyncError, Unauthorized
from ..util import atomic_write_bytes, now_ms, wipe
from .crypto import KdfParams, check_canary, derive_master_key
from .s3 import S3Config
from .sync import (
    IDENTITY_FILENAME,
    INDEX_FILENAME,
    LOCK_FILENAME,
    METADATA_FILENAMES,
    STATE_VERSION,
    STORE_FILENAME,
    _hash_file,
    _is_excluded,
    identity_vault_id,
)

LOG = logging.getLogger(__name__)

BLOB_DIRNAME = "files"
"""Folder (inside the vault home) holding the encrypted blobs."""

SIDECAR_SUFFIXES = ("-wal", "-shm")
"""SQLite side files that are parked with their index when a vault is replaced."""

ProgressCallback = Callable[[str, int, int], None]
"""``(phase, done, total)`` sink, mirroring the sync engine's callback."""

CancelCallback = Callable[[], bool]
"""Returns True when the caller wants the import to stop."""


def _noop_progress(phase: str, done: int, total: int) -> None:
    """Discard progress updates."""


# --------------------------------------------------------------------------- results
@dataclass
class RemoteVaultInfo:
    """What the bucket advertises before anything is written to disk."""

    prefix: str = ""
    vault_id: str = ""
    created_at: int | None = None
    schema_version: int = 0
    kdf_algo: str = ""
    files: int = 0
    folders: int = 0
    versions: int = 0
    payload_bytes: int = 0
    referenced_blobs: int = 0
    blobs: int = 0
    blob_bytes: int = 0
    index_bytes: int = 0
    store_bytes: int = 0
    identity_bytes: int = 0
    settings: dict[str, Any] = field(default_factory=dict)
    settings_sync: dict[str, Any] = field(default_factory=dict)
    lock: dict[str, Any] | None = None

    @property
    def item_count(self) -> int:
        """Number of index rows (files + folders)."""
        return self.files + self.folders

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready summary (used by the CLI and the UI)."""
        return {
            "prefix": self.prefix,
            "vault_id": self.vault_id,
            "created_at": self.created_at,
            "schema_version": self.schema_version,
            "kdf_algo": self.kdf_algo,
            "files": self.files,
            "folders": self.folders,
            "versions": self.versions,
            "payload_bytes": self.payload_bytes,
            "referenced_blobs": self.referenced_blobs,
            "blobs": self.blobs,
            "blob_bytes": self.blob_bytes,
            "index_bytes": self.index_bytes,
            "store_bytes": self.store_bytes,
            "identity_bytes": self.identity_bytes,
            "settings": self.settings,
            "settings_sync": self.settings_sync,
            "lock": self.lock,
        }


@dataclass
class ImportReport:
    """Outcome of :func:`import_vault`.

    ``downloaded``/``reused``/``downloaded_bytes`` count the *content* files (blobs and any
    other file in the folder). The three metadata files are always fetched and installed,
    so their size is reported separately as ``metadata_bytes``.
    """

    ok: bool = False
    home: str = ""
    vault_id: str = ""
    files: int = 0
    folders: int = 0
    versions: int = 0
    payload_bytes: int = 0
    downloaded: int = 0
    reused: int = 0
    downloaded_bytes: int = 0
    metadata_bytes: int = 0
    seeded: int = 0
    replaced: bool = False
    parked_at: str = ""
    seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready report."""
        return {
            "ok": self.ok,
            "home": self.home,
            "vault_id": self.vault_id,
            "files": self.files,
            "folders": self.folders,
            "versions": self.versions,
            "payload_bytes": self.payload_bytes,
            "downloaded": self.downloaded,
            "reused": self.reused,
            "downloaded_bytes": self.downloaded_bytes,
            "metadata_bytes": self.metadata_bytes,
            "seeded": self.seeded,
            "replaced": self.replaced,
            "parked_at": self.parked_at,
            "seconds": round(self.seconds, 2),
        }


# --------------------------------------------------------------------------- identity
def parse_identity(data: bytes | None) -> dict[str, Any]:
    """Parse a ``.vault-meta.json`` payload.

    Raises:
        NotFound: when the object is missing or is not a JSON object.
    """
    if not data:
        raise NotFound("remote_vault_missing")
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise NotFound("remote_vault_missing", details={"reason": str(exc)}) from exc
    if not isinstance(parsed, dict):
        raise NotFound("remote_vault_missing")
    return parsed


def remote_vault_id(client: Any, config: S3Config) -> str:
    """Return the ``vault_id`` stored in the bucket, or ``""`` when there is none."""
    try:
        data = client.get(f"{config.normalized_prefix()}{IDENTITY_FILENAME}")
    except Exception:  # noqa: BLE001 - an unreachable bucket must not raise here
        LOG.warning("could not read the remote vault identity", exc_info=True)
        return ""
    return identity_vault_id(data)


def kdf_params_of(identity: dict[str, Any]) -> KdfParams:
    """Return the :class:`KdfParams` described by an identity mapping."""
    kdf = identity.get("kdf")
    if not isinstance(kdf, dict):
        raise NotFound("remote_vault_missing", details={"reason": "kdf_missing"})
    try:
        return KdfParams(
            algo=str(kdf.get("algo") or "argon2id"),
            salt=base64.b64decode(str(kdf.get("salt_b64") or "")),
            time_cost=int(kdf.get("time_cost") or 0),
            memory_kib=int(kdf.get("memory_kib") or 0),
            parallelism=int(kdf.get("parallelism") or 0),
            iterations=int(kdf.get("iterations") or 0),
        )
    except (ValueError, TypeError) as exc:
        raise NotFound("remote_vault_missing", details={"reason": "kdf_invalid"}) from exc


def verify_remote_password(identity: dict[str, Any], password: str) -> bool:
    """Return True when ``password`` reproduces the identity's canary."""
    try:
        canary = base64.b64decode(str(identity.get("canary_b64") or ""))
    except (ValueError, TypeError):
        return False
    if not canary:
        return False
    master_key = derive_master_key(password, kdf_params_of(identity))
    try:
        return check_canary(master_key, canary)
    finally:
        wipe(master_key)


# --------------------------------------------------------------------------- probing
def _listing(client: Any, config: S3Config) -> dict[str, dict[str, Any]]:
    """Return ``{vault-relative path: {size, etag}}`` for the bucket prefix."""
    prefix = config.normalized_prefix()
    listing: dict[str, dict[str, Any]] = {}
    for item in client.list(prefix):
        key = str(item.get("key") or "")
        if not key.startswith(prefix):
            continue
        relative = key[len(prefix) :]
        if not relative or relative == LOCK_FILENAME or _is_excluded(relative):
            continue
        listing[relative] = {
            "size": int(item.get("size") or 0),
            "etag": item.get("etag"),
        }
    return listing


def _read_index(index_bytes: bytes) -> tuple[int, int, int, int, set[str]]:
    """Return ``(files, folders, versions, payload_bytes, referenced_blob_ids)``."""
    handle, name = tempfile.mkstemp(suffix=".sqlite", prefix="sv-import-")
    os.close(handle)
    path = Path(name)
    try:
        path.write_bytes(index_bytes)
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            files = int(connection.execute("SELECT COUNT(*) FROM files WHERE is_dir=0").fetchone()[0])
            folders = int(connection.execute("SELECT COUNT(*) FROM files WHERE is_dir=1").fetchone()[0])
            versions = int(connection.execute("SELECT COUNT(*) FROM file_versions").fetchone()[0])
            payload = int(
                connection.execute(
                    "SELECT COALESCE(SUM(size), 0) FROM files WHERE is_dir=0"
                ).fetchone()[0]
            )
            referenced = {
                str(row[0])
                for row in connection.execute(
                    "SELECT blob_id FROM files WHERE blob_id IS NOT NULL AND blob_id <> ''"
                )
            }
            referenced |= {
                str(row[0])
                for row in connection.execute(
                    "SELECT blob_id FROM file_versions WHERE blob_id IS NOT NULL AND blob_id <> ''"
                )
            }
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise SyncError("remote_index_unreadable", details={"reason": str(exc)}) from exc
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover - best effort cleanup
            pass
    return files, folders, versions, payload, referenced


def probe_remote(
    client: Any,
    config: S3Config,
    *,
    with_index: bool = True,
) -> tuple[RemoteVaultInfo, dict[str, Any]]:
    """Describe the vault stored under the bucket prefix.

    Args:
        client: an S3 client (or a test double) with ``get``/``list``.
        config: bucket coordinates and credentials.
        with_index: also download ``meta.sqlite`` to count its rows (a few MB).

    Returns:
        The summary and the parsed identity mapping.

    Raises:
        SyncError: when the bucket is unconfigured or has no vault at all.
        NotFound: when the prefix holds no vault identity.
    """
    if not config.configured:
        raise SyncError("sync_not_configured")
    prefix = config.normalized_prefix()
    listing = _listing(client, config)
    if not listing:
        raise NotFound("remote_bucket_empty", details={"prefix": prefix})

    identity_bytes = client.get(f"{prefix}{IDENTITY_FILENAME}")
    identity = parse_identity(identity_bytes)

    info = RemoteVaultInfo(
        prefix=prefix,
        vault_id=str(identity.get("vault_id") or ""),
        created_at=identity.get("created_at") if isinstance(identity.get("created_at"), int) else None,
        schema_version=int(identity.get("schema_version") or 0),
        kdf_algo=str((identity.get("kdf") or {}).get("algo") or ""),
        identity_bytes=len(identity_bytes or b""),
        settings=identity.get("settings") if isinstance(identity.get("settings"), dict) else {},
    )
    settings_sync = info.settings.get("sync")
    info.settings_sync = settings_sync if isinstance(settings_sync, dict) else {}

    index_entry = listing.get(INDEX_FILENAME)
    info.index_bytes = int(index_entry["size"]) if index_entry else 0
    store_entry = listing.get(STORE_FILENAME)
    info.store_bytes = int(store_entry["size"]) if store_entry else 0

    blobs = [
        (relative, int(entry["size"]))
        for relative, entry in listing.items()
        if relative.startswith(f"{BLOB_DIRNAME}/") and relative.endswith(".enc")
    ]
    info.blobs = len(blobs)
    info.blob_bytes = sum(size for _, size in blobs)

    if with_index and index_entry:
        index_bytes = client.get(f"{prefix}{INDEX_FILENAME}")
        if index_bytes is not None:
            info.files, info.folders, info.versions, info.payload_bytes, referenced = _read_index(
                index_bytes
            )
            info.referenced_blobs = len(referenced)

    lock_bytes = client.get(f"{prefix}{LOCK_FILENAME}")
    if lock_bytes:
        try:
            parsed_lock = json.loads(lock_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            parsed_lock = None
        if isinstance(parsed_lock, dict):
            info.lock = parsed_lock
    return info, identity


# --------------------------------------------------------------------------- local state
def _local_vault_id(home: Path) -> str:
    """Return the ``vault_id`` already present in ``home`` (``""`` when none)."""
    path = home / IDENTITY_FILENAME
    if not path.is_file():
        return ""
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    return str(parsed.get("vault_id") or "")


def _park_existing(home: Path) -> Path:
    """Copy the current vault's metadata files next to ``home`` and remove the originals.

    ``files/`` is deliberately left in place: blobs are content-addressed, so the import
    reuses every blob the two vaults share instead of downloading them again.

    The copy happens before the original is removed, so the parked folder is always a
    complete record of the vault being replaced even if the second step fails.

    Raises:
        SyncError: ``vault_in_use`` when a file cannot be copied or removed because another
            process still has it open (Windows refuses both while a handle is held).
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = home.with_name(f"{home.name}.replaced-{stamp}")
    suffix = 1
    while target.exists():
        suffix += 1
        target = home.with_name(f"{home.name}.replaced-{stamp}-{suffix}")
    target.mkdir(parents=True, exist_ok=True)
    for name in (*METADATA_FILENAMES, *(f"{INDEX_FILENAME}{s}" for s in SIDECAR_SUFFIXES)):
        source = home / name
        if not source.exists():
            continue
        try:
            shutil.copy2(source, target / name)
            source.unlink()
        except OSError as exc:
            raise SyncError(
                "vault_in_use",
                details={"path": str(source), "reason": str(exc)},
            ) from exc
    note = target / "README.txt"
    note.write_text(
        "These files belong to the vault that used to live in the folder next to this one.\n"
        "They were parked (not deleted) when a vault was imported from S3.\n"
        "The old 'files/' blobs stay in place; unreferenced ones can be pruned with\n"
        "VaultSession.fs.gc_orphans() once the imported vault is unlocked.\n",
        encoding="utf-8",
    )
    return target


def _present_blobs(home: Path) -> set[str]:
    """Return the blob ids already stored under ``<home>/files/<xx>/``."""
    root = home / BLOB_DIRNAME
    if not root.is_dir():
        return set()
    return {path.stem for path in root.glob("*/*.enc")}


def _seed_sync_state(home: Path, vault_id: str) -> int:
    """Persist the imported folder as the last-synced manifest for ``vault_id``.

    The folder and the bucket are identical right after an import, so recording the base
    manifest upfront means the first sync transfers only what really changed (and never
    re-uploads the blobs).
    """
    files: dict[str, dict[str, Any]] = {}
    for path in home.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(home).as_posix()
        if _is_excluded(relative):
            continue
        try:
            stat = path.stat()
        except OSError:  # pragma: no cover - file vanished mid-walk
            continue
        files[relative] = {
            "size": int(stat.st_size),
            "mtime": int(stat.st_mtime * 1000),
            "md5": _hash_file(path),
        }
    payload = {
        "version": STATE_VERSION,
        "vault_id": vault_id,
        "files": files,
        "last_sync": now_ms(),
    }
    destination = user_data_dir() / "sync" / f"{vault_id or 'vault'}.json"
    try:
        atomic_write_bytes(destination, json.dumps(payload).encode("utf-8"))
    except OSError:  # pragma: no cover - the import itself already succeeded
        LOG.warning("could not seed the sync manifest after import", exc_info=True)
    return len(files)


def persist_sync_credentials(config: S3Config) -> Path:
    """Store the credentials used for an import machine-locally (``s3.json``, mode 0600).

    Keeps the existing ``client_id`` so the device keeps its identity in the bucket lock.
    """
    data = load_sync_config()
    data["access_key"] = config.access_key
    data["secret_key"] = config.secret_key
    save_sync_config(data)
    sync_client_id()
    from ..config import sync_config_path  # noqa: PLC0415 - avoid a wider import block

    return sync_config_path()


# --------------------------------------------------------------------------- import
def _write_atomic(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically (``<name>.tmp`` + ``os.replace``)."""
    atomic_write_bytes(path, data)


def import_vault(
    client: Any,
    config: S3Config,
    home: Path | str,
    *,
    password: str | None = None,
    progress: ProgressCallback | None = None,
    cancel: CancelCallback | None = None,
    replace: bool = False,
) -> ImportReport:
    """Adopt the vault stored in the bucket into ``home``.

    Args:
        client: S3 client (or test double) with ``get``/``list``.
        config: bucket coordinates and credentials.
        home: the vault folder to create/populate.
        password: when given, it is verified against the *remote* canary before anything is
            written, so a wrong password fails immediately instead of after the download.
        progress: ``(phase, done, total)`` callback for the UI.
        cancel: returns True to stop the import (already-downloaded files are kept).
        replace: allow replacing a vault with a *different* ``vault_id``; the existing
            metadata files are parked next to the folder first.

    Returns:
        An :class:`ImportReport` describing what was transferred.

    Raises:
        SyncError: unconfigured bucket, unreadable remote index, or missing blobs.
        NotFound: the bucket/prefix holds no vault.
        Unauthorized: ``password`` does not match the remote identity.
        AlreadyExists: ``home`` holds a different vault and ``replace`` is False.
    """
    sink: ProgressCallback = progress or _noop_progress
    should_cancel = cancel or (lambda: False)
    started = time.monotonic()
    home = Path(home)
    prefix = config.normalized_prefix()

    sink("probe", 0, 1)
    _info, identity = probe_remote(client, config, with_index=True)
    remote_id = str(identity.get("vault_id") or "")
    sink("probe", 1, 1)

    if password is not None and not verify_remote_password(identity, password):
        raise Unauthorized("bad_password", details={"reason": "remote_canary_mismatch"})

    local_id = _local_vault_id(home)
    parked = ""
    replaced = False
    if local_id and local_id != remote_id:
        if not replace:
            raise AlreadyExists(
                "vault_exists",
                details={"home": str(home), "vault_id": local_id, "remote_vault_id": remote_id},
            )
        parked = str(_park_existing(home))
        replaced = True

    home.mkdir(parents=True, exist_ok=True)
    listing = _listing(client, config)

    payload = [
        relative for relative in sorted(listing) if relative not in METADATA_FILENAMES
    ]
    total = len(payload)
    downloaded = 0
    reused = 0
    downloaded_bytes = 0
    for position, relative in enumerate(payload, start=1):
        if should_cancel():
            raise SyncError("import_cancelled", details={"path": relative})
        sink("files", position, total)
        target = home / relative
        expected = int(listing[relative]["size"])
        try:
            if target.is_file() and target.stat().st_size == expected:
                reused += 1
                continue
        except OSError:  # pragma: no cover - fall through to the download
            pass
        data = client.get(f"{prefix}{relative}")
        if data is None:  # vanished between list and get
            continue
        if len(data) != expected:
            raise SyncError(
                "import_truncated",
                details={"path": relative, "expected": expected, "got": len(data)},
            )
        _write_atomic(target, data)
        downloaded += 1
        downloaded_bytes += len(data)

    if should_cancel():
        raise SyncError("import_cancelled")

    sink("index", 0, 1)
    index_bytes = client.get(f"{prefix}{INDEX_FILENAME}")
    if index_bytes is None:
        raise SyncError("remote_index_missing", details={"prefix": prefix})
    files, folders, versions, payload_bytes, referenced = _read_index(index_bytes)
    sink("index", 1, 1)

    present = _present_blobs(home)
    missing = sorted(referenced - present)
    if missing:
        raise SyncError(
            "import_incomplete",
            details={"missing": len(missing), "sample": missing[:3], "prefix": prefix},
        )

    store_bytes = client.get(f"{prefix}{STORE_FILENAME}")
    if store_bytes is None:
        raise SyncError("remote_store_missing", details={"prefix": prefix})

    sink("install", 0, 1)
    # The identity is written last: until it exists the folder is not a vault, so an
    # interrupted import can never be mistaken for a usable (or lockable) one.
    identity_bytes = json.dumps(identity, ensure_ascii=False, indent=2).encode("utf-8")
    _write_atomic(home / INDEX_FILENAME, index_bytes)
    _write_atomic(home / STORE_FILENAME, store_bytes)
    _write_atomic(home / IDENTITY_FILENAME, identity_bytes)
    sink("install", 1, 1)

    seeded = _seed_sync_state(home, remote_id)
    sink("done", 1, 1)
    return ImportReport(
        ok=True,
        home=str(home),
        vault_id=remote_id,
        files=files,
        folders=folders,
        versions=versions,
        payload_bytes=payload_bytes,
        downloaded=downloaded,
        reused=reused,
        downloaded_bytes=downloaded_bytes,
        metadata_bytes=len(index_bytes) + len(store_bytes) + len(identity_bytes),
        seeded=seeded,
        replaced=replaced,
        parked_at=parked,
        seconds=time.monotonic() - started,
    )


__all__ = [
    "BLOB_DIRNAME",
    "ImportReport",
    "RemoteVaultInfo",
    "import_vault",
    "kdf_params_of",
    "parse_identity",
    "persist_sync_credentials",
    "probe_remote",
    "remote_vault_id",
    "verify_remote_password",
]
