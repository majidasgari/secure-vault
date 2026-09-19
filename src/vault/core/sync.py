"""Two-way S3 folder sync with a cooperative write lock (docs/SYNC.md).

The design assumes the vault is **single-writer**: at most one client edits at a time.
A lock object (``.secure-vault.lock``) in the bucket records the current owner. On
unlock a client tries to acquire it; if another client holds it the session becomes
**read-only** (every write raises :class:`~vault.errors.SyncReadOnly`) until the user
presses *Take control*, which force-overrides the stale lock.

The sync itself is a three-way mirror over the whole vault home (``.vault-meta.json``,
``meta.sqlite``, ``secure.store`` and ``files/``). Derived caches are never synced: the
semantic vector DB and the embedding cache live outside the vault by design, and
``semantic*.db`` / ``*.db`` / runtime leftovers are excluded defensively.

The last-synced manifest is kept machine-local (``<user data dir>/sync/<vault>.json``)
so deletes can be told apart from new files on either side.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
from pathlib import Path
from typing import Any, Callable

from ..config import sync_client_id, user_data_dir
from ..errors import ProviderUnavailable, SyncError, SyncReadOnly
from ..util import atomic_write_bytes, now_ms
from .s3 import S3Client, S3Config, backend_kind

LOG = logging.getLogger(__name__)

LOCK_FILENAME = ".secure-vault.lock"
STATE_VERSION = 1
CHUNK = 1 << 20  # 1 MiB read chunks while hashing

ProgressCallback = Callable[[str, int, int], None]


def _default_progress(phase: str, done: int, total: int) -> None:
    """No-op progress sink."""


def _new_job() -> dict[str, Any]:
    """Return a fresh, idle sync-job state dict."""
    return {
        "running": False,
        "finished": False,
        "ok": None,
        "phase": "idle",
        "current": None,
        "upload": {"done": 0, "total": 0},
        "download": {"done": 0, "total": 0},
        "delete": {"done": 0, "total": 0},
        "started_at": None,
        "updated_at": None,
        "error": None,
        "result": None,
    }


def _is_excluded(relative: str) -> bool:
    """Return True for paths that must never be synced (derived/runtime files)."""
    name = relative.rsplit("/", 1)[-1]
    if name in (".DS_Store", LOCK_FILENAME):
        return True
    if name.endswith((".tmp", ".dec", "-wal", "-shm")):
        return True
    if name.endswith(".db"):
        return True
    if name.startswith("store."):
        return True
    parts = relative.split("/")
    if "semantic" in parts or "cache" in parts:
        return True
    return False


def _hash_file(path: Path) -> str:
    """Return the hex MD5 of a file (matches a single-PUT S3 ETag)."""
    import hashlib  # noqa: PLC0415

    digest = hashlib.md5()  # noqa: S324 - change detection, not security
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


class SyncManager:
    """Owns the S3 client, the lock state and the mirror engine for one session."""

    def __init__(self, session: Any, *, client: Any | None = None) -> None:
        """Bind the manager to ``session``; ``client`` overrides the boto3 client (tests)."""
        self.session = session
        self.client: Any | None = client
        self.config = S3Config()
        self.owned = False
        self.readonly = False
        #: The lock object currently in the bucket (owner, host, timestamps), if any.
        self.lock_info: dict[str, Any] | None = None
        self.last_error: str | None = None
        self.last_sync: dict[str, Any] | None = None
        self._sync_lock = threading.Lock()
        self._job_lock = threading.Lock()
        self._job: dict[str, Any] = _new_job()
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self.reload_config()

    # ------------------------------------------------------------------- config
    def reload_config(self) -> None:
        """Re-read the vault settings and the machine-local credentials."""
        try:
            self.config = S3Config.from_session(self.session)
        except Exception:  # noqa: BLE001 - a locked/absent vault has no settings
            self.config = S3Config()

    def set_client(self, client: Any | None) -> None:
        """Inject a replacement client (used by tests and the self-test)."""
        self.client = client

    def _s3(self) -> Any:
        """Return the S3 client, building the boto3 one on demand."""
        if self.client is None:
            self.client = S3Client(self.config)
        return self.client

    @property
    def available(self) -> bool:
        """True when an S3 client can be constructed (boto3 importable)."""
        if self.client is not None:
            return True
        return S3Client(self.config).available

    def lock_key(self) -> str:
        """Return the bucket key of the lock object."""
        return f"{self.config.normalized_prefix()}{LOCK_FILENAME}"

    def state_path(self) -> Path:
        """Return the machine-local last-synced manifest path."""
        vault_id = ""
        try:
            vault_id = str(self.session.meta.vault_id or "")
        except Exception:  # noqa: BLE001
            vault_id = ""
        return user_data_dir() / "sync" / f"{vault_id or 'vault'}.json"

    # --------------------------------------------------------------------- lock
    def _payload(self, owner: str) -> dict[str, Any]:
        """Build the JSON body written to the lock object."""
        try:
            vault_id = str(self.session.meta.vault_id or "")
        except Exception:  # noqa: BLE001
            vault_id = ""
        now = now_ms()
        return {
            "version": 1,
            "vault_id": vault_id,
            "owner": owner,
            "host": socket.gethostname(),
            "pid": os.getpid(),
            "acquired_at": now,
            "heartbeat_at": now,
        }

    @staticmethod
    def _parse_lock(raw: bytes | None) -> dict[str, Any] | None:
        """Decode a lock object, tolerating a corrupt/foreign one."""
        if not raw:
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def startup(self) -> dict[str, Any]:
        """Resolve the config and try to acquire the lock (called on unlock).

        A configured but unreachable bucket resolves to read-only, which is the safe
        default: refusing to write is always better than unlinking a peer's changes.
        """
        self.reload_config()
        if not self.config.configured:
            self.owned = False
            self.readonly = False
            self.lock_info = None
            return self.status()
        try:
            return self.acquire(force=False)
        except (ProviderUnavailable, SyncError) as exc:
            self.last_error = getattr(exc, "message", str(exc))
            self.owned = False
            self.readonly = True
            return self.status()

    def _adopt(self, info: dict[str, Any] | None) -> dict[str, Any]:
        """Set the in-memory ownership flags from a lock payload and return the status."""
        me = sync_client_id()
        self.lock_info = info
        if info and info.get("owner") == me:
            self.owned = True
            self.readonly = False
        else:
            self.owned = False
            self.readonly = True
        return self.status()

    def acquire(self, *, force: bool = False) -> dict[str, Any]:
        """Try to become the writer; ``force`` overrides another owner's lock."""
        self.reload_config()
        if not self.config.configured:
            self.owned = False
            self.readonly = False
            return self.status()
        client = self._s3()
        me = sync_client_id()
        key = self.lock_key()
        info = self._parse_lock(client.get(key))
        if info is not None and info.get("owner") == me and not force:
            info["heartbeat_at"] = now_ms()
            client.put(key, json.dumps(info).encode("utf-8"))
            self.last_error = None
            return self._adopt(info)
        if info is None:
            payload = self._payload(me)
            stored = True
            try:
                stored = client.put(
                    key, json.dumps(payload).encode("utf-8"), if_none_match=True
                )
            except SyncError:
                # ``IfNoneMatch`` unsupported by this backend: fall back to read-then-write.
                stored = False
            if not stored:
                info = self._parse_lock(client.get(key))
                if info is not None and info.get("owner") != me and not force:
                    self.last_error = None
                    return self._adopt(info)
                client.put(key, json.dumps(payload).encode("utf-8"))
            self.last_error = None
            return self._adopt(payload)
        if force:
            payload = self._payload(me)
            if info is not None:
                payload["forced_from"] = {
                    "owner": info.get("owner"),
                    "host": info.get("host"),
                    "acquired_at": info.get("acquired_at"),
                }
            client.put(key, json.dumps(payload).encode("utf-8"))
            self.last_error = None
            return self._adopt(payload)
        self.last_error = None
        return self._adopt(info)

    def release(self) -> dict[str, Any]:
        """Delete the lock object when this client owns it."""
        if not self.config.configured:
            self.owned = False
            self.readonly = False
            return self.status()
        if self.owned:
            try:
                self._s3().delete(self.lock_key())
            except (ProviderUnavailable, SyncError) as exc:
                self.last_error = getattr(exc, "message", str(exc))
            else:
                self.last_error = None
        self.owned = False
        self.readonly = True
        self.lock_info = None
        return self.status()

    def status(self) -> dict[str, Any]:
        """Return a JSON-ready snapshot of the sync state (never contains a secret)."""
        held_by: dict[str, Any] | None = None
        if self.lock_info and not self.owned:
            held_by = {
                "owner": self.lock_info.get("owner"),
                "host": self.lock_info.get("host"),
                "acquired_at": self.lock_info.get("acquired_at"),
                "heartbeat_at": self.lock_info.get("heartbeat_at"),
            }
        backend = getattr(self.client, "backend_name", None) if self.client is not None else None
        if backend is None and self.config.configured:
            backend = backend_kind()
        return {
            "configured": bool(self.config.configured),
            "enabled": bool(self.config.enabled),
            "available": self.available,
            "backend": backend,
            "bucket": self.config.bucket,
            "prefix": self.config.prefix,
            "endpoint": self.config.endpoint,
            "owned": bool(self.owned),
            "readonly": bool(self.readonly),
            "held_by": held_by,
            "last_error": self.last_error,
            "last_sync": self.last_sync,
            "state_path": str(self.state_path()),
            "syncing": self.syncing,
            "job": self.job(),
        }

    def is_write_allowed(self) -> bool:
        """True when a write may proceed (no sync, or this client owns the lock)."""
        if not self.config.configured:
            return True
        return bool(self.owned) and not self.readonly

    # -------------------------------------------------------------- progress job
    @property
    def syncing(self) -> bool:
        """True while a mirror job is running in the background."""
        with self._job_lock:
            return bool(self._job["running"])

    def job(self) -> dict[str, Any]:
        """Return a copy of the current sync-job state (safe to read from any thread)."""
        with self._job_lock:
            return json.loads(json.dumps(self._job))

    def _check_cancel(self) -> None:
        """Abort the mirror when :meth:`cancel` was called (lock/quit)."""
        if self._cancel.is_set():
            raise SyncError("sync_cancelled")

    def _update_job(self, **fields: Any) -> None:
        """Merge ``fields`` into the job state and stamp ``updated_at``."""
        with self._job_lock:
            for key, value in fields.items():
                if isinstance(value, dict) and isinstance(self._job.get(key), dict):
                    merged = dict(self._job[key])
                    merged.update(value)
                    self._job[key] = merged
                else:
                    self._job[key] = value
            self._job["updated_at"] = now_ms()

    # ------------------------------------------------------------ test / start
    def test_connection(self) -> dict[str, Any]:
        """Check that the bucket/credentials work; never raises, never blocks long."""
        self.reload_config()
        if not self.config.configured:
            return {"ok": False, "error": "not_configured", "configured": False}
        try:
            client = self._s3()
            entries = client.list(self.config.normalized_prefix())
        except Exception as exc:  # noqa: BLE001 - report, never raise
            return {
                "ok": False,
                "configured": True,
                "backend": backend_kind(),
                "error": getattr(exc, "message", str(exc)),
            }
        return {
            "ok": True,
            "configured": True,
            "backend": getattr(client, "backend_name", None) or backend_kind(),
            "bucket": self.config.bucket,
            "prefix": self.config.prefix,
            "objects": len(entries),
        }

    def start_sync(self) -> dict[str, Any]:
        """Start the mirror in a background thread and return immediately.

        The worker never holds the service lock, so status polls and reads stay
        responsive while it runs. Writes are refused (see
        :meth:`VaultSession._require_writable`) until the job finishes.

        Raises:
            SyncError: when sync is not configured.
            SyncReadOnly: when this client does not hold the write lock.
        """
        if not self.config.configured:
            raise SyncError("sync_not_configured")
        if not self.is_write_allowed():
            raise SyncReadOnly("sync_readonly", details={"held_by": self.lock_info})
        if self.syncing:
            return {"started": False, "job": self.job()}
        self._thread = threading.Thread(
            target=self._background_sync, name="vault-sync", daemon=True
        )
        self._thread.start()
        return {"started": True, "job": self.job()}

    def _background_sync(self) -> None:
        """Thread entry point: run :meth:`sync` and swallow (recorded) errors."""
        try:
            self.sync()
        except Exception:  # noqa: BLE001 - the job state carries the failure
            LOG.info("background sync failed", exc_info=True)

    def cancel(self) -> None:
        """Ask a running background sync to stop at the next step."""
        self._cancel.set()

    def wait(self, timeout: float = 3.0) -> bool:
        """Wait for the background thread to finish; return True when it has."""
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout=timeout)
        return not thread.is_alive()

    # -------------------------------------------------------------------- state
    def _read_state(self) -> dict[str, Any]:
        """Load the last-synced manifest, tolerating a missing/corrupt file."""
        path = self.state_path()
        if not path.exists():
            return {"version": STATE_VERSION, "files": {}}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"version": STATE_VERSION, "files": {}}
        if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
            return {"version": STATE_VERSION, "files": {}}
        return data

    def _write_state(self, files: dict[str, Any]) -> None:
        """Persist the new base manifest machine-locally."""
        payload = {
            "version": STATE_VERSION,
            "vault_id": str(getattr(self.session.meta, "vault_id", "") or ""),
            "files": files,
            "last_sync": now_ms(),
        }
        try:
            atomic_write_bytes(self.state_path(), json.dumps(payload).encode("utf-8"))
        except OSError:  # pragma: no cover - the mirror already succeeded
            LOG.warning("could not persist the sync manifest", exc_info=True)

    # ---------------------------------------------------------------- manifests
    def _local_manifest(self) -> dict[str, dict[str, Any]]:
        """Hash every syncable file under the vault home."""
        home = Path(self.session.home)
        manifest: dict[str, dict[str, Any]] = {}
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
            manifest[relative] = {
                "size": int(stat.st_size),
                "mtime": int(stat.st_mtime * 1000),
                "md5": _hash_file(path),
            }
        return manifest

    def _remote_manifest(self) -> dict[str, dict[str, Any]]:
        """List the bucket and key objects by their vault-relative path."""
        client = self._s3()
        prefix = self.config.normalized_prefix()
        manifest: dict[str, dict[str, Any]] = {}
        for item in client.list(prefix):
            key = str(item.get("key") or "")
            if not key.startswith(prefix):
                continue
            relative = key[len(prefix) :]
            if not relative or relative == LOCK_FILENAME or _is_excluded(relative):
                continue
            etag = item.get("etag")
            if etag and "-" in etag:
                etag = None
            manifest[relative] = {
                "size": int(item.get("size") or 0),
                "modified": int(item.get("modified") or 0),
                "etag": etag,
            }
        return manifest

    @staticmethod
    def _base_md5(entry: dict[str, Any] | None) -> str | None:
        """Return the base manifest's content hash for an entry."""
        return entry.get("md5") if entry else None

    def plan(
        self,
        local: dict[str, dict[str, Any]],
        remote: dict[str, dict[str, Any]],
        base: dict[str, dict[str, Any]],
    ) -> dict[str, list[str]]:
        """Compute the three-way mirror actions for the three manifests."""
        uploads: list[str] = []
        downloads: list[str] = []
        delete_remote: list[str] = []
        delete_local: list[str] = []
        conflicts: list[str] = []
        for relative in sorted(set(local) | set(remote) | set(base)):
            here = local.get(relative)
            there = remote.get(relative)
            was = base.get(relative)
            base_md5 = self._base_md5(was)
            if here is not None and there is not None:
                local_changed = was is None or here.get("md5") != base_md5
                remote_etag = there.get("etag")
                remote_changed = was is None or remote_etag is None or remote_etag != base_md5
                if not local_changed and not remote_changed:
                    continue
                if local_changed and not remote_changed:
                    uploads.append(relative)
                elif remote_changed and not local_changed:
                    downloads.append(relative)
                elif here.get("md5") == remote_etag:
                    continue
                else:
                    # Both sides changed while we hold the lock: the local writer wins.
                    uploads.append(relative)
                    conflicts.append(relative)
            elif here is not None and there is None:
                if was is None:
                    uploads.append(relative)
                elif here.get("md5") != base_md5:
                    uploads.append(relative)
                    conflicts.append(relative)
                else:
                    delete_local.append(relative)
            elif there is not None and here is None:
                if was is None:
                    downloads.append(relative)
                else:
                    remote_etag = there.get("etag")
                    if remote_etag is None or remote_etag != base_md5:
                        downloads.append(relative)
                        conflicts.append(relative)
                    else:
                        delete_remote.append(relative)
            # else: present only in base — deleted on both sides; it just leaves the base.
        return {
            "upload": uploads,
            "download": downloads,
            "delete_remote": delete_remote,
            "delete_local": delete_local,
            "conflict": conflicts,
        }

    # --------------------------------------------------------------------- sync
    def sync(self, progress: ProgressCallback | None = None) -> dict[str, Any]:
        """Mirror the vault folder to/from S3 and persist the new base manifest.

        Raises:
            SyncReadOnly: when this client does not hold the write lock.
            SyncError: for the first failing S3 operation.
        """
        report = _default_progress if progress is None else progress
        if not self.config.configured:
            raise SyncError("sync_not_configured")
        if not self.is_write_allowed():
            raise SyncReadOnly("sync_readonly", details={"held_by": self.lock_info})
        if not self._sync_lock.acquire(blocking=False):
            raise SyncError("sync_in_progress")
        self._cancel.clear()
        self._update_job(
            running=True,
            finished=False,
            ok=None,
            phase="scan",
            current=None,
            upload={"done": 0, "total": 0},
            download={"done": 0, "total": 0},
            delete={"done": 0, "total": 0},
            started_at=now_ms(),
            error=None,
            result=None,
        )
        self.session._syncing = True
        try:
            result = self._run_sync(report)
        except Exception as exc:  # noqa: BLE001 - record and re-raise
            self._update_job(
                running=False,
                finished=True,
                ok=False,
                phase="error",
                error=getattr(exc, "message", str(exc)),
            )
            raise
        finally:
            self.session._syncing = False
            self._sync_lock.release()
        self._update_job(
            running=False,
            finished=True,
            ok=True,
            phase="done",
            result=result,
        )
        return result

    def _run_sync(self, progress: ProgressCallback) -> dict[str, Any]:
        """Flush local state, plan and execute the mirror, then save the base."""
        session = self.session
        session._require_unlocked()
        # A write always calls ``session.flush()`` already; flushing again here would
        # re-encrypt ``secure.store`` with a fresh nonce and make every sync re-upload it.
        # Only the WAL is folded back so ``meta.sqlite`` is a self-contained file.
        if getattr(session, "_index", None) is not None:
            try:
                session.index.checkpoint()
            except Exception:  # noqa: BLE001
                LOG.warning("meta.sqlite checkpoint before sync failed", exc_info=True)

        home = Path(session.home)
        base = self._read_state().get("files", {})
        progress("scan", 0, 1)
        local = self._local_manifest()
        remote = self._remote_manifest()
        actions = self.plan(local, remote, base)
        progress("scan", 1, 1)

        uploaded = 0
        downloaded = 0
        deleted_remote = 0
        deleted_local = 0
        prefix = self.config.normalized_prefix()
        client = self._s3()

        total_upload = len(actions["upload"])
        total_download = len(actions["download"])
        total_delete = len(actions["delete_remote"]) + len(actions["delete_local"])
        self._update_job(
            phase="transfer",
            upload={"done": 0, "total": total_upload},
            download={"done": 0, "total": total_download},
            delete={"done": 0, "total": total_delete},
        )

        for index, relative in enumerate(actions["upload"], start=1):
            self._check_cancel()
            path = home / relative
            self._update_job(
                phase="upload", current=relative, upload={"done": index, "total": total_upload}
            )
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise SyncError(
                    "sync_read_failed", details={"path": relative, "reason": str(exc)}
                ) from exc
            client.put(f"{prefix}{relative}", data)
            uploaded += 1
            progress("upload", index, total_upload)

        for index, relative in enumerate(actions["download"], start=1):
            self._check_cancel()
            self._update_job(
                phase="download",
                current=relative,
                download={"done": index, "total": total_download},
            )
            data = client.get(f"{prefix}{relative}")
            if data is None:  # vanished between list and get: skip
                continue
            target = home / relative
            atomic_write_bytes(target, data)
            try:
                os.utime(target, (now_ms() / 1000.0, now_ms() / 1000.0))
            except OSError:  # pragma: no cover - mtime is informational
                pass
            downloaded += 1
            progress("download", index, total_download)

        for index, relative in enumerate(
            list(actions["delete_remote"]) + list(actions["delete_local"]), start=1
        ):
            self._check_cancel()
            self._update_job(
                phase="delete", current=relative, delete={"done": index, "total": total_delete}
            )
            if relative in actions["delete_remote"]:
                client.delete(f"{prefix}{relative}")
                deleted_remote += 1
            else:
                try:
                    (home / relative).unlink()
                    deleted_local += 1
                except OSError:  # pragma: no cover - already gone
                    pass

        current = self._local_manifest()
        self._write_state(current)
        self.last_error = None
        result = {
            "ok": True,
            "uploaded": uploaded,
            "downloaded": downloaded,
            "deleted_remote": deleted_remote,
            "deleted_local": deleted_local,
            "conflicts": actions["conflict"],
            "files": len(current),
            "at": now_ms(),
        }
        self.last_sync = result
        self.session._log(
            source="ui",
            tool="sync",
            outcome="allow",
            details=f"up={uploaded} down={downloaded}",
        )
        return result


__all__ = ["SyncManager", "LOCK_FILENAME", "STATE_VERSION"]
