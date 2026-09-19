"""The :class:`VaultSession` façade — the single entry point to a vault (SPEC/01 §12).

Owns the metadata, index, blob store, encrypted content store, master key and lock state.
Every content operation is gated by :class:`~vault.core.security.Policy` using the
role-derived source (``ui`` in-process, ``mcp`` over the socket) and refusals are logged
before raising.
"""

from __future__ import annotations

import difflib
import logging
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

from ..config import DEFAULT_AUTO_LOCK_SECONDS, DEFAULT_PLAIN_THRESHOLD
from ..errors import (
    AlreadyExists,
    BadRequest,
    DowngradeForbidden,
    NotFound,
    PermissionDenied,
    SyncError,
    SyncReadOnly,
    Unauthorized,
    VaultError,
    VaultLocked,
)
from ..util import is_within, normalize_vault_path, now_ms, sha256_hex, wipe
from . import search as search_mod
from . import semantics
from . import retention
from .crypto import derive_master_key
from .index import Index
from .meta import META_FILENAME, VaultMeta
from .security import (
    LEVELS,
    SOURCE_MCP,
    SOURCE_UI,
    Policy,
    rank,
)
from .semantic_queue import SemanticIndexQueue
from .semantic_store import SemanticStore
from .store import SecureStore
from .vaultfs import VaultFS

SecretRequestCallback = Callable[[dict[str, Any]], Any]
ActivityCallback = Callable[[dict[str, Any]], Any]

LOG = logging.getLogger(__name__)


class VaultSession:
    """Owns the vault state: meta, index, vaultfs, secure store, master key, lock state."""

    def __init__(
        self,
        home: Path,
        *,
        runtime_dir: Path | None = None,
        plain_threshold: int | None = None,
    ) -> None:
        """Bind a session to ``home`` (nothing is created until :meth:`create`)."""
        from ..config import runtime_dir as _default_runtime

        self._home = Path(home)
        self._runtime = Path(runtime_dir) if runtime_dir is not None else _default_runtime()
        self._plain_threshold_override = plain_threshold
        self._meta: VaultMeta | None = None
        self._index: Index | None = None
        self._fs: VaultFS | None = None
        self._store: SecureStore | None = None
        #: The separate, rebuildable ``semantic.db`` vector index (opened lazily).
        self._semantic_store: SemanticStore | None = None
        #: Serialises semantic-index runs (manual rebuild vs the auto-index worker).
        self._semantic_lock = threading.RLock()
        self._semantic_queue: SemanticIndexQueue | None = None
        self._master_key: bytearray | None = None
        self._last_activity = now_ms()
        #: Provider injected explicitly (tests, self-test); wins over settings.
        self._semantic_provider: semantics.EmbeddingProvider | None = None
        #: Provider built lazily from the vault settings and cached until refreshed.
        self._semantic_auto_provider: semantics.EmbeddingProvider | None = None
        self._semantic_resolved = False
        self._pending: dict[str, dict[str, Any]] = {}
        #: S3 sync manager (lock + mirror); created on unlock and when S3 is configured.
        self._sync_manager: Any | None = None
        #: Optional injected S3 client (tests/self-test); wins over boto3.
        self._sync_client: Any | None = None
        #: True while a background S3 mirror is running (writes are refused meanwhile).
        self._syncing = False
        self.on_secret_request: SecretRequestCallback | None = None
        # SPEC/09 §7: metadata-only activity feed hook (never carries content).
        self.on_activity: ActivityCallback | None = None
        self._activity_source: str | None = None

    # ------------------------------------------------------------------ lifecycle
    @staticmethod
    def is_initialised(home: Path) -> bool:
        """Return True when ``home`` contains a vault metadata file."""
        return (Path(home) / META_FILENAME).exists()

    @staticmethod
    def create(
        home: Path,
        password: str,
        *,
        settings: dict[str, Any] | None = None,
    ) -> "VaultSession":
        """Create a new vault and return an unlocked session for it."""
        home = Path(home)
        if (home / META_FILENAME).exists():
            raise AlreadyExists("vault_exists", details={"home": str(home)})
        home.mkdir(parents=True, exist_ok=True)
        meta = VaultMeta.create(home / META_FILENAME, password)
        if settings:
            VaultSession._merge_settings(meta.settings, settings)
            meta.save()
        session = VaultSession(home)
        session._meta = meta
        session._index = Index(home / "meta.sqlite")
        master_key = derive_master_key(password, meta.kdf_params())
        bootstrap = SecureStore.create_new(home, master_key)
        bootstrap.close()
        session._master_key = master_key
        session._fs = VaultFS(
            home, session._index, master_key, plain_threshold=session._plain_threshold
        )
        session._store = SecureStore.open(home, master_key, session._runtime)
        session.touch()
        session._init_sync()
        return session

    @staticmethod
    def _merge_settings(base: dict[str, Any], override: dict[str, Any]) -> None:
        """Recursively merge ``override`` into ``base`` in place."""
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                VaultSession._merge_settings(base[key], value)
            else:
                base[key] = value

    def unlock(self, password: str) -> None:
        """Unlock the vault with ``password``.

        Raises:
            Unauthorized: when the password is wrong (``bad_password``).
        """
        meta = self._require_meta()
        if not meta.verify_password(password):
            raise Unauthorized("bad_password")
        if not self.is_locked:
            return
        if self._index is None:
            self._index = Index(self._home / "meta.sqlite")
        master_key = derive_master_key(password, meta.kdf_params())
        self._master_key = master_key
        self._fs = VaultFS(
            self._home,
            self._index,
            master_key,
            plain_threshold=self._plain_threshold,
        )
        self._store = SecureStore.open(self._home, master_key, self._runtime)
        self._prune_access_log()
        self.touch()
        self._init_sync()

    def reindex_search(
        self, progress: Callable[[str, int, int], None] | None = None
    ) -> dict[str, int]:
        """Rebuild the full-text index from the stored bodies (owner housekeeping).

        The index is derived data: dropping and rebuilding it never touches file content, and it
        is the only way to reclaim the millions of base64 tokens a previous version stored for
        inline images (measured: a 253 MB store for 48 MB of notes).
        """
        self._require_unlocked()
        self._require_writable("reindex_search")
        idx = self._require_index()
        assert self._store is not None
        previous = getattr(self, "_suppress_log", False)
        self._suppress_log = True          # bulk housekeeping must not flood the audit log
        try:
            dropped = self._store.reset_index()
            files = [row for row in idx.walk("/") if not int(row["is_dir"])]
            indexed = 0
            for position, row in enumerate(files, start=1):
                if str(row.get("sensitivity") or "normal") == "normal":
                    try:
                        data = self.read_file(str(row["logical_path"]), source=SOURCE_UI)
                    except VaultError:
                        data = b""
                    if data:
                        self._index_file_text(
                            int(row["id"]), data.decode("utf-8", errors="ignore")
                        )
                        indexed += 1
                if progress is not None and (position % 25 == 0 or position == len(files)):
                    progress("reindex", position, len(files))
            self._store.vacuum()
            self._store.flush()
        finally:
            self._suppress_log = previous
        return {"dropped": dropped, "indexed": indexed, "files": len(files)}

    def index_semantics(
        self,
        *,
        force: bool = False,
        progress: Callable[[int, int], None] | None = None,
        prefix: str | None = None,
        paths: set[str] | None = None,
        refresh: bool = True,
        allow_reset: bool = False,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Rebuild the semantic (embedding) index for every ``normal`` text file.

        The provider is (re)resolved from the current settings first, so a newly enabled
        backend takes effect without restarting. ``progress(done, total)`` is called once
        per file from whatever thread the caller is on. ``prefix``/``paths`` limit the
        rebuild; ``refresh=False`` keeps the loaded model for a per-write re-embed.

        A ``(model, dim, chunking)`` mismatch is only wiped when ``allow_reset`` is set
        (an explicit user rebuild); otherwise the run is refused and the live index kept.
        """
        with self._semantic_lock:
            if refresh:
                self.refresh_semantic_provider()
            return semantics.index_all(
                self,
                force=force,
                progress=progress,
                prefix=prefix,
                paths=paths,
                allow_reset=allow_reset,
                reason=reason,
            )

    def _auto_index_semantics(self, logical: str) -> None:
        """Queue a written path for background re-embedding (never inline).

        Best effort: if the semantic index has not been opened this session there is no
        loaded model to reuse and the file is picked up by the next explicit index.
        """
        if self._semantic_store is None:
            return
        try:
            if not (self._require_meta().settings.get("semantic") or {}).get("enabled"):
                return
        except VaultError:
            return
        if self.semantic_provider is None:
            return
        if self._semantic_queue is None:
            self._semantic_queue = SemanticIndexQueue(self._index_semantic_batch)
        self._semantic_queue.enqueue(logical)

    def _index_semantic_batch(self, paths: set[str]) -> None:
        """Background worker: re-embed a coalesced batch without wiping the index."""
        self.index_semantics(
            force=True,
            paths=set(paths),
            refresh=False,
            allow_reset=False,
            reason="auto_index",
        )

    def _prune_access_log(self) -> None:
        """Keep the audit log bounded (newest rows win; failures never block unlocking).

        Retention lives in :mod:`vault.core.retention` so the data layer
        (:mod:`vault.core.index`) stays free of any DELETE on the log.
        """
        if self._index is None:
            return
        try:
            retention.prune_access_log(self._index)
        except Exception:  # noqa: BLE001 - housekeeping must never block the user
            return

    def lock(self) -> None:
        """Flush, wipe the master key and close the store and index."""
        manager = self._sync_manager
        if manager is not None and manager.syncing:
            # Stop a background mirror before the store/index close under it.
            try:
                manager.cancel()
                manager.wait(timeout=3.0)
            except Exception:  # noqa: BLE001 - locking must never block on sync
                pass
        if manager is not None and manager.owned:
            # Auto-release the S3 write lock so another machine can take over cleanly.
            try:
                manager.release()
            except Exception:  # noqa: BLE001 - a failed release must not block locking
                pass
        queue, self._semantic_queue = self._semantic_queue, None
        if queue is not None:
            queue.stop()
        if self._index is not None:
            self._prune_access_log()
        if self._semantic_store is not None:
            self._semantic_store.close()
            self._semantic_store = None
        if self._store is not None:
            self._store.close()
            self._store = None
        if self._index is not None:
            self._index.close()
            self._index = None
        if self._master_key is not None:
            wipe(self._master_key)
            self._master_key = None
        if self._fs is not None:
            self._fs.master_key = None
            self._fs = None

    def close(self) -> None:
        """Lock and release all held files."""
        self.lock()
        self._meta = None

    @property
    def is_locked(self) -> bool:
        """True when no master key/store is loaded."""
        return self._master_key is None or self._store is None

    @property
    def home(self) -> Path:
        """The vault home directory."""
        return self._home

    def flush(self) -> None:
        """Re-encrypt the content store and the semantic index if they are open."""
        if self._store is not None:
            self._store.flush()
        if self._semantic_store is not None:
            self._semantic_store.flush()

    def touch(self, *, source: str = SOURCE_UI) -> None:
        """Record UI activity for the auto-lock clock (MCP activity does not count)."""
        if source == SOURCE_UI:
            self._last_activity = now_ms()

    def auto_lock_due(self) -> bool:
        """Return True when the UI idle time exceeds ``auto_lock_seconds``."""
        if self.is_locked:
            return False
        seconds = int(self._require_meta().settings.get("auto_lock_seconds", 0) or 0)
        if seconds <= 0:
            return False
        return (now_ms() - self._last_activity) > seconds * 1000

    # -------------------------------------------------------------------- internal
    def _plain_threshold(self) -> int:
        """Resolve the effective plain-storage threshold."""
        if self._plain_threshold_override is not None:
            return int(self._plain_threshold_override)
        try:
            return int(
                self._require_meta().settings.get(
                    "plain_threshold_bytes", DEFAULT_PLAIN_THRESHOLD
                )
            )
        except Exception:  # noqa: BLE001 - fall back to the default
            return DEFAULT_PLAIN_THRESHOLD

    def _require_meta(self) -> VaultMeta:
        """Load metadata on demand; raises :class:`NotFound` when absent."""
        if self._meta is None:
            self._meta = VaultMeta.load(self._home / META_FILENAME)
        return self._meta

    def _require_index(self) -> Index:
        """Open the metadata index on demand (metadata stays readable while locked)."""
        if self._index is None:
            self._index = Index(self._home / "meta.sqlite")
        return self._index

    def _require_unlocked(self) -> None:
        """Raise :class:`VaultLocked` when the vault is locked."""
        if self.is_locked or self._fs is None or self._store is None:
            raise VaultLocked("vault_locked")

    # ---------------------------------------------------------------------- sync
    def sync_manager(self) -> Any:
        """Return (creating) the S3 sync manager for this session."""
        from .sync import SyncManager  # noqa: PLC0415 - avoid an import cycle

        if self._sync_manager is None:
            self._sync_manager = SyncManager(self, client=self._sync_client)
        return self._sync_manager

    def set_sync_client(self, client: Any | None) -> dict[str, Any]:
        """Inject an S3 client (tests/self-test) and re-run the startup lock check."""
        self._sync_client = client
        self._sync_manager = None
        return self._init_sync()

    def _init_sync(self) -> dict[str, Any]:
        """Resolve the sync config and try to acquire the S3 write lock.

        Called on unlock. A vault with sync disabled stays fully writable; a configured
        bucket that is locked (or unreachable) resolves to read-only.
        """
        manager = self.sync_manager()
        try:
            manager.startup()
        except Exception:  # noqa: BLE001 - startup must never block unlocking
            manager.readonly = bool(manager.config.configured)
        return manager.status()

    def _require_writable(self, tool: str) -> None:
        """Refuse a mutation when another S3 client holds the write lock.

        This is the single gate every write path goes through: the check runs at write
        time (not only at startup), so it stays correct even if S3 is configured later
        in the session.
        """
        if getattr(self, "_syncing", False):
            raise SyncError(
                "sync_in_progress", details={"hint": "wait for the sync to finish"}
            )
        manager = self._sync_manager
        if manager is None or not manager.readonly:
            return
        self._log(
            source=SOURCE_UI,
            tool=tool,
            outcome="deny",
            code=SyncReadOnly.code,
            details="sync_readonly",
        )
        raise SyncReadOnly(
            "sync_readonly", details={"held_by": manager.lock_info}
        )

    def _log(
        self,
        *,
        source: str,
        tool: str,
        outcome: str,
        target_path: str | None = None,
        code: str | None = None,
        details: str | None = None,
        session: str | None = None,
    ) -> None:
        """Append an access-log row, never letting logging failure mask the operation.

        While an API dispatch is running the *service* owns the single row for the call (so the
        tool column carries the API method name), and core-level rows are suppressed — otherwise
        every real read/write produced two rows.
        """
        if getattr(self, "_suppress_log", False):
            return
        try:
            self._require_index().log_access(
                source=source,
                role=source,
                tool=tool,
                target_path=target_path,
                outcome=outcome,
                code=code,
                details=details,
                session=session,
            )
        except Exception:  # noqa: BLE001 - logging is best effort
            pass

    def _deny(
        self,
        tool: str,
        path: str,
        source: str,
        reason: str,
        session: str | None = None,
    ) -> None:
        """Log a deny row and raise :class:`PermissionDenied`."""
        self._log(
            source=source,
            tool=tool,
            target_path=path,
            outcome="deny",
            code=PermissionDenied.code,
            details=reason,
            session=session,
        )
        raise PermissionDenied(reason, details={"path": path})

    def _emit_activity(
        self,
        *,
        kind: str,
        tool: str,
        path: str | None,
        sensitivity: str | None,
        outcome: str,
        bytes: int | None = None,
        session: str | None = None,
        query: str | None = None,
    ) -> None:
        """Emit one metadata-only activity event (SPEC/09 §7).

        The event carries the path, level, source, tool, outcome and byte count — never any
        file content. ``query`` is the *request* string of a search call, so the local user
        can see exactly what an agent searched for in the tray/activity feed; it is shown to
        the owner only and is never written to the access log.
        """
        callback = self.on_activity
        if callback is None:
            return
        event = {
            "ts": now_ms(),
            "source": self._activity_source or "gui",
            "tool": tool,
            "path": path,
            "sensitivity": sensitivity,
            "outcome": outcome,
            "bytes": bytes,
            "session": session,
            "kind": kind,
            "query": query,
        }
        try:
            callback(event)
        except Exception:  # noqa: BLE001 - the feed must never break an operation
            pass

    # ------------------------------------------------------------------- properties
    @property
    def meta(self) -> VaultMeta:
        """The loaded vault metadata."""
        return self._require_meta()

    @property
    def index(self) -> Index:
        """The metadata index (available while locked)."""
        return self._require_index()

    @property
    def fs(self) -> VaultFS:
        """The blob store (requires an unlocked session)."""
        self._require_unlocked()
        assert self._fs is not None
        return self._fs

    @property
    def store(self) -> SecureStore:
        """The encrypted content store (requires an unlocked session)."""
        self._require_unlocked()
        assert self._store is not None
        return self._store

    def semantic_db_path(self) -> Path:
        """Resolve where the semantic vector cache lives.

        Default: ``<user data dir>/semantic/<vault_id>.db`` (under the user's home, **not**
        the synced vault). ``semantic.db_path`` may point at a ``.db`` file or a directory
        (in which case ``semantic-<vault_id>.db`` is used inside it).
        """
        meta = self._require_meta()
        settings = meta.settings
        configured = (settings.get("semantic") or {}).get("db_path")
        vault_id = str(getattr(meta, "vault_id", "") or "vault")
        from ..config import user_data_dir

        default = user_data_dir() / "semantic" / f"{vault_id}.db"
        if isinstance(configured, str) and configured.strip():
            candidate = Path(configured).expanduser()
            target = (
                candidate
                if candidate.suffix.lower() == ".db"
                else candidate / f"semantic-{vault_id}.db"
            )
            # Vectors are derived data and must live outside the synced vault; a path
            # inside the home is ignored (settings refuse to store one, but old configs
            # or symlinks could still point there).
            if is_within(target, self._home):
                LOG.warning(
                    "semantic db_path %s is inside the vault; using %s instead",
                    target,
                    default,
                )
                return default
            return target
        return default

    @property
    def semantic_store(self) -> SemanticStore:
        """The separate encrypted semantic index (requires an unlocked session).

        The vector cache is a **rebuildable local cache** under the user's home (or a path
        chosen in Settings), not part of the synced vault: it is opened on first semantic
        use, created empty when missing, and re-derived on a new machine by re-indexing.
        It needs the optional ``sqlite-vec`` extension.
        """
        self._require_unlocked()
        if self._semantic_store is None:
            assert self._master_key is not None
            path = self.semantic_db_path()
            try:
                self._semantic_store = SemanticStore.open(
                    path, self._master_key, self._runtime
                )
            except NotFound:
                self._semantic_store = SemanticStore.create_new(
                    path, self._master_key, self._runtime
                )
        return self._semantic_store

    def reload_semantic_store(self) -> None:
        """Flush and forget the open cache so the next use re-resolves its path."""
        if self._semantic_store is not None:
            try:
                self._semantic_store.close()
            except Exception:  # noqa: BLE001 - the cache is rebuildable
                pass
            self._semantic_store = None

    def _forget_semantic(self, file_id: int) -> None:
        """Drop a file's semantic chunks when its content stops being searchable."""
        if self._semantic_store is not None:
            try:
                self._semantic_store.delete_file(int(file_id))
            except Exception:  # noqa: BLE001 - the semantic index is a rebuildable cache
                pass

    def prune_semantic_folders(self) -> int:
        """Drop chunks for files that are no longer inside an included folder."""
        if self._semantic_store is None:
            return 0
        states = semantics.folder_states(self._require_meta().settings)
        index = self._require_index()
        removed = 0
        for file_id in list(self._semantic_store.indexed_files()):
            row = index.get_file_by_id(int(file_id))
            if row is None or not semantics.file_included(
                str(row["logical_path"]), states
            ):
                removed += self._semantic_store.delete_file(int(file_id))
        if removed:
            self._semantic_store.flush()
        return removed

    @property
    def semantic_provider(self) -> semantics.EmbeddingProvider | None:
        """The embedding provider, resolved lazily from the settings when not injected.

        An explicitly injected provider (tests, self-test) always wins. Otherwise the
        provider is built from the vault's ``semantic`` settings on first use and cached;
        a missing optional backend resolves to ``None`` instead of raising, so the rest of
        the app keeps working. Call :meth:`refresh_semantic_provider` after changing the
        settings.
        """
        if self._semantic_provider is not None:
            return self._semantic_provider
        if not self._semantic_resolved:
            self._semantic_resolved = True
            self._semantic_auto_provider = self._build_semantic_provider()
        return self._semantic_auto_provider

    def _build_semantic_provider(self) -> semantics.EmbeddingProvider | None:
        """Build a provider from the current settings, or ``None`` when unavailable."""
        try:
            settings = self._require_meta().settings
        except VaultError:
            return None
        try:
            return semantics.get_provider(settings)
        except semantics.ProviderUnavailable:
            return None

    def set_semantic_provider(self, provider: semantics.EmbeddingProvider | None) -> None:
        """Inject an embedding provider (tests use :class:`~vault.core.semantics.StubProvider`)."""
        self._semantic_provider = provider

    def refresh_semantic_provider(self) -> None:
        """Forget the settings-derived provider so the next use rebuilds it.

        The explicitly injected provider is untouched.
        """
        self._semantic_auto_provider = None
        self._semantic_resolved = False

    # ---------------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        """Return a JSON-ready snapshot of the vault state."""
        meta = self._require_meta()
        counts = self._require_index().count()
        semantic_settings = meta.settings.get("semantic", {})
        available, reason = semantics.is_available(meta.settings)
        store_stats = (
            self._store.stats()
            if self._store is not None
            else {"fts_rows": 0, "notes": 0, "vectors": 0, "bytes": 0}
        )
        if self._semantic_store is not None:
            semantic_stats = self._semantic_store.stats()
        else:
            semantic_stats = {
                "chunks": 0,
                "files": 0,
                "model": None,
                "chunking": None,
                "bytes": 0,
                "last_reset": None,
            }
        return {
            "locked": self.is_locked,
            "home": str(self._home),
            "files": counts["files"],
            "folders": counts["dirs"],
            "by_level": counts["by_level"],
            "semantic": {
                "enabled": bool(semantic_settings.get("enabled")),
                "available": available,
                "reason": reason,
                "model": semantic_settings.get("model"),
                "chunking": semantics.chunk_mode(meta.settings),
                "chunks": int(semantic_stats["chunks"]),
                "indexed_files": int(semantic_stats["files"]),
                "bytes": int(semantic_stats["bytes"]),
                "db_path": str(self.semantic_db_path()),
                "last_reset": semantic_stats.get("last_reset"),
                "cache": self.semantic_cache_stats(),
                "queue": self._semantic_queue.stats() if self._semantic_queue else {
                    "pending": 0,
                    "debounce_ms": 0,
                    "last_error": None,
                },
            },
            "auto_lock_seconds": int(meta.settings.get("auto_lock_seconds", 0) or 0),
            "store": store_stats,
            "sync": self.sync_manager().status(),
        }

    def apply_sync_settings(self) -> dict[str, Any]:
        """Re-read the sync settings/credentials and re-run the startup lock check."""
        manager = self.sync_manager()
        manager.set_client(self._sync_client)
        manager.reload_config()
        try:
            return manager.startup()
        except Exception:  # noqa: BLE001 - never let a bad bucket break settings save
            manager.readonly = bool(manager.config.configured)
            return manager.status()

    def semantic_cache_stats(self) -> dict[str, Any]:
        """Return the vector-cache stats for the currently indexed model, if known.

        Read-only: it never creates the cache file and never prunes on a status poll.
        """
        empty = {
            "entries": 0,
            "bytes": 0,
            "hits": 0,
            "misses": 0,
            "hit_rate": 0.0,
            "path": None,
        }
        model = None
        dim = None
        if self._semantic_store is not None:
            meta = self._semantic_store.meta()
            model = meta.get("model")
            dim = meta.get("dim")
        if not model:
            model = (self._require_meta().settings.get("semantic") or {}).get("model")
        if not model or not dim:
            return empty
        try:
            from .vector_cache import VectorCache  # noqa: PLC0415

            path = VectorCache.default_path(str(model), int(dim))
            if not path.exists():
                result = dict(empty)
                result["path"] = str(path)
                return result
            cap = int(
                (self._require_meta().settings.get("semantic") or {}).get(
                    "cache_max_mb", 512
                )
                or 512
            )
            cache = VectorCache(
                path,
                model=str(model),
                dim=int(dim),
                max_bytes=max(0, cap) * 1024 * 1024,
                prune_on_open=False,
            )
            stats = cache.stats()
            cache.close()
            return stats
        except Exception:  # noqa: BLE001 - stats are informational only
            return empty

    def clear_semantic_cache(self, *, source: str = SOURCE_UI) -> int:
        """Delete the on-disk embedding cache and reset its stats."""
        try:
            from .vector_cache import VectorCache  # noqa: PLC0415

            return VectorCache.clear_all()
        except Exception:  # noqa: BLE001 - best effort
            return 0

    # ----------------------------------------------------------------------- files
    def list_folder(self, path: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """List the direct children of ``path`` (metadata only; works while locked)."""
        logical = normalize_vault_path(path)
        entries = self._require_index().list_dir(logical)
        self._emit_activity(
            kind="list", tool="list_folder", path=logical, sensitivity=None,
            outcome="allow",
        )
        return {"path": logical, "entries": entries}

    def read_file(
        self, path: str, *, source: str = SOURCE_UI, session: str | None = None
    ) -> bytes:
        """Read and decrypt a file's content, enforcing policy.

        Raises:
            VaultLocked: when the session is locked.
            PermissionDenied: when the source may not read this level.
        """
        logical = normalize_vault_path(path)
        try:
            self._require_unlocked()
        except VaultLocked:
            self._emit_activity(
                kind="read", tool="read_file", path=logical, sensitivity=None,
                outcome="deny", session=session,
            )
            raise
        row = self._require_index().require_file(logical)
        if int(row["is_dir"]):
            raise BadRequest("is_directory", details={"path": logical})
        if not Policy.can_read_content(row["sensitivity"], source):
            self._emit_activity(
                kind="read", tool="read_file", path=logical,
                sensitivity=row["sensitivity"], outcome="deny", session=session,
            )
            self._deny("read_file", logical, source, "content_forbidden", session)
        data = self.fs.read_bytes(row)
        self._emit_activity(
            kind="read", tool="read_file", path=logical,
            sensitivity=row["sensitivity"], outcome="allow", bytes=len(data),
            session=session,
        )
        self._log(
            source=source, tool="read_file", target_path=logical, outcome="allow",
            session=session,
        )
        return data

    def read_text(
        self,
        path: str,
        *,
        source: str = SOURCE_UI,
        encoding: str = "utf-8",
    ) -> str:
        """Read a file's content and decode it with ``encoding``."""
        return self.read_file(path, source=source).decode(encoding, errors="strict")

    def read_lines(
        self, path: str, start: int, count: int, *, source: str = SOURCE_UI
    ) -> str:
        """Return ``count`` lines starting at 0-based line ``start`` as text."""
        text = self.read_text(path, source=source)
        lines = text.splitlines()
        start = max(0, int(start))
        return "\n".join(lines[start : start + int(count)])

    def _read_raw(self, row: dict[str, Any]) -> bytes:
        """Read a row's content bypassing policy (internal use only)."""
        self._require_unlocked()
        assert self._fs is not None
        return self._fs.read_bytes(row)

    def _index_file_text(self, file_id: int, text: str) -> None:
        """(Re)index a file's body together with its short note into FTS."""
        store = self._store
        note = store.get_file_note(int(file_id)) if store is not None else ""
        if store is not None:
            store.index_text(int(file_id), text, note=note or "")

    @staticmethod
    def _record_version(
        idx: Index,
        file_id: int,
        new_row: dict[str, Any],
        existing: dict[str, Any] | None,
        data: bytes,
        blob_id: str,
        source: str,
    ) -> None:
        """Append a content version, seeding the previous content the first time.

        Every save keeps its own blob (the old blob is never deleted here), so the full
        history stays browsable; identical content does not create a new version.
        """
        digest = sha256_hex(data)
        if (
            existing is not None
            and existing.get("blob_id")
            and idx.version_count(file_id) == 0
        ):
            idx.record_version(
                file_id,
                blob_id=str(existing["blob_id"]),
                size=int(existing.get("size") or 0),
                encrypted=int(existing.get("encrypted") or 1),
                sensitivity=str(existing.get("sensitivity") or "normal"),
                mtime=int(existing.get("mtime") or now_ms()),
                source=str(existing.get("source") or "ui"),
            )
        latest = idx.latest_version(file_id)
        if latest is None or latest.get("digest") != digest:
            idx.record_version(
                file_id,
                blob_id=str(blob_id),
                size=int(new_row["size"]),
                encrypted=int(new_row["encrypted"]),
                sensitivity=str(new_row["sensitivity"]),
                mtime=int(new_row["mtime"]),
                source=source,
                digest=digest,
            )

    def write_file(
        self,
        path: str,
        data: bytes,
        *,
        source: str = SOURCE_UI,
        create_parents: bool = True,
        sensitivity: str | None = None,
    ) -> dict[str, Any]:
        """Write content to ``path`` (creating/updating the row) and return it.

        Raises:
            VaultLocked: when the session is locked.
            PermissionDenied: when MCP tries to create a non-``normal`` file.
            DowngradeForbidden: when a sensitivity change violates policy.
        """
        logical = normalize_vault_path(path)
        self._require_unlocked()
        self._require_writable("write_file")
        if logical == "/":
            raise BadRequest("cannot_write_root")
        idx = self._require_index()
        existing = idx.get_file(logical)
        if existing is not None and int(existing["is_dir"]):
            raise BadRequest("is_directory", details={"path": logical})
        if sensitivity is not None and sensitivity not in LEVELS:
            raise BadRequest("unknown_level", details={"level": sensitivity})
        if existing is not None:
            old_level = existing["sensitivity"]
        else:
            old_level = self._require_meta().settings.get("default_sensitivity", "normal")
            if old_level not in LEVELS:
                old_level = "normal"
        desired = sensitivity if sensitivity is not None else old_level
        if existing is None and source == SOURCE_MCP and desired != "normal":
            self._deny(
                "write_file", logical, source, "mcp_cannot_create_secret", None
            )
        if desired != old_level:
            if rank(desired) > rank(old_level):
                if not Policy.can_raise(old_level, desired, source):
                    raise DowngradeForbidden("raise_forbidden")
            elif not Policy.can_lower(old_level, desired, source):
                raise DowngradeForbidden("downgrade_forbidden")
        if create_parents:
            self._ensure_parents(logical, source)
        blob_id, size, encrypted = self.fs.write_blob(data, sensitivity=desired)
        file_id = idx.upsert_file(
            logical,
            blob_id=blob_id,
            is_dir=False,
            size=size,
            encrypted=encrypted,
            sensitivity=desired,
            source=source,
        )
        new_row = idx.require_file(logical)
        self._record_version(idx, file_id, new_row, existing, data, blob_id, source)
        if desired == "normal":
            self._index_file_text(file_id, data.decode("utf-8", errors="ignore"))
        else:
            self._store.remove_file(file_id)
            self._forget_semantic(file_id)
        self.flush()
        self._log(
            source=source, tool="write_file", target_path=logical, outcome="allow"
        )
        self._emit_activity(
            kind="write",
            tool="write_file",
            path=logical,
            sensitivity=desired,
            outcome="allow",
            bytes=size,
        )
        return new_row

    def write_lines(
        self,
        path: str,
        text: str,
        *,
        mode: str = "append",
        at_line: int | None = None,
        source: str = SOURCE_UI,
    ) -> dict[str, Any]:
        """Append/prepend/replace/insert lines into a file and return its row."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        idx = self._require_index()
        existing = idx.get_file(logical)
        current = ""
        if existing is not None and not int(existing["is_dir"]):
            current = self._read_raw(existing).decode("utf-8", errors="ignore")
        lines = current.splitlines()
        new_lines = text.splitlines()
        if mode == "replace":
            combined = text
        elif mode == "prepend":
            combined = "\n".join(new_lines + lines)
        elif mode == "insert":
            position = max(0, int(at_line if at_line is not None else len(lines)))
            merged = lines[:position] + new_lines + lines[position:]
            combined = "\n".join(merged)
        elif mode == "append":
            if current and not current.endswith("\n"):
                current += "\n"
            combined = current + text
        else:
            raise BadRequest("unknown_mode", details={"mode": mode})
        return self.write_file(logical, combined.encode("utf-8"), source=source)

    def _ensure_parents(self, logical: str, source: str) -> None:
        """Create any missing ancestor directories for ``logical``."""
        idx = self._require_index()
        parts = logical.split("/")[:-1]
        prefix = ""
        for part in parts:
            prefix = f"{prefix}/{part}" if prefix else part
            if idx.get_file(prefix) is None:
                idx.upsert_file(prefix, is_dir=True, sensitivity="normal", source=source)

    def mkdir(self, path: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Create a directory (and any missing parents) and return its row."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        self._require_writable("mkdir")
        if logical == "/":
            raise AlreadyExists("root_exists")
        idx = self._require_index()
        if idx.get_file(logical) is not None:
            raise AlreadyExists("path_exists", details={"path": logical})
        self._ensure_parents(logical, source)
        idx.upsert_file(logical, is_dir=True, sensitivity="normal", source=source)
        self.flush()
        self._log(source=source, tool="mkdir", target_path=logical, outcome="allow")
        self._emit_activity(
            kind="mkdir", tool="mkdir", path=logical, sensitivity=None, outcome="allow"
        )
        return idx.require_file(logical)

    def move(self, src: str, dst: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Move/rename a file or directory and return the destination row."""
        source_path = normalize_vault_path(src)
        dest_path = normalize_vault_path(dst)
        self._require_unlocked()
        self._require_writable("move")
        idx = self._require_index()
        idx.require_file(source_path)
        idx.move(source_path, dest_path)
        self.flush()
        self._log(source=source, tool="move", target_path=dest_path, outcome="allow")
        self._emit_activity(
            kind="move", tool="move", path=dest_path, sensitivity=None, outcome="allow"
        )
        return idx.require_file(dest_path)

    def copy(self, src: str, dst: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Copy a file or directory recursively and return the destination row."""
        source_path = normalize_vault_path(src)
        dest_path = normalize_vault_path(dst)
        self._require_unlocked()
        self._require_writable("copy")
        idx = self._require_index()
        row = idx.require_file(source_path)
        if idx.get_file(dest_path) is not None:
            raise AlreadyExists("destination_exists", details={"path": dest_path})
        if int(row["is_dir"]):
            idx.upsert_file(dest_path, is_dir=True, sensitivity="normal", source=source)
            prefix = source_path + "/"
            for child in list(idx.walk(source_path)):
                if child["logical_path"] == source_path:
                    continue
                suffix = child["logical_path"][len(prefix):]
                target = f"{dest_path}/{suffix}"
                if int(child["is_dir"]):
                    idx.upsert_file(target, is_dir=True, sensitivity="normal", source=source)
                else:
                    self._copy_file(child, target, source)
        else:
            self._copy_file(row, dest_path, source)
        self.flush()
        self._log(source=source, tool="copy", target_path=dest_path, outcome="allow")
        return idx.require_file(dest_path)

    def _copy_file(self, row: dict[str, Any], dest_path: str, source: str) -> None:
        """Copy one file row to ``dest_path`` honoring read policy."""
        if not Policy.can_read_content(row["sensitivity"], source):
            self._deny("copy", row["logical_path"], source, "content_forbidden", None)
        data = self._read_raw(row)
        blob_id, size, encrypted = self.fs.write_blob(data, sensitivity=row["sensitivity"])
        idx = self._require_index()
        file_id = idx.upsert_file(
            dest_path,
            blob_id=blob_id,
            is_dir=False,
            size=size,
            encrypted=encrypted,
            sensitivity=row["sensitivity"],
            source=source,
        )
        new_row = idx.require_file(dest_path)
        idx.record_version(
            file_id,
            blob_id=blob_id,
            size=int(new_row["size"]),
            encrypted=int(new_row["encrypted"]),
            sensitivity=str(new_row["sensitivity"]),
            mtime=int(new_row["mtime"]),
            source=source,
            digest=sha256_hex(data),
        )
        if row["sensitivity"] == "normal":
            self._index_file_text(file_id, data.decode("utf-8", errors="ignore"))

    def delete(
        self, path: str, *, source: str = SOURCE_UI, recursive: bool = False
    ) -> dict[str, Any]:
        """Delete a file (or directory) and its blobs/content rows."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        self._require_writable("delete")
        idx = self._require_index()
        # Gather every blob (current + historical) before the rows disappear.
        blobs: list[str] = []
        for candidate in idx.walk(logical):
            if candidate.get("blob_id"):
                blobs.append(str(candidate["blob_id"]))
            for version in idx.list_versions(int(candidate["id"])):
                blobs.append(str(version.get("blob_id") or ""))
        removed = idx.delete_file(logical, recursive=recursive)
        for blob_id in blobs:
            self.fs.delete_blob(blob_id)
        for row in removed:
            self._store.remove_file(int(row["id"]))
            self._forget_semantic(int(row["id"]))
        self.flush()
        self._log(source=source, tool="delete", target_path=logical, outcome="allow")
        self._emit_activity(
            kind="delete", tool="delete", path=logical, sensitivity=None, outcome="allow"
        )
        return {
            "path": logical,
            "deleted": len(removed),
            "removed": [row["logical_path"] for row in removed],
        }

    def set_sensitivity(
        self, path: str, level: str, *, source: str = SOURCE_UI
    ) -> dict[str, Any]:
        """Change a file/folder sensitivity level, enforcing raise/lower policy."""
        logical = normalize_vault_path(path)
        if level not in LEVELS:
            raise BadRequest("unknown_level", details={"level": level})
        self._require_unlocked()
        self._require_writable("set_sensitivity")
        idx = self._require_index()
        row = idx.require_file(logical)
        old_level = row["sensitivity"]
        if level == old_level:
            return row
        if rank(level) > rank(old_level):
            if not Policy.can_raise(old_level, level, source):
                raise DowngradeForbidden("raise_forbidden")
        elif not Policy.can_lower(old_level, level, source):
            self._log(
                source=source, tool="set_sensitivity", target_path=logical,
                outcome="deny", code=DowngradeForbidden.code,
            )
            raise DowngradeForbidden("downgrade_forbidden")
        if int(row["is_dir"]):
            idx.set_sensitivity(logical, level)
            new_row = idx.require_file(logical)
        else:
            # The blob AAD binds its sensitivity, so a level change must re-encrypt the
            # content; otherwise the file becomes undecryptable under the new level.
            if row.get("blob_id"):
                data = self._read_raw(row)
                blob_id, size, encrypted = self.fs.write_blob(data, sensitivity=level)
                idx.upsert_file(
                    logical,
                    blob_id=blob_id,
                    is_dir=False,
                    size=size,
                    encrypted=encrypted,
                    sensitivity=level,
                    source=source,
                )
                # The previous blob is kept: historical versions still reference it.
            else:
                idx.set_sensitivity(logical, level)
            new_row = idx.require_file(logical)
            if level == "normal":
                data = self._read_raw(new_row)
                self._index_file_text(int(new_row["id"]), data.decode("utf-8", "ignore"))
            else:
                self._store.remove_file(int(new_row["id"]))
                self._forget_semantic(int(new_row["id"]))
        self.flush()
        self._log(source=source, tool="set_sensitivity", target_path=logical, outcome="allow")
        self._emit_activity(
            kind="write",
            tool="set_sensitivity",
            path=logical,
            sensitivity=str(new_row["sensitivity"]),
            outcome="allow",
        )
        return new_row

    def set_tags(
        self, path: str, tags: list[str], *, source: str = SOURCE_UI
    ) -> dict[str, Any]:
        """Replace a file's tags and return its row with ``tags`` attached."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        self._require_writable("set_tags")
        idx = self._require_index()
        idx.set_tags(logical, tags)
        self.flush()
        self._log(source=source, tool="set_tags", target_path=logical, outcome="allow")
        row = idx.require_file(logical)
        row["tags"] = idx.get_tags(logical)
        self._emit_activity(
            kind="write",
            tool="set_tags",
            path=logical,
            sensitivity=str(row["sensitivity"]),
            outcome="allow",
        )
        return row

    def folder_note(self, path: str, *, source: str = SOURCE_UI) -> str | None:
        """Return the note attached to a folder, if any."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        return self._store.get_folder_note(logical)

    def set_folder_note(self, path: str, text: str, *, source: str = SOURCE_UI) -> None:
        """Attach/replace the note on a folder."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        self._require_writable("set_folder_note")
        self._store.set_folder_note(logical, text)
        self.flush()
        self._log(
            source=source, tool="set_folder_note", target_path=logical, outcome="allow"
        )
        self._emit_activity(
            kind="write",
            tool="set_folder_note",
            path=logical,
            sensitivity=None,
            outcome="allow",
            bytes=len(text.encode("utf-8")),
        )

    def file_note(self, path: str, *, source: str = SOURCE_UI) -> str | None:
        """Return the short note attached to a file, if any."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        row = self._require_index().require_file(logical)
        return self._store.get_file_note(int(row["id"]))

    def set_file_note(self, path: str, text: str, *, source: str = SOURCE_UI) -> None:
        """Attach/replace the short note on a file and keep search in sync."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        self._require_writable("set_file_note")
        row = self._require_index().require_file(logical)
        if int(row["is_dir"]):
            raise BadRequest("is_directory", details={"path": logical})
        file_id = int(row["id"])
        self._store.set_file_note(file_id, text)
        if row["sensitivity"] == "normal":
            try:
                data = self._read_raw(row)
                self._index_file_text(file_id, data.decode("utf-8", errors="ignore"))
            except VaultError:
                pass
            self._auto_index_semantics(logical)
        self.flush()
        self._log(
            source=source, tool="set_file_note", target_path=logical, outcome="allow"
        )
        self._emit_activity(
            kind="write",
            tool="set_file_note",
            path=logical,
            sensitivity=str(row["sensitivity"]),
            outcome="allow",
            bytes=len(text.encode("utf-8")),
        )

    # ---------------------------------------------------------------------- digest
    def digest(
        self, path: str, *, depth: int = 1, source: str = SOURCE_UI
    ) -> dict[str, Any]:
        """Return one compact overview of a folder (or file), notes included.

        Replaces the N+1 round-trips an agent needs today to understand a folder: the
        folder's note plus, for each child (recursively up to ``depth``), its name, size,
        sensitivity, tags, note and — for normal files — the first non-empty line.
        """
        logical = normalize_vault_path(path)
        self._require_unlocked()
        row = self._require_index().require_file(logical)
        if int(row["is_dir"]):
            result = self._digest_folder(logical, max(0, int(depth)))
        else:
            result = self._digest_file(row)
        self._log(source=source, tool="digest", target_path=logical, outcome="allow")
        return result

    def _digest_folder(self, logical: str, depth: int) -> dict[str, Any]:
        """Build the recursive digest payload for ``logical``."""
        idx = self._require_index()
        entries: list[dict[str, Any]] = []
        for child in idx.list_dir(logical):
            child_path = str(child["logical_path"])
            if not int(child["is_dir"]):
                entries.append(self._digest_file(child))
            elif depth > 0:
                entries.append(self._digest_folder(child_path, depth - 1))
            else:
                entries.append(
                    {
                        "name": child_path.rsplit("/", 1)[-1],
                        "path": "/" + child_path.lstrip("/"),
                        "is_dir": True,
                        "size": int(child["size"]),
                        "mtime": int(child["mtime"]),
                        "sensitivity": child["sensitivity"],
                        "tags": idx.get_tags(child_path),
                        "note": self._store.get_folder_note(child_path),
                        "entries": [],
                    }
                )
        return {
            "name": "/" if logical == "/" else logical.rsplit("/", 1)[-1],
            "path": "/" + logical.lstrip("/"),
            "is_dir": True,
            "note": self._store.get_folder_note(logical),
            "entries": entries,
        }

    def _digest_file(self, row: dict[str, Any]) -> dict[str, Any]:
        """Build the digest payload for one file (first line only when normal)."""
        idx = self._require_index()
        logical = str(row["logical_path"])
        entry: dict[str, Any] = {
            "name": logical.rsplit("/", 1)[-1],
            "path": "/" + logical.lstrip("/"),
            "is_dir": False,
            "size": int(row["size"]),
            "mtime": int(row["mtime"]),
            "sensitivity": row["sensitivity"],
            "tags": idx.get_tags(logical),
            "note": self._store.get_file_note(int(row["id"])),
            "first_line": None,
        }
        if row["sensitivity"] == "normal":
            try:
                data = self._read_raw(row)
            except VaultError:
                data = b""
            for line in data.decode("utf-8", errors="ignore").splitlines():
                if line.strip():
                    entry["first_line"] = line.strip()[:200]
                    break
        return entry

    # -------------------------------------------------------------------- versions
    def versions(self, path: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Return every stored version of a file, newest first."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        row = self._require_index().require_file(logical)
        if int(row["is_dir"]):
            raise BadRequest("is_directory", details={"path": logical})
        rows = self._require_index().list_versions(int(row["id"]))
        return {
            "path": logical,
            "count": len(rows),
            "versions": [
                {
                    "version": int(v["version"]),
                    "mtime": int(v["mtime"]),
                    "size": int(v["size"]),
                    "sensitivity": str(v["sensitivity"]),
                    "source": str(v["source"]),
                }
                for v in rows
            ],
        }

    def version_text(
        self,
        path: str,
        version: int,
        *,
        source: str = SOURCE_UI,
        encoding: str = "utf-8",
    ) -> str:
        """Return the decoded content of one historical version."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        row = self._require_index().require_file(logical)
        version_row = self._require_index().get_version(int(row["id"]), int(version))
        if version_row is None:
            raise NotFound(
                "version_not_found", details={"path": logical, "version": version}
            )
        return self.fs.read_bytes(version_row).decode(encoding, errors="replace")

    def diff(
        self,
        path: str,
        from_version: int,
        to_version: int,
        *,
        source: str = SOURCE_UI,
    ) -> dict[str, Any]:
        """Return a git-style line diff between any two versions of a file."""
        logical = normalize_vault_path(path)
        before = self.version_text(logical, from_version).splitlines()
        after = self.version_text(logical, to_version).splitlines()
        hunks: list[dict[str, Any]] = []
        for tag, a1, a2, b1, b2 in difflib.SequenceMatcher(
            a=before, b=after
        ).get_opcodes():
            hunks.append(
                {
                    "type": tag,  # equal | replace | delete | insert
                    "a_start": a1 + 1,
                    "a_lines": before[a1:a2],
                    "b_start": b1 + 1,
                    "b_lines": after[b1:b2],
                }
            )
        return {
            "path": logical,
            "from": int(from_version),
            "to": int(to_version),
            "hunks": hunks,
        }

    # ---------------------------------------------------------------------- search
    def search_filenames(
        self,
        query: str,
        *,
        limit: int = 50,
        path_prefix: str | None = None,
        source: str = SOURCE_UI,
    ) -> list[dict[str, Any]]:
        """Search filenames (all levels, names only), optionally under ``path_prefix``."""
        results = search_mod.search_filenames(
            self, query, limit=limit, path_prefix=path_prefix
        )
        self._emit_activity(
            kind="search", tool="search_filenames", path=None, sensitivity=None,
            outcome="allow", query=query,
        )
        self._log(source=source, tool="search_filenames", outcome="allow")
        return results

    def search_text(
        self,
        query: str,
        *,
        limit: int = 50,
        path_prefix: str | None = None,
        source: str = SOURCE_UI,
    ) -> list[dict[str, Any]]:
        """Search literal content (``normal`` files only), optionally under a prefix."""
        self._require_unlocked()
        results = search_mod.search_text(
            self, query, limit=limit, path_prefix=path_prefix
        )
        self._emit_activity(
            kind="search", tool="search_text", path=None, sensitivity=None,
            outcome="allow", query=query,
        )
        self._log(source=source, tool="search_text", outcome="allow")
        return results

    def search_semantic(
        self,
        query: str,
        *,
        limit: int = 50,
        path_prefix: str | None = None,
        source: str = SOURCE_UI,
    ) -> list[dict[str, Any]]:
        """Search by embedding similarity (``normal`` files only), optionally scoped."""
        self._require_unlocked()
        results = search_mod.search_semantic(
            self, query, limit=limit, path_prefix=path_prefix
        )
        self._emit_activity(
            kind="search", tool="search_semantic", path=None, sensitivity=None,
            outcome="allow", query=query,
        )
        self._log(source=source, tool="search_semantic", outcome="allow")
        return results

    # ------------------------------------------------------- secrets / UI handoff
    def request_open_secret(
        self, path: str, *, source: str = SOURCE_MCP, session: str | None = None
    ) -> dict[str, Any]:
        """Ask the UI to display a ``secretfile``; the agent never receives content.

        Raises:
            PermissionDenied: for any level other than ``secretfile``.
        """
        logical = normalize_vault_path(path)
        self._require_unlocked()
        row = self._require_index().require_file(logical)
        if row["sensitivity"] != "secretfile" or not Policy.can_request_open_secret(
            row["sensitivity"], source
        ):
            self._emit_activity(
                kind="read", tool="request_open_secret", path=logical,
                sensitivity=row["sensitivity"], outcome="deny", session=session,
            )
            self._deny(
                "request_open_secret", logical, source, "only_secretfile", session
            )
        request_id = uuid.uuid4().hex
        request: dict[str, Any] = {
            "request_id": request_id,
            "path": logical,
            "status": "pending",
            "created_at": now_ms(),
        }
        self._pending[request_id] = request
        if self.on_secret_request is not None:
            try:
                outcome = self.on_secret_request(request)
                if isinstance(outcome, str) and outcome in ("pending", "shown", "denied"):
                    request["status"] = outcome
            except Exception:  # noqa: BLE001 - UI callbacks must not break the agent path
                pass
        self._log(
            source=source, tool="request_open_secret", target_path=logical,
            outcome="allow", session=session,
        )
        return {"request_id": request_id, "status": request["status"]}

    def resolve_open_secret(self, request_id: str, *, approved: bool) -> dict[str, Any]:
        """Resolve a pending secret-open request as ``shown`` or ``denied``."""
        request = self._pending.pop(request_id, None)
        if request is None:
            raise NotFound("request_not_found", details={"request_id": request_id})
        request["status"] = "shown" if approved else "denied"
        return request

    def pending_requests(self) -> list[dict[str, Any]]:
        """Return the pending secret-open requests."""
        return list(self._pending.values())

    # ------------------------------------------------------------------------ log
    def access_log(self, **kw: Any) -> list[dict[str, Any]]:
        """Return access-log rows (delegates to the metadata index)."""
        return self._require_index().access_log(**kw)


__all__ = ["VaultSession"]
