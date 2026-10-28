"""The :class:`VaultSession` façade — the single entry point to a vault (SPEC/01 §12).

Owns the metadata, index, blob store, encrypted content store, master key and lock state.
Every content operation is gated by :class:`~vault.core.security.Policy` using the
role-derived source (``ui`` in-process, ``mcp`` over the socket) and refusals are logged
before raising.
"""

from __future__ import annotations

import base64
import difflib
import logging
import re
import secrets
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
from . import credentials
from . import journal as journal_mod
from . import search as search_mod
from . import sync_ops
from . import semantics
from . import retention
from . import learning
from .crypto import check_canary, decrypt_blob, derive_master_key, encrypt_blob
from .index import Index
from .meta import META_FILENAME, VaultMeta
from .security import (
    LEVELS,
    SECRET_LEVELS,
    SOURCE_MCP,
    SOURCE_UI,
    Policy,
    rank,
)
from .semantic_queue import SemanticIndexQueue
from .semantic_store import SemanticStore
from .store import STORE_FILENAME, SecureStore
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
        #: The credential-field index (metadata only: title/site/category/url/username).
        self._credentials: Any | None = None
        #: This machine's id for the vault (machine-local; created on first mutation).
        self._journal_client: str | None = None
        #: True while remote ops are being applied — those must never be re-recorded as ours.
        self._applying_remote = False
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
        #: Requests already answered, keyed by id — the web UI polls the one it is waiting on.
        self._resolved: dict[str, dict[str, Any]] = {}
        #: Paths an explicit approval released for display, with their expiry (ms). Cleared on lock.
        self._grants: dict[str, int] = {}
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
        #: True while a bulk internal scan runs (the browser bridge's credential index): the
        #: per-file read events of such a scan would flood the tray feed with hundreds of rows
        #: that describe bookkeeping rather than use. The *reveal* is never suppressed.
        self._suppress_activity = False

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
        master_key = derive_master_key(password, meta.kdf_params())
        self._open_with_master_key(master_key)

    def unlock_with_master_key(self, master_key: bytes | bytearray) -> None:
        """Unlock the vault with a raw master key (fingerprint quick unlock).

        The key is validated against the vault's canary before any state is opened, so a
        stale or foreign key is refused exactly like a wrong password.

        Raises:
            Unauthorized: when the key does not reproduce the canary (``bad_master_key``).
        """
        meta = self._require_meta()
        candidate = bytearray(master_key)
        canary = base64.b64decode(meta.data.get("canary_b64", ""))
        if not check_canary(bytes(candidate), canary):
            wipe(candidate)
            raise Unauthorized("bad_master_key", details={"reason": "canary_mismatch"})
        if not self.is_locked:
            wipe(candidate)
            return
        self._open_with_master_key(candidate)

    def _open_with_master_key(self, master_key: bytearray) -> None:
        """Open the store, filesystem and index around ``master_key`` (assumes valid)."""
        if self._index is None:
            self._index = Index(self._home / "meta.sqlite")
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

    # --------------------------------------------------------------- quick unlock
    def quick_unlock_status(self) -> dict[str, Any]:
        """Return the fingerprint quick-unlock state for this vault.

        Combines the sensor/enrolment facts (machine-wide) with the stored record for this
        vault: ``available``, ``enabled``, ``device``, ``fingers``, ``protection`` and the
        usage counters.
        """
        meta = self._require_meta()
        from . import fingerprint  # noqa: PLC0415 - keep the core import graph flat

        state = fingerprint.quick_unlock_state(self._home)
        state["vault_id"] = meta.vault_id
        return state

    def quick_unlock_enable(
        self,
        verification: Any,
        *,
        finger: str | None = None,
    ) -> dict[str, Any]:
        """Store a wrapped copy of the master key, gated by a matched ``verification``.

        Args:
            verification: the :class:`fingerprint.VerifyResult` of a real scan; a result
                that did not match refuses the write.
            finger: optional single finger name to remember (display only).

        Raises:
            VaultLocked: when the vault is not open (there is no key to wrap).
            Unauthorized: when ``verification`` did not match.
        """
        self._require_unlocked()
        from . import fingerprint  # noqa: PLC0415 - keep the core import graph flat

        assert self._master_key is not None
        state = fingerprint.enable_quick_unlock(
            self._home, self._master_key, verification, finger=finger
        )
        self._log(
            source=SOURCE_UI,
            tool="vault.quick_unlock_enable",
            outcome="allow",
            details=f"protection={state.get('protection')}",
        )
        return state

    def quick_unlock_disable(self) -> bool:
        """Forget the stored quick-unlock record for this vault (idempotent)."""
        self._require_unlocked()
        from . import fingerprint  # noqa: PLC0415 - keep the core import graph flat

        removed = fingerprint.disable_quick_unlock(self._home)
        self._log(
            source=SOURCE_UI,
            tool="vault.quick_unlock_disable",
            outcome="allow" if removed else "no_record",
        )
        return removed

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
        # Nothing approved (and nothing asked for) while unlocked may outlive the lock.
        self._pending.clear()
        self._resolved.clear()
        self._grants.clear()
        if self._fs is not None:
            self._fs.master_key = None
            self._fs = None
        # The credential index holds decrypted metadata: it dies with the key.
        self._credentials = None

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
        # Journal mode syncs by operation log, so the legacy write lock does not gate it.
        if manager is None or not manager.readonly or self.sync_mode() == "journal":
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
        # A bulk internal metadata scan (the browser bridge's credential index) reads every
        # credential file once; those *allowed* reads describe bookkeeping, not use, and would
        # bury the feed under hundreds of rows. Refusals and errors are still emitted.
        if self._suppress_activity and outcome == "allow":
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
        base_rev = journal_mod.current_rev(idx, logical)
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
        self._journal_op(
            "put",
            logical,
            base_rev=base_rev,
            blob_id=blob_id,
            size=size,
            encrypted=encrypted,
            sensitivity=desired,
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
                self._journal_op("put", prefix, base_rev=0, is_dir=True)

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
        self._journal_op("put", logical, base_rev=0, is_dir=True)
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
        base_rev = journal_mod.current_rev(idx, source_path)
        idx.move(source_path, dest_path)
        self._journal_op("rename", dest_path, base_rev=base_rev, **{"from": source_path})
        self.flush()
        # The new name has to reach the documents too, or every note that showed the picture now
        # shows a broken link and nothing tells the user why.
        updated = self._repoint_references(source_path, dest_path, source=source)
        self._log(source=source, tool="move", target_path=dest_path, outcome="allow")
        self._emit_activity(
            kind="move", tool="move", path=dest_path, sensitivity=None, outcome="allow"
        )
        row = idx.require_file(dest_path)
        row["references_updated"] = updated
        return row

    #: Characters that make a file name part of a longer word (`data.png` is not `a.png`).
    _NAME_CHARS = r"\w.\-"

    def _repoint_references(self, old: str, new: str, *, source: str) -> int:
        """Rewrite the notes that point at a moved file, and return how many changed.

        A reference to a file in this vault is its own path — `vault:/attachments/x.png` in a
        markdown link, or a relative path ending in the same name — so a rename has to travel
        through the documents. Only `normal` files are rewritten: their text is the only text
        this session may read, and a gated note is left alone (its count is not reported).
        """
        old_path = "/" + old.strip("/")
        new_path = "/" + new.strip("/")
        old_name = old_path.rsplit("/", 1)[-1]
        new_name = new_path.rsplit("/", 1)[-1]
        name_pattern = None
        #: Only a *file* name is rewritten on its own; a folder's name is not a reference, and a
        #: bare word in prose (a name with no extension) is not a file name.
        if old_name and old_name != new_name and "." in old_name:
            name_pattern = re.compile(
                rf"(?<![{self._NAME_CHARS}]){re.escape(old_name)}(?![{self._NAME_CHARS}])"
            )
        changed = 0
        for row in list(self._require_index().walk("/")):
            if int(row["is_dir"]) or not row.get("blob_id"):
                continue
            path = str(row["logical_path"])
            if path == new or str(row["sensitivity"]) != "normal":
                continue
            try:
                text = self._read_raw(row).decode("utf-8")
            except (UnicodeDecodeError, VaultError):
                continue  # a picture, or a note that cannot be read as text
            updated = text.replace(old_path, new_path)
            if name_pattern is not None:
                updated = name_pattern.sub(new_name, updated)
            if updated == text:
                continue
            self.write_file(path, updated.encode("utf-8"), source=source)
            changed += 1
        return changed

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
            self._journal_op("put", dest_path, base_rev=0, is_dir=True)
            prefix = source_path + "/"
            for child in list(idx.walk(source_path)):
                if child["logical_path"] == source_path:
                    continue
                suffix = child["logical_path"][len(prefix):]
                target = f"{dest_path}/{suffix}"
                if int(child["is_dir"]):
                    idx.upsert_file(target, is_dir=True, sensitivity="normal", source=source)
                    self._journal_op("put", target, base_rev=0, is_dir=True)
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
        self._journal_op(
            "put",
            dest_path,
            base_rev=0,
            blob_id=blob_id,
            size=int(new_row["size"]),
            encrypted=int(new_row["encrypted"]),
            sensitivity=str(new_row["sensitivity"]),
        )
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
        base_rev = journal_mod.current_rev(idx, logical)
        removed = idx.delete_file(logical, recursive=recursive)
        for blob_id in blobs:
            self.fs.delete_blob(blob_id)
        for row in removed:
            self._store.remove_file(int(row["id"]))
            self._forget_semantic(int(row["id"]))
        if removed:
            self._journal_delete(logical, base_rev=base_rev)
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
        base_rev = journal_mod.current_rev(idx, logical)
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
        if int(new_row["is_dir"]):
            self._journal_op("level", logical, base_rev=base_rev, sensitivity=level)
        else:
            self._journal_op(
                "put",
                logical,
                base_rev=base_rev,
                blob_id=new_row.get("blob_id"),
                size=int(new_row["size"]),
                encrypted=int(new_row["encrypted"]),
                sensitivity=level,
            )
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
        base_rev = journal_mod.current_rev(idx, logical)
        idx.set_tags(logical, tags)
        self._journal_op("tag", logical, base_rev=base_rev, tags=list(tags))
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

    def set_emoji(
        self, path: str, emoji: str | None, *, source: str = SOURCE_UI
    ) -> dict[str, Any]:
        """Set (or clear, with ``None``) the emoji label of a folder or file.

        Returns the updated entry, so a caller can re-render one row without re-listing the
        folder. The label is metadata on the path (plaintext, synced, visible while locked),
        which is why it needs no content access — but it still requires an unlocked, writable
        session: an unlocked vault is the only state in which the index may be changed.
        """
        from .emoji import normalize as normalize_emoji  # noqa: PLC0415 - tiny helper

        logical = normalize_vault_path(path)
        label = normalize_emoji(emoji)
        self._require_unlocked()
        self._require_writable("set_emoji")
        idx = self._require_index()
        base_rev = journal_mod.current_rev(idx, logical)
        idx.set_emoji(logical, label)
        self._journal_op("emoji", logical, base_rev=base_rev, emoji=label)
        self.flush()
        self._log(source=source, tool="set_emoji", target_path=logical, outcome="allow")
        row = idx.require_file(logical)
        self._emit_activity(
            kind="write",
            tool="set_emoji",
            path=logical,
            sensitivity=str(row["sensitivity"]),
            outcome="allow",
        )
        return row

    # ------------------------------------------------------------------ learning
    def _learning_op(self, logical: str, file_id: int) -> None:
        """Record a learning mark for the peers (never moves the entry's revision).

        A study schedule is personal bookkeeping: it must not turn a note edit on another device
        into a conflict, so these ops are metadata that apply last-writer-wins.
        """
        record = self._require_index().learning_record(file_id)
        if record is None:
            self._journal_op("learning", logical, bump=False, removed=True)
            return
        self._journal_op(
            "learning",
            logical,
            bump=False,
            stage=int(record["stage"]),
            due=int(record["due"]),
            started=int(record["started"]),
            seen=int(record["seen"]),
        )

    def learning_list(self, *, now: int | None = None) -> dict[str, Any]:
        """Return the cards due now (today and any missed) plus the ones still ahead.

        Metadata only — names, levels and the schedule — so it answers while locked, like a
        folder listing. A card's content is read by whichever client shows it.
        """
        moment = now_ms() if now is None else int(now)
        entries = [
            self._learning_entry(row, moment) for row in self._require_index().learning_records()
        ]
        due = [entry for entry in entries if entry["due"] and entry["due"] <= moment]
        upcoming = [entry for entry in entries if entry["due"] and entry["due"] > moment]
        return {
            "now": moment,
            "due": due,
            "upcoming": upcoming,
            "count": len(due),
            "intervals": list(learning.INTERVALS_DAYS),
        }

    def _learning_entry(self, row: dict[str, Any], now: int) -> dict[str, Any]:
        """Shape one joined index row into the card both clients render."""
        logical = str(row["logical_path"])
        stage = int(row["stage"])
        due = int(row["due"])
        return {
            "name": "/" if logical == "/" else logical.rsplit("/", 1)[-1],
            "path": "/" + logical.lstrip("/"),
            "sensitivity": row["sensitivity"],
            "emoji": row.get("emoji"),
            "stage": stage,
            "total": learning.TOTAL_STAGES,
            "due": due,
            "started": int(row["started"]),
            "seen": int(row["seen"]),
            "completed": learning.is_complete(stage) or not due,
            "overdue_days": learning.days_overdue(due, now),
        }

    def _learning_target(self, path: str, tool: str) -> tuple[str, dict[str, Any]]:
        """Resolve a note for a learning action: unlocked, writable, and not a folder."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        self._require_writable(tool)
        row = self._require_index().require_file(logical)
        if int(row["is_dir"]):
            raise BadRequest("is_directory", details={"path": logical})
        return logical, row

    def learning_start(self, path: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Put a note into its learning cycle (a no-op when it is already there)."""
        logical, row = self._learning_target(path, "learning_start")
        idx = self._require_index()
        moment = now_ms()
        file_id = int(row["id"])
        if idx.learning_get(file_id) is None:
            stage, due = learning.started(moment)
            idx.learning_set(file_id, stage=stage, due=due, started=moment, seen=0)
            self._learning_op(logical, file_id)
            self.flush()
            self._log(source=source, tool="learning_start", target_path=logical, outcome="allow")
            self._emit_activity(
                kind="write",
                tool="learning_start",
                path=logical,
                sensitivity=str(row["sensitivity"]),
                outcome="allow",
            )
        record = idx.learning_record(file_id) or {}
        return self._learning_entry(record, moment)

    def learning_seen(self, path: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Record one review: the card moves to the next interval; the sixth ends the cycle.

        A finished cycle leaves the learning table, so the note stops coming back on its own —
        re-entering is a deliberate start (or a reset before the cycle ends).
        """
        logical, row = self._learning_target(path, "learning_seen")
        idx = self._require_index()
        file_id = int(row["id"])
        current = idx.learning_get(file_id)
        if current is None:
            raise NotFound("not_in_learning", details={"path": logical})
        moment = now_ms()
        stage, due = learning.reviewed(moment, int(current["stage"]))
        self._log(source=source, tool="learning_seen", target_path=logical, outcome="allow")
        self._emit_activity(
            kind="write",
            tool="learning_seen",
            path=logical,
            sensitivity=str(row["sensitivity"]),
            outcome="allow",
        )
        if not due:
            idx.learning_delete(file_id)
            self._learning_op(logical, file_id)
            self.flush()
            return {
                "path": "/" + logical.lstrip("/"),
                "stage": stage,
                "total": learning.TOTAL_STAGES,
                "due": 0,
                "completed": True,
            }
        idx.learning_set(
            file_id, stage=stage, due=due, started=int(current["started"]), seen=moment
        )
        self._learning_op(logical, file_id)
        self.flush()
        record = idx.learning_record(file_id) or {}
        return self._learning_entry(record, moment)

    def learning_reset(self, path: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Restart a card's cycle from the first interval (tomorrow)."""
        logical, row = self._learning_target(path, "learning_reset")
        idx = self._require_index()
        file_id = int(row["id"])
        if idx.learning_get(file_id) is None:
            raise NotFound("not_in_learning", details={"path": logical})
        moment = now_ms()
        stage, due = learning.started(moment)
        idx.learning_set(file_id, stage=stage, due=due, started=moment, seen=0)
        self._learning_op(logical, file_id)
        self.flush()
        self._log(source=source, tool="learning_reset", target_path=logical, outcome="allow")
        self._emit_activity(
            kind="write",
            tool="learning_reset",
            path=logical,
            sensitivity=str(row["sensitivity"]),
            outcome="allow",
        )
        record = idx.learning_record(file_id) or {}
        return self._learning_entry(record, moment)

    def learning_stop(self, path: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Take a note out of learning (a no-op when it is not in it)."""
        logical, row = self._learning_target(path, "learning_stop")
        idx = self._require_index()
        file_id = int(row["id"])
        removed = idx.learning_get(file_id) is not None
        if removed:
            idx.learning_delete(file_id)
            self._learning_op(logical, file_id)
            self.flush()
            self._log(source=source, tool="learning_stop", target_path=logical, outcome="allow")
            self._emit_activity(
                kind="write",
                tool="learning_stop",
                path=logical,
                sensitivity=str(row["sensitivity"]),
                outcome="allow",
            )
        return {"path": "/" + logical.lstrip("/"), "removed": removed}

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
        self._journal_op(
            "note",
            logical,
            base_rev=journal_mod.current_rev(self._require_index(), logical),
            scope="folder",
            **self._seal_note(text),
        )
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
        base_rev = journal_mod.current_rev(self._require_index(), logical)
        self._store.set_file_note(file_id, text)
        self._journal_op("note", logical, base_rev=base_rev, scope="file", **self._seal_note(text))
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
                        "emoji": child.get("emoji"),
                        "entries": [],
                    }
                )
        folder_row = idx.get_file(logical) or {}
        return {
            "name": "/" if logical == "/" else logical.rsplit("/", 1)[-1],
            "path": "/" + logical.lstrip("/"),
            "is_dir": True,
            "note": self._store.get_folder_note(logical),
            "emoji": folder_row.get("emoji"),
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
            "emoji": row.get("emoji"),
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
        only_secret: bool = False,
        fields: bool = False,
        source: str = SOURCE_UI,
    ) -> list[dict[str, Any]]:
        """Search filenames (all levels, names only), optionally under ``path_prefix``.

        ``fields`` also matches the *metadata fields* of credential entries (title, site,
        category, url, username) — never a password, which the credential index does not hold.
        That is a UI affordance: the field scan decrypts every credential body once (metadata
        only, no audit rows), so agent sources are refused it by the service layer.
        """
        results = search_mod.search_filenames(
            self, query, limit=limit, path_prefix=path_prefix, only_secret=only_secret
        )
        if fields:
            results = self._merge_credential_fields(query, results, int(limit))
        self._emit_activity(
            kind="search", tool="search_filenames", path=None, sensitivity=None,
            outcome="allow", query=query,
        )
        self._log(source=source, tool="search_filenames", outcome="allow")
        return results

    def _merge_credential_fields(
        self, query: str, results: list[dict[str, Any]], limit: int
    ) -> list[dict[str, Any]]:
        """Append the credential entries whose fields match ``query`` (deduplicated)."""
        try:
            with credentials.quiet_scan(self):
                hits = self.credential_index().search(query, limit=limit * 2)
        except Exception:  # noqa: BLE001 - a field scan must never break a name search
            return results
        seen = {str(item.get("logical_path") or "") for item in results}
        merged = list(results)
        for hit in hits:
            logical = str(hit["path"]).lstrip("/")
            if logical in seen:
                continue
            try:
                row = self._require_index().require_file(logical)
            except Exception:  # noqa: BLE001 - deleted between the scan and the merge
                continue
            seen.add(logical)
            merged.append(search_mod.field_result(row, hit["fields"]))
        merged.sort(key=lambda item: str(item.get("logical_path", "")))
        return merged[: max(1, limit)]

    def credential_index(self) -> Any:
        """The session's one credential index, built on first use and refreshed when stale."""
        if self._credentials is None:
            self._credentials = credentials.CredentialIndex(self)
        return self._credentials

    # ------------------------------------------------------------------ journal
    @property
    def client_id(self) -> str:
        """This machine's id for this vault (machine-local, never inside the vault)."""
        if self._journal_client is None:
            try:
                vault_id = str(self._require_meta().vault_id or "")
            except Exception:  # noqa: BLE001 - a vault without metadata still gets an id
                vault_id = ""
            self._journal_client = journal_mod.client_id(vault_id)
        return self._journal_client

    def _journal_op(
        self, kind: str, path: str, *, base_rev: int | None = None, bump: bool = True, **payload: Any
    ) -> None:
        """Record the op for a mutation that just happened here.

        Called *after* the local change: if recording fails, the change is already in the index and
        raising would tell the caller the write failed. A lost op cannot lose data silently either —
        the path's revision still moves, so a peer edit of the same path arrives as a conflict and
        the user is asked (see journal.apply_ops).
        """
        if self._applying_remote:
            return
        try:
            idx = self._require_index()
            base = journal_mod.current_rev(idx, path) if base_rev is None else int(base_rev)
            op = journal_mod.record(
                idx, kind, path, client=self.client_id, payload=payload or None, base_rev=base
            )
            if bump:
                self._set_rev(path, int(op["rev"]))
        except Exception:  # noqa: BLE001 - never turn a successful write into a failure
            LOG.warning("journal: could not record %s for %s", kind, path)

    def _journal_delete(self, path: str, *, base_rev: int) -> None:
        """Record a deletion (the row is already gone, so the revision becomes a tombstone)."""
        if self._applying_remote:
            return
        try:
            idx = self._require_index()
            op = journal_mod.record(
                idx, "delete", path, client=self.client_id, base_rev=int(base_rev)
            )
            idx.conn.execute(
                "INSERT INTO tombstones(path, rev, writer, at) VALUES(?,?,?,?) "
                "ON CONFLICT(path) DO UPDATE SET rev=excluded.rev, writer=excluded.writer, "
                "at=excluded.at",
                (normalize_vault_path(path), int(op["rev"]), self.client_id, now_ms()),
            )
            idx.conn.commit()
        except Exception:  # noqa: BLE001
            LOG.warning("journal: could not record the deletion of %s", path)

    def _set_rev(self, path: str, rev: int) -> None:
        """Move a path's local revision to what its op claims (so the next edit bases on it)."""
        idx = self._require_index()
        idx.conn.execute(
            "UPDATE files SET rev=?, last_writer=? WHERE logical_path=? COLLATE NOCASE",
            (int(rev), self.client_id, normalize_vault_path(path)),
        )
        idx.conn.commit()

    # ---------------------------------------------------- sealed note text in ops
    def _seal_note(self, text: str) -> dict[str, str]:
        """Seal note text for an op: the journal sits in plaintext metadata, so text is ciphertext."""
        key = self._master_key
        if key is None:
            raise VaultLocked("vault_locked")
        token = secrets.token_hex(16)
        blob = encrypt_blob(bytes(key), token, text.encode("utf-8"), sensitivity="normal")
        return {"id": token, "enc": base64.b64encode(blob).decode("ascii")}

    def _open_note(self, payload: dict[str, Any]) -> str:
        """Open a sealed note payload from an op (peer or own)."""
        key = self._master_key
        if key is None:
            raise VaultLocked("vault_locked")
        token = str(payload.get("id") or "")
        raw = base64.b64decode(str(payload.get("enc") or ""))
        return decrypt_blob(bytes(key), token, raw, sensitivity="normal").decode("utf-8")

    def apply_journal_op(self, op: dict[str, Any]) -> str | None:
        """Apply the op kinds that live in the encrypted store (notes and learning marks).

        Returns ``"applied"``/``"conflict"`` when it handled the op, ``None`` to let the index layer
        take it. A note edit is treated like any other change to that entry (it has a revision and can
        conflict); a learning mark is personal study bookkeeping, so it never conflicts.
        """
        kind = str(op.get("kind") or "")
        if kind not in ("note", "learning"):
            return None
        index = self._require_index()
        path = normalize_vault_path(str(op.get("path") or ""))
        row = index.get_file(path)
        if row is None:
            return "applied"  # the entry is gone here; nothing to annotate
        payload = dict(op.get("payload") or {})
        if kind == "learning":
            file_id = int(row["id"])
            if payload.get("removed"):
                index.learning_delete(file_id)
            else:
                index.learning_set(
                    file_id,
                    stage=int(payload.get("stage", 0)),
                    due=int(payload.get("due", 0)),
                    started=int(payload.get("started", 0)),
                    seen=int(payload.get("seen", 0)),
                )
            self.flush()
            return "applied"
        current = journal_mod.current_rev(index, path)
        if not op.get("resolution_of") and int(op.get("base_rev", 0)) != current:
            journal_mod.conflict_record(index, op, current)
            index.conn.commit()
            return "conflict"
        text = self._open_note(payload)
        if str(payload.get("scope")) == "file":
            self._store.set_file_note(int(row["id"]), text)
        else:
            self._store.set_folder_note(path, text)
        self.flush()
        self._set_rev(path, int(op.get("rev", current + 1)))
        return "applied"

    def pending_ops(self) -> int:
        """How many local operations are still waiting to be published."""
        try:
            row = self._require_index().conn.execute(
                "SELECT COUNT(*) AS n FROM journal_out WHERE published=0"
            ).fetchone()
            return int(row["n"] or 0) if row is not None else 0
        except Exception:  # noqa: BLE001 - a locked/absent index has nothing pending
            return 0

    # ------------------------------------------------------- multi-client sync
    #: ``legacy`` = the whole-folder mirror with the single-writer lock; ``journal`` = the op log.
    SYNC_MODES = ("legacy", "journal")

    def sync_mode(self) -> str:
        """Return the vault's sync mode (``legacy`` until it is migrated)."""
        try:
            value = str((self._require_meta().settings.get("sync") or {}).get("mode") or "legacy")
        except Exception:  # noqa: BLE001 - a brand-new vault has no settings yet
            return "legacy"
        return value if value in self.SYNC_MODES else "legacy"

    def set_sync_mode(self, mode: str) -> None:
        """Persist ``sync.mode`` in the vault settings (travels with the vault)."""
        if mode not in self.SYNC_MODES:
            raise BadRequest("unknown_sync_mode", details={"mode": mode})
        meta = self._require_meta()
        settings = dict(meta.settings.get("sync") or {})
        settings["mode"] = mode
        meta.settings["sync"] = settings
        meta.save()

    def migrate_to_journal(self) -> dict[str, Any]:
        """Adopt the operation log: seed one op per existing entry, note and learning card.

        Idempotent — a second run changes nothing. The old mirror objects stay in the bucket, so a
        legacy client keeps working while this one switches (docs/SYNC.md §11).
        """
        self._require_unlocked()
        self._require_writable("migrate_to_journal")
        index = self._require_index()
        if index.kv_get("sync.journal_seeded") == "1":
            self.set_sync_mode("journal")
            return {"already": True, "files": 0, "notes": 0, "learning": 0}

        files = 0
        for row in list(index.walk("/")):
            path = str(row["logical_path"])
            if int(row.get("is_dir", 0)):
                self._journal_op("put", path, base_rev=0, is_dir=True)
            elif row.get("blob_id"):
                self._journal_op(
                    "put",
                    path,
                    base_rev=0,
                    blob_id=str(row["blob_id"]),
                    size=int(row.get("size") or 0),
                    encrypted=int(row.get("encrypted") or 1),
                    sensitivity=str(row.get("sensitivity") or "normal"),
                    mtime=int(row.get("mtime") or 0),
                )
            files += 1

        notes = 0
        for note in self._store.all_folder_notes():
            folder = str(note.get("folder_path") or "")
            text = str(note.get("note_text") or "")
            if not folder:
                continue
            self._journal_op(
                "note",
                folder,
                base_rev=journal_mod.current_rev(index, folder),
                scope="folder",
                **self._seal_note(text),
            )
            notes += 1
        rows_with_notes = [row for row in index.walk("/") if not int(row.get("is_dir", 0))]
        for file_id, text in self._store.get_file_notes(
            [int(row["id"]) for row in rows_with_notes]
        ).items():
            row = index.get_file_by_id(file_id)
            if row is None:
                continue
            self._journal_op(
                "note",
                str(row["logical_path"]),
                base_rev=journal_mod.current_rev(index, str(row["logical_path"])),
                scope="file",
                **self._seal_note(str(text)),
            )
            notes += 1

        learning = 0
        for record in index.learning_records():
            # learning_records() returns the file row joined with its schedule (``id`` is the file).
            self._journal_op(
                "learning",
                str(record["logical_path"]),
                bump=False,
                stage=int(record.get("stage") or 0),
                due=int(record.get("due") or 0),
                started=int(record.get("started") or 0),
                seen=int(record.get("seen") or 0),
            )
            learning += 1

        index.kv_set("sync.journal_seeded", "1")
        self.set_sync_mode("journal")
        self.flush()
        self._log(source=SOURCE_UI, tool="migrate_to_journal", outcome="allow")
        return {
            "already": False,
            "files": files,
            "notes": notes,
            "learning": learning,
            "pending": self.pending_ops(),
        }

    def sync_journal(self, *, client: Any | None = None, max_ops: int | None = None) -> dict[str, Any]:
        """Publish this client's ops and apply every peer's, without a write lock.

        ``max_ops`` publishes at most that many and skips the pull: a caller with a long first push
        (thousands of ops) drives it in slices so its own event loop is never held for minutes.

        Raises:
            VaultLocked: when the session is locked.
            BadRequest: when S3 is not configured.
        """
        self._require_unlocked()
        if self.sync_mode() != "journal":
            raise BadRequest("sync_mode_legacy")
        from .s3 import S3Client, S3Config  # noqa: PLC0415 - keep the core import graph light

        config = S3Config.from_session(self)
        if not config.configured:
            raise BadRequest("sync_not_configured")
        s3 = client if client is not None else S3Client(config)
        transport = sync_ops.OpsTransport(
            s3,
            prefix=config.normalized_prefix(),
            vault_id=str(self._require_meta().vault_id or ""),
            client_id=self.client_id,
            blob_path=lambda blob_id: self.fs.blob_path(blob_id),
            handler=self.apply_journal_op,
            log=LOG.debug,
        )
        index = self._require_index()
        pushed = transport.push(index, max_ops=max_ops)
        pending = self.pending_ops()
        if max_ops is not None and pending:
            # Still sending: the peer side waits for a call that finds nothing left to publish.
            self.flush()
            self._log(source=SOURCE_UI, tool="sync_journal", outcome="allow")
            return {
                "pushed": int(pushed["pushed"]),
                "push_failed": int(pushed["failed"]),
                "applied": 0,
                "duplicates": 0,
                "gaps": [],
                "conflicts": len(journal_mod.unresolved(index)),
                "pending": pending,
                "more": True,
            }
        self._applying_remote = True
        try:
            pulled = transport.pull(index, max_ops=max_ops)
        finally:
            self._applying_remote = False
        self.flush()
        more = bool(pulled.get("more"))
        self._log(source=SOURCE_UI, tool="sync_journal", outcome="allow")
        return {
            "pushed": int(pushed["pushed"]),
            "push_failed": int(pushed["failed"]),
            "applied": int(pulled["applied"]),
            "duplicates": int(pulled["duplicates"]),
            "gaps": list(pulled["gaps"]),
            "conflicts": len(journal_mod.unresolved(index)),
            "pending": self.pending_ops(),
            "more": more,
        }

    def publish_reader_snapshot(self, *, client: Any | None = None) -> dict[str, Any]:
        """Publish the metadata a *reading* client mirrors, after a journal sync (best effort).

        Multi-device mode never mirrors ``meta.sqlite``/``secure.store`` — they are projections of
        the op log — but a read-only client (the phone) has no op log to apply. Uploading the current
        index next to the blobs is what lets it show the vault as it is. Nothing here reads them
        back, and an unchanged file is skipped by its ETag.
        """
        from .s3 import S3Client, S3Config, md5_hex  # noqa: PLC0415 - keep the core import graph light
        from .sync import INDEX_FILENAME  # noqa: PLC0415 - the filename the legacy mirror uses

        config = S3Config.from_session(self)
        if not config.configured:
            return {"uploaded": []}
        s3 = client if client is not None else S3Client(config)
        prefix = config.normalized_prefix()
        home = Path(self.home)
        try:
            # Fold the WAL back so ``meta.sqlite`` is self-contained when read from the bucket.
            self._require_index().checkpoint()
        except Exception:  # noqa: BLE001 - a checkpoint failure only makes the copy older
            LOG.warning("meta.sqlite checkpoint before the snapshot failed", exc_info=True)
        try:
            remote = {str(entry.get("key")): entry for entry in s3.list(prefix)}
        except Exception:  # noqa: BLE001 - without a listing every file is simply re-sent
            remote = {}
        uploaded: list[str] = []
        for name in (INDEX_FILENAME, STORE_FILENAME, META_FILENAME):
            path = home / name
            try:
                data = path.read_bytes()
            except OSError:
                continue
            entry = remote.get(prefix + name) or {}
            if entry.get("etag") and str(entry["etag"]) == md5_hex(data):
                continue  # the reader already has this exact file
            s3.put(prefix + name, data)
            uploaded.append(name)
        return {"uploaded": uploaded}

    def verify_blobs(self, *, progress: dict[str, Any] | None = None) -> dict[str, Any]:
        """Check that every blob decrypts cleanly, reporting into ``progress`` as it goes.

        Slow by nature — it decrypts the whole vault — so the desktop runs it off the GUI thread and
        this loop keeps ``progress["done"]``/``["total"]`` up to date for the indicator.

        shortcut: verified against a snapshot of the index, so a write made from another client
        mid-run can show up as a false failure; upgrade when several clients write while the user
        verifies.
        """
        self._require_unlocked()
        rows = [row for row in self._require_index().walk("/") if row.get("blob_id")]
        if progress is not None:
            progress.update({"done": 0, "total": len(rows), "finished": False})
        bad: list[str] = []
        for index, row in enumerate(rows, start=1):
            if not self.fs.verify_blob(row):
                bad.append("/" + str(row["logical_path"]).lstrip("/"))
            if progress is not None:
                progress["done"] = index
        if progress is not None:
            progress["finished"] = True
        return {"checked": len(rows), "bad": bad}

    def conflicts(self) -> list[dict[str, Any]]:
        """Every conflict still waiting for the user's answer."""
        return journal_mod.unresolved(self._require_index())

    def _answer_note(self, theirs: dict[str, Any], choice: str) -> dict[str, Any]:
        """Answer a conflict about a *note*: mine, theirs, or both texts kept side by side."""
        index = self._require_index()
        path = normalize_vault_path(str(theirs.get("path") or ""))
        payload = dict(theirs.get("payload") or {})
        their_text = self._open_note(payload)
        scope = str(payload.get("scope") or "folder")
        row = index.get_file(path)
        mine_text = ""
        if row is not None:
            mine_text = (
                self._store.get_file_note(int(row["id"]))
                if scope == "file"
                else self._store.get_folder_note(path)
            ) or ""
        if choice == "mine":
            text = mine_text
        elif choice == "both":
            # A note is one field: keeping both means keeping both texts, mine first.
            text = (mine_text + "\n\n" + their_text).strip()
        else:
            text = their_text
        current = journal_mod.current_rev(index, path)
        if row is not None:
            if scope == "file":
                self._store.set_file_note(int(row["id"]), text)
            else:
                self._store.set_folder_note(path, text)
        self.flush()
        self._set_rev(path, current + 1)
        return journal_mod.record(
            index,
            "note",
            path,
            client=self.client_id,
            base_rev=current,
            payload={"scope": scope, **self._seal_note(text)},
            resolution_of=str(theirs.get("op_id") or ""),
        )

    def resolve_conflict(self, conflict_id: int, choice: str) -> dict[str, Any]:
        """Answer one conflict (``mine``/``theirs``/``both``) and queue the decision as an op."""
        self._require_unlocked()
        answer = journal_mod.resolve(
            self._require_index(),
            int(conflict_id),
            choice,
            client=self.client_id,
            handler=self.apply_journal_op,
            answer_builder=self._answer_note,
        )
        self.flush()
        self._log(source=SOURCE_UI, tool="resolve_conflict", outcome="allow")
        return {"resolved": int(conflict_id), "choice": choice, "op": answer.get("op_id")}

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
    #: How long an approved display stays readable (ms). The web UI reads the text right after
    #: the user approves, and a reload or a second look must not ask again.
    SECRET_GRANT_TTL_MS: int = 120_000
    #: How many answered requests stay queryable (the web UI polls the one it is waiting on).
    SECRET_HISTORY: int = 32

    def request_open_secret(
        self,
        path: str,
        *,
        source: str = SOURCE_MCP,
        session: str | None = None,
        origin: str = "",
    ) -> dict[str, Any]:
        """Ask the UI to display a ``secret``/``secretfile``; the caller never gets content.

        ``origin`` names the transport that asked (``"web"`` for the browser). The desktop app
        shows its permission dialog either way; what differs is what an approval does — the
        browser reads the text back into the web UI, while an agent's approval opens the native
        viewer (`VaultApplication._resolve_request`).

        Raises:
            PermissionDenied: for any level other than a secret one, or for a source that may
                not ask (see :meth:`Policy.can_request_open_secret`).
        """
        logical = normalize_vault_path(path)
        self._require_unlocked()
        row = self._require_index().require_file(logical)
        if row["sensitivity"] not in SECRET_LEVELS or not Policy.can_request_open_secret(
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
            "source": source,
            "session": session,
            "origin": origin,
        }
        self._pending[request_id] = request
        if self.on_secret_request is not None:
            try:
                outcome = self.on_secret_request(request)
                if isinstance(outcome, str) and outcome in ("pending", "shown", "denied"):
                    request["status"] = outcome
            except Exception:  # noqa: BLE001 - UI callbacks must not break the agent path
                pass
            if request["status"] != "pending":
                self._remember_request(request)
        self._log(
            source=source, tool="request_open_secret", target_path=logical,
            outcome="allow", session=session,
        )
        return {"request_id": request_id, "status": request["status"]}

    def resolve_open_secret(self, request_id: str, *, approved: bool) -> dict[str, Any]:
        """Resolve a pending secret-open request as ``shown`` or ``denied``.

        An approval also releases that one path for :data:`SECRET_GRANT_TTL_MS`: it is what lets
        the web UI read the text it just asked for, and it is the only way a browser ever gets
        it (`vault.read_secret` is refused without it).
        """
        request = self._pending.pop(request_id, None)
        if request is None:
            raise NotFound("request_not_found", details={"request_id": request_id})
        request["status"] = "shown" if approved else "denied"
        request["resolved_at"] = now_ms()
        if approved:
            self._grant_secret_display(str(request.get("path") or ""))
        self._remember_request(request)
        return request

    def pending_requests(self) -> list[dict[str, Any]]:
        """Return the pending secret-open requests."""
        return list(self._pending.values())

    def secret_request_status(self, request_id: str) -> dict[str, Any]:
        """Return ``pending``/``shown``/``denied`` for one request (``unknown`` otherwise).

        The web UI polls this while it waits for the desktop app's answer. Content never passes
        through it, and it is a quiet call (no access-log row) — a poll every second would
        otherwise bury the log.
        """
        pending = self._pending.get(request_id)
        if pending is not None:
            return {
                "request_id": request_id,
                "status": "pending",
                "path": pending.get("path"),
            }
        resolved = self._resolved.get(request_id)
        if resolved is not None:
            return {
                "request_id": request_id,
                "status": resolved.get("status"),
                "path": resolved.get("path"),
            }
        return {"request_id": request_id, "status": "unknown", "path": None}

    # ------------------------------------------------- secret display approvals
    def _grant_secret_display(self, path: str) -> None:
        """Release one path for the short window after an explicit approval."""
        if not path:
            return
        self._grants[normalize_vault_path(path)] = now_ms() + self.SECRET_GRANT_TTL_MS

    def secret_display_granted(self, path: str) -> bool:
        """Return True while ``path`` may be read on the strength of an approval."""
        logical = normalize_vault_path(path)
        expiry = self._grants.get(logical)
        if expiry is None:
            return False
        if expiry < now_ms():
            self._grants.pop(logical, None)
            return False
        return True

    def _remember_request(self, request: dict[str, Any]) -> None:
        """Keep the most recent answered requests queryable, oldest first."""
        self._resolved[str(request.get("request_id"))] = request
        while len(self._resolved) > self.SECRET_HISTORY:
            self._resolved.pop(next(iter(self._resolved)))

    # ------------------------------------------------------------------------ log
    def access_log(self, **kw: Any) -> list[dict[str, Any]]:
        """Return access-log rows (delegates to the metadata index)."""
        return self._require_index().access_log(**kw)


__all__ = ["VaultSession"]
