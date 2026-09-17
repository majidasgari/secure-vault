"""The :class:`VaultSession` façade — the single entry point to a vault (SPEC/01 §12).

Owns the metadata, index, blob store, encrypted content store, master key and lock state.
Every content operation is gated by :class:`~vault.core.security.Policy` using the
role-derived source (``ui`` in-process, ``mcp`` over the socket) and refusals are logged
before raising.
"""

from __future__ import annotations

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
    Unauthorized,
    VaultLocked,
)
from ..util import normalize_vault_path, now_ms, wipe
from . import search as search_mod
from . import semantics
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
from .store import SecureStore
from .vaultfs import VaultFS

SecretRequestCallback = Callable[[dict[str, Any]], Any]


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
        self._master_key: bytearray | None = None
        self._last_activity = now_ms()
        self._semantic_provider: semantics.EmbeddingProvider | None = None
        self._pending: dict[str, dict[str, Any]] = {}
        self.on_secret_request: SecretRequestCallback | None = None

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
        self.touch()

    def lock(self) -> None:
        """Flush, wipe the master key and close the store and index."""
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
        """Re-encrypt the content store if it is open."""
        if self._store is not None:
            self._store.flush()

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
        """Append an access-log row, never letting logging failure mask the operation."""
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

    @property
    def semantic_provider(self) -> semantics.EmbeddingProvider | None:
        """The injected/configured embedding provider, if any."""
        return self._semantic_provider

    def set_semantic_provider(self, provider: semantics.EmbeddingProvider | None) -> None:
        """Inject an embedding provider (tests use :class:`~vault.core.semantics.StubProvider`)."""
        self._semantic_provider = provider

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
            },
            "auto_lock_seconds": int(meta.settings.get("auto_lock_seconds", 0) or 0),
            "store": store_stats,
        }

    # ----------------------------------------------------------------------- files
    def list_folder(self, path: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """List the direct children of ``path`` (metadata only; works while locked)."""
        logical = normalize_vault_path(path)
        entries = self._require_index().list_dir(logical)
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
        self._require_unlocked()
        row = self._require_index().require_file(logical)
        if int(row["is_dir"]):
            raise BadRequest("is_directory", details={"path": logical})
        if not Policy.can_read_content(row["sensitivity"], source):
            self._deny("read_file", logical, source, "content_forbidden", session)
        data = self.fs.read_bytes(row)
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
        if existing is not None and existing.get("blob_id") and existing["blob_id"] != blob_id:
            self.fs.delete_blob(existing["blob_id"])
        if desired == "normal":
            self._store.index_text(file_id, data.decode("utf-8", errors="ignore"))
        else:
            self._store.remove_file(file_id)
        self.flush()
        self._log(
            source=source, tool="write_file", target_path=logical, outcome="allow"
        )
        return self._require_index().require_file(logical)

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
        if logical == "/":
            raise AlreadyExists("root_exists")
        idx = self._require_index()
        if idx.get_file(logical) is not None:
            raise AlreadyExists("path_exists", details={"path": logical})
        self._ensure_parents(logical, source)
        idx.upsert_file(logical, is_dir=True, sensitivity="normal", source=source)
        self.flush()
        self._log(source=source, tool="mkdir", target_path=logical, outcome="allow")
        return idx.require_file(logical)

    def move(self, src: str, dst: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Move/rename a file or directory and return the destination row."""
        source_path = normalize_vault_path(src)
        dest_path = normalize_vault_path(dst)
        self._require_unlocked()
        idx = self._require_index()
        idx.require_file(source_path)
        idx.move(source_path, dest_path)
        self.flush()
        self._log(source=source, tool="move", target_path=dest_path, outcome="allow")
        return idx.require_file(dest_path)

    def copy(self, src: str, dst: str, *, source: str = SOURCE_UI) -> dict[str, Any]:
        """Copy a file or directory recursively and return the destination row."""
        source_path = normalize_vault_path(src)
        dest_path = normalize_vault_path(dst)
        self._require_unlocked()
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
        file_id = self._require_index().upsert_file(
            dest_path,
            blob_id=blob_id,
            is_dir=False,
            size=size,
            encrypted=encrypted,
            sensitivity=row["sensitivity"],
            source=source,
        )
        if row["sensitivity"] == "normal":
            self._store.index_text(file_id, data.decode("utf-8", errors="ignore"))

    def delete(
        self, path: str, *, source: str = SOURCE_UI, recursive: bool = False
    ) -> dict[str, Any]:
        """Delete a file (or directory) and its blobs/content rows."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        idx = self._require_index()
        removed = idx.delete_file(logical, recursive=recursive)
        for row in removed:
            if row.get("blob_id"):
                self.fs.delete_blob(row["blob_id"])
            self._store.remove_file(int(row["id"]))
        self.flush()
        self._log(source=source, tool="delete", target_path=logical, outcome="allow")
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
                if blob_id != row["blob_id"]:
                    self.fs.delete_blob(row["blob_id"])
            else:
                idx.set_sensitivity(logical, level)
            new_row = idx.require_file(logical)
            if level == "normal":
                data = self._read_raw(new_row)
                self._store.index_text(int(new_row["id"]), data.decode("utf-8", "ignore"))
            else:
                self._store.remove_file(int(new_row["id"]))
        self.flush()
        self._log(source=source, tool="set_sensitivity", target_path=logical, outcome="allow")
        return new_row

    def set_tags(
        self, path: str, tags: list[str], *, source: str = SOURCE_UI
    ) -> dict[str, Any]:
        """Replace a file's tags and return its row with ``tags`` attached."""
        logical = normalize_vault_path(path)
        self._require_unlocked()
        idx = self._require_index()
        idx.set_tags(logical, tags)
        self.flush()
        self._log(source=source, tool="set_tags", target_path=logical, outcome="allow")
        row = idx.require_file(logical)
        row["tags"] = idx.get_tags(logical)
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
        self._store.set_folder_note(logical, text)
        self.flush()
        self._log(
            source=source, tool="set_folder_note", target_path=logical, outcome="allow"
        )

    # ---------------------------------------------------------------------- search
    def search_filenames(
        self, query: str, *, limit: int = 50, source: str = SOURCE_UI
    ) -> list[dict[str, Any]]:
        """Search filenames (all levels, names only)."""
        results = search_mod.search_filenames(self, query, limit=limit)
        self._log(source=source, tool="search_filenames", outcome="allow")
        return results

    def search_text(
        self, query: str, *, limit: int = 50, source: str = SOURCE_UI
    ) -> list[dict[str, Any]]:
        """Search literal content (``normal`` files only)."""
        self._require_unlocked()
        results = search_mod.search_text(self, query, limit=limit)
        self._log(source=source, tool="search_text", outcome="allow")
        return results

    def search_semantic(
        self, query: str, *, limit: int = 50, source: str = SOURCE_UI
    ) -> list[dict[str, Any]]:
        """Search by embedding similarity (``normal`` files only)."""
        self._require_unlocked()
        results = search_mod.search_semantic(self, query, limit=limit)
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
