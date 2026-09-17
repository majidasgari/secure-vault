"""Blob storage for encrypted/plain file content (SPEC/01 §7)."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Callable

from ..errors import BadRequest, NotFound, VaultLocked
from ..util import atomic_write_bytes
from .crypto import decrypt_blob, encrypt_blob


class VaultFS:
    """Stores file content as AES-256-GCM blobs sharded under ``files/``."""

    def __init__(
        self,
        home: Path,
        index: Any,
        master_key: bytearray | None,
        *,
        plain_threshold: int | Callable[[], int],
    ) -> None:
        """Bind the blob store to a vault home, its index and the (optional) master key.

        ``plain_threshold`` may be an ``int`` or a zero-argument callable returning the
        current effective threshold, so that a settings change takes effect immediately.
        """
        self.home = Path(home)
        self.index = index
        self.master_key = master_key
        self._plain_threshold_source = plain_threshold

    @property
    def plain_threshold(self) -> int:
        """Return the currently effective plain-storage threshold in bytes."""
        src = self._plain_threshold_source
        return int(src() if callable(src) else src)

    def blob_path(self, blob_id: str) -> Path:
        """Return the on-disk path for ``blob_id`` (``files/<aa>/<blob_id>.enc``)."""
        return self.home / "files" / blob_id[:2] / f"{blob_id}.enc"

    def read_bytes(self, row: dict[str, Any]) -> bytes:
        """Decrypt and return the content of a file row.

        Raises:
            VaultLocked: when no master key is available.
            NotFound: when the blob file is missing.
            TamperDetected: when the blob fails authentication.
        """
        if self.master_key is None:
            raise VaultLocked("vault_locked")
        blob_id = row.get("blob_id")
        if not blob_id:
            raise BadRequest("not_a_blob", details={"path": row.get("logical_path")})
        path = self.blob_path(blob_id)
        if not path.exists():
            raise NotFound("blob_missing", details={"blob_id": blob_id})
        blob = path.read_bytes()
        return decrypt_blob(
            self.master_key, blob_id, blob, sensitivity=row["sensitivity"]
        )

    def write_blob(self, data: bytes, *, sensitivity: str) -> tuple[str, int, bool]:
        """Write ``data`` as a new blob and return ``(blob_id, size, encrypted)``.

        Files strictly larger than ``plain_threshold`` are stored plain (``encrypted`` 0).
        """
        if self.master_key is None:
            raise VaultLocked("vault_locked")
        blob_id = uuid.uuid4().hex
        plain = len(data) > self.plain_threshold
        blob = encrypt_blob(
            self.master_key,
            blob_id,
            data,
            sensitivity=sensitivity,
            plain=plain,
        )
        atomic_write_bytes(self.blob_path(blob_id), blob)
        return blob_id, len(data), (0 if plain else 1)

    def delete_blob(self, blob_id: str | None) -> None:
        """Delete a blob file if present; missing files are ignored."""
        if not blob_id:
            return
        try:
            self.blob_path(blob_id).unlink()
        except FileNotFoundError:
            pass

    def gc_orphans(self) -> int:
        """Delete blob files not referenced by any index row; return the count deleted."""
        referenced = {
            row["blob_id"]
            for row in self.index.walk("/")
            if row.get("blob_id")
        }
        if not (self.home / "files").exists():
            return 0
        removed = 0
        for path in sorted((self.home / "files").rglob("*.enc")):
            if path.stem not in referenced:
                try:
                    path.unlink()
                    removed += 1
                except FileNotFoundError:  # pragma: no cover - race
                    pass
        return removed

    def verify_blob(self, row: dict[str, Any]) -> bool:
        """Return True iff the row's blob decrypts cleanly."""
        try:
            self.read_bytes(row)
            return True
        except Exception:  # noqa: BLE001 - verification is best-effort
            return False


__all__ = ["VaultFS"]
