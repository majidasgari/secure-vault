"""The plaintext ``.vault-meta.json`` descriptor (SPEC/01 §5).

Only non-secret material lives here: the vault id, KDF parameters and salt, and the
password-verification canary. No file content is ever written to this file.
"""

from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path
from typing import Any

from ..config import DEFAULT_AUTO_LOCK_SECONDS, DEFAULT_PLAIN_THRESHOLD
from ..errors import BadRequest, NotFound
from ..util import atomic_write_bytes, now_ms, wipe
from .crypto import (
    KdfParams,
    check_canary,
    derive_master_key,
    make_canary,
    new_kdf_params,
)

SCHEMA_VERSION = 1
META_FILENAME = ".vault-meta.json"

_DEFAULT_IMPORT_MIRROR = "/data/Cloud/Documents/Notes/joplin-mirror"
#: Public alias: the Joplin mirror root used when the settings carry no explicit path.
DEFAULT_IMPORT_MIRROR = _DEFAULT_IMPORT_MIRROR


def default_settings() -> dict[str, Any]:
    """Return a fresh copy of the default vault settings block."""
    return {
        "plain_threshold_bytes": DEFAULT_PLAIN_THRESHOLD,
        "auto_lock_seconds": DEFAULT_AUTO_LOCK_SECONDS,
        "default_sensitivity": "normal",
        "semantic": {
            "enabled": False,
            "model": "all-MiniLM-L6-v2",
            "provider": "local",
        },
        "import_joplin": {
            "mirror_root": _DEFAULT_IMPORT_MIRROR,
            "sensitive_globs": [],
        },
    }


class VaultMeta:
    """In-memory view of ``.vault-meta.json`` with atomic persistence."""

    def __init__(self, path: Path, data: dict[str, Any]) -> None:
        """Wrap ``data`` and bind it to the on-disk ``path``."""
        self.path = Path(path)
        self.data = data

    @classmethod
    def create(cls, path: Path, password: str) -> "VaultMeta":
        """Create and persist a new metadata file for a new vault."""
        params = new_kdf_params()
        master_key = derive_master_key(password, params)
        try:
            canary = make_canary(master_key)
        finally:
            wipe(master_key)
        data: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "vault_id": uuid.uuid4().hex,
            "created_at": now_ms(),
            "kdf": {
                "algo": params.algo,
                "salt_b64": base64.b64encode(params.salt).decode("ascii"),
                "time_cost": params.time_cost,
                "memory_kib": params.memory_kib,
                "parallelism": params.parallelism,
                "iterations": params.iterations,
            },
            "canary_b64": base64.b64encode(canary).decode("ascii"),
            "settings": default_settings(),
        }
        meta = cls(Path(path), data)
        meta.save()
        return meta

    @classmethod
    def load(cls, path: Path) -> "VaultMeta":
        """Load and validate an existing metadata file.

        Raises:
            NotFound: if the file is missing or not valid JSON/mapping.
            BadRequest: if the schema version is newer than this build supports.
        """
        path = Path(path)
        if not path.exists():
            raise NotFound("vault_not_initialised", details={"path": str(path)})
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise NotFound(
                "vault_not_initialised", details={"path": str(path), "reason": str(exc)}
            ) from exc
        if not isinstance(data, dict):
            raise NotFound("vault_not_initialised", details={"path": str(path)})
        version = data.get("schema_version")
        if not isinstance(version, int):
            raise NotFound("vault_not_initialised", details={"path": str(path)})
        if version > SCHEMA_VERSION:
            raise BadRequest(
                "schema_too_new",
                details={"found": version, "supported": SCHEMA_VERSION},
            )
        return cls(path, data)

    def save(self) -> None:
        """Atomically write the metadata back to disk."""
        payload = json.dumps(self.data, ensure_ascii=False, indent=2).encode("utf-8")
        atomic_write_bytes(self.path, payload)

    def kdf_params(self) -> KdfParams:
        """Return the KDF parameters stored in the file."""
        kdf = self.data["kdf"]
        return KdfParams(
            algo=kdf["algo"],
            salt=base64.b64decode(kdf["salt_b64"]),
            time_cost=int(kdf.get("time_cost", 0)),
            memory_kib=int(kdf.get("memory_kib", 0)),
            parallelism=int(kdf.get("parallelism", 0)),
            iterations=int(kdf.get("iterations", 0)),
        )

    @property
    def settings(self) -> dict[str, Any]:
        """The mutable settings mapping (call :meth:`save` to persist changes)."""
        settings = self.data.get("settings")
        if not isinstance(settings, dict):
            settings = default_settings()
            self.data["settings"] = settings
        return settings

    @property
    def vault_id(self) -> str:
        """The stable vault identifier."""
        return str(self.data.get("vault_id", ""))

    def verify_password(self, password: str) -> bool:
        """Return True iff ``password`` reproduces the canary."""
        canary = base64.b64decode(self.data.get("canary_b64", ""))
        master_key = derive_master_key(password, self.kdf_params())
        try:
            return check_canary(master_key, canary)
        finally:
            wipe(master_key)

    def rekey(self, new_password: str) -> None:
        """Re-encrypt the vault under a new password (not part of phase P1)."""
        raise NotImplementedError(
            "rekey is not implemented in phase P1; it requires re-encrypting every blob"
        )


__all__ = [
    "VaultMeta",
    "SCHEMA_VERSION",
    "META_FILENAME",
    "DEFAULT_IMPORT_MIRROR",
    "default_settings",
]
