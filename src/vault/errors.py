"""Typed errors for Secure Vault.

Every error carries a stable ``code`` so the API/MCP layers can map it to a response
verbatim. New codes must never be invented outside SPEC/00 §6.
"""

from __future__ import annotations

from typing import Any


class VaultError(Exception):
    """Base class for every Secure Vault error.

    Attributes:
        code: stable machine-readable error code.
        message: human-readable message (English, never contains secrets).
        details: optional structured context for the caller.
    """

    code: str = "ERROR"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        """Create an error with a message and optional structured details."""
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details if details is not None else {}

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-ready representation ``{"code", "message", "details"}``."""
        return {"code": self.code, "message": self.message, "details": self.details}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}({self.message!r}, code={self.code!r})"


class VaultLocked(VaultError):
    """The vault is locked and the requested operation needs the master key."""

    code = "VAULT_LOCKED"


class VaultNotRunning(VaultError):
    """No vault daemon is reachable (socket missing / connection refused)."""

    code = "VAULT_NOT_RUNNING"


class PermissionDenied(VaultError):
    """The caller is not allowed to perform the requested operation."""

    code = "PERMISSION_DENIED"


class DowngradeForbidden(VaultError):
    """An attempt to lower a sensitivity level that the policy forbids."""

    code = "SENSITIVITY_DOWNGRADE_FORBIDDEN"


class NotFound(VaultError):
    """The requested path or object does not exist."""

    code = "NOT_FOUND"


class AlreadyExists(VaultError):
    """The target path or object already exists."""

    code = "ALREADY_EXISTS"


class InvalidPath(VaultError):
    """A logical path is malformed or escapes the vault root."""

    code = "INVALID_PATH"


class TamperDetected(VaultError):
    """Ciphertext failed authentication, the header is malformed, or input is truncated."""

    code = "TAMPER_DETECTED"


class BadRequest(VaultError):
    """The request is malformed or violates a precondition."""

    code = "BAD_REQUEST"


class Unauthorized(VaultError):
    """Authentication failed (wrong password or bad token)."""

    code = "UNAUTHORIZED"


class ProviderUnavailable(VaultError):
    """An optional provider (e.g. semantic embeddings) is not installed or disabled."""

    code = "PROVIDER_UNAVAILABLE"


__all__ = [
    "VaultError",
    "VaultLocked",
    "VaultNotRunning",
    "PermissionDenied",
    "DowngradeForbidden",
    "NotFound",
    "AlreadyExists",
    "InvalidPath",
    "TamperDetected",
    "BadRequest",
    "Unauthorized",
    "ProviderUnavailable",
]
