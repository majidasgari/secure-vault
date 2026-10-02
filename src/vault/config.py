"""Paths, defaults and the small user-facing configuration file (SPEC/01 §2)."""

from __future__ import annotations

import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import atomic_write_bytes, restrict

WINDOWS = sys.platform == "win32"
"""True on Windows, where the XDG directories do not exist."""


def _windows_dir(variable: str, fallback: str) -> Path:
    """Return ``%<variable>%`` on Windows, falling back to ``~/<fallback>``."""
    value = os.environ.get(variable)
    if value:
        return Path(value)
    return Path.home() / fallback


def _default_vault_home() -> str:
    """Return the platform default vault home (a synced, user-visible folder)."""
    if WINDOWS:
        documents = Path.home() / "Documents"
        base = documents if documents.is_dir() else Path.home()
        return str(base / "SecureVault")
    return "/data/Cloud/SecureVault"


DEFAULT_VAULT_HOME = os.environ.get("SECURE_VAULT_HOME") or _default_vault_home()
"""Default vault home; overridable at process start via ``SECURE_VAULT_HOME``."""

DEFAULT_PLAIN_THRESHOLD = 10 * 1024 * 1024
"""Files strictly larger than this are stored unencrypted (plain) inside the blob dir."""

DEFAULT_AUTO_LOCK_SECONDS = 900
"""Seconds of UI inactivity before auto-lock; ``0`` disables auto-lock."""

DEFAULT_LANGUAGE = "fa"
"""Default UI language."""

SYNC_CONFIG_FILENAME = "s3.json"
"""Machine-local S3 credentials + client id (never synced into the vault home)."""


def runtime_dir() -> Path:
    """Return the per-user runtime directory, creating it with mode ``0700``.

    Honours ``XDG_RUNTIME_DIR``, falls back to ``%LOCALAPPDATA%\\secure-vault\
untime``
    on Windows and to ``/tmp/secure-vault-<uid>`` elsewhere. Decrypted scratch data
    (store, socket, token, pid) lives here, never in the vault home.
    """
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base:
        path = Path(base) / "secure-vault"
    elif WINDOWS:
        path = _windows_dir("LOCALAPPDATA", "AppData/Local") / "secure-vault" / "runtime"
    else:
        path = Path("/tmp") / f"secure-vault-{os.getuid()}"
    path.mkdir(parents=True, exist_ok=True)
    restrict(path, 0o700)
    return path


def user_config_dir() -> Path:
    """Return the per-user configuration directory (not created here)."""
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        return Path(base) / "secure-vault"
    if WINDOWS:
        return _windows_dir("APPDATA", "AppData/Roaming") / "secure-vault"
    return Path.home() / ".config" / "secure-vault"


def user_data_dir() -> Path:
    """Return the per-user data directory, creating it with mode ``0700``.

    Honours ``XDG_DATA_HOME``, falls back to ``%LOCALAPPDATA%\\secure-vault\\data`` on
    Windows and to ``~/.local/share/secure-vault`` elsewhere. The semantic vector cache
    lives here by default: it is large, machine-local and rebuildable, so it must not sit
    in the synced vault home.
    """
    base = os.environ.get("XDG_DATA_HOME")
    if base:
        root = Path(base)
    elif WINDOWS:
        root = _windows_dir("LOCALAPPDATA", "AppData/Local")
    else:
        root = Path.home() / ".local" / "share"
    path = root / "secure-vault"
    path.mkdir(parents=True, exist_ok=True)
    restrict(path, 0o700)
    return path


def user_state_dir() -> Path:
    """Return the per-user state/log directory, creating it with mode ``0700``.

    Honours ``XDG_STATE_HOME``, falls back to ``%LOCALAPPDATA%\\secure-vault\\state`` on
    Windows and to ``~/.local/state/secure-vault`` elsewhere.
    """
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        path = Path(base) / "secure-vault"
    elif WINDOWS:
        path = _windows_dir("LOCALAPPDATA", "AppData/Local") / "secure-vault" / "state"
    else:
        path = Path.home() / ".local" / "state" / "secure-vault"
    path.mkdir(parents=True, exist_ok=True)
    restrict(path, 0o700)
    return path


@dataclass
class UserConfig:
    """The contents of ``ui.json`` with forward-compatible unknown-key preservation."""

    path: Path
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def language(self) -> str:
        """Return the configured UI language (defaults to ``DEFAULT_LANGUAGE``)."""
        value = self.data.get("language")
        return value if isinstance(value, str) and value else DEFAULT_LANGUAGE

    @language.setter
    def language(self, value: str) -> None:
        """Set the UI language (call :meth:`save` to persist)."""
        self.data["language"] = value

    @property
    def window(self) -> dict[str, Any]:
        """Return the persisted window geometry/state mapping."""
        value = self.data.get("window")
        return value if isinstance(value, dict) else {}

    @window.setter
    def window(self, value: dict[str, Any]) -> None:
        """Replace the persisted window geometry/state mapping."""
        self.data["window"] = value

    @property
    def last_folder(self) -> str | None:
        """Return the last opened folder logical path, if any."""
        value = self.data.get("last_folder")
        return value if isinstance(value, str) else None

    @last_folder.setter
    def last_folder(self, value: str | None) -> None:
        """Set the last opened folder logical path."""
        self.data["last_folder"] = value

    def save(self) -> None:
        """Atomically persist the configuration to ``ui.json``."""
        payload = json.dumps(self.data, ensure_ascii=False, indent=2).encode("utf-8")
        atomic_write_bytes(self.path, payload)


def user_config() -> UserConfig:
    """Load ``ui.json`` from the user config dir, tolerating missing/corrupt files.

    Unknown keys are preserved on round-trip. The file is not created until :meth:`save`.
    """
    path = user_config_dir() / "ui.json"
    data: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError):
            data = {}
    data.setdefault("language", DEFAULT_LANGUAGE)
    data.setdefault("window", {})
    data.setdefault("last_folder", None)
    return UserConfig(path=path, data=data)


def sync_config_path() -> Path:
    """Return the machine-local S3 credentials file (``<config>/s3.json``)."""
    return user_config_dir() / SYNC_CONFIG_FILENAME


def load_sync_config() -> dict[str, Any]:
    """Load the machine-local S3 credentials, tolerating a missing/corrupt file.

    The file is **never** written into the vault home: it holds the secret access key,
    which must not be swept up by the cloud client that syncs the vault.
    """
    path = sync_config_path()
    data: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError):
            data = {}
    return data


def save_sync_config(data: dict[str, Any]) -> None:
    """Atomically persist the machine-local S3 credentials with mode ``0600``."""
    path = sync_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    atomic_write_bytes(path, payload)
    restrict(path, 0o600)


def sync_client_id() -> str:
    """Return this machine's stable client id, creating it on first use.

    The id names the S3 lock owner, so it must survive restarts but stay machine-local
    (that is also why it lives in ``s3.json`` next to the credentials, not in the vault).
    """
    data = load_sync_config()
    identifier = data.get("client_id")
    if isinstance(identifier, str) and identifier.strip():
        return identifier.strip()
    identifier = uuid.uuid4().hex
    data["client_id"] = identifier
    save_sync_config(data)
    return identifier


@dataclass(frozen=True)
class AppPaths:
    """Filesystem locations of the repository's static assets."""

    repo_root: Path
    assets_dir: Path
    i18n_dir: Path


def app_paths() -> AppPaths:
    """Return the repo root and its ``assets``/``i18n`` directories."""
    repo_root = Path(__file__).resolve().parents[2]
    return AppPaths(
        repo_root=repo_root,
        assets_dir=repo_root / "assets",
        i18n_dir=repo_root / "i18n",
    )


__all__ = [
    "WINDOWS",
    "DEFAULT_VAULT_HOME",
    "DEFAULT_PLAIN_THRESHOLD",
    "DEFAULT_AUTO_LOCK_SECONDS",
    "DEFAULT_LANGUAGE",
    "SYNC_CONFIG_FILENAME",
    "runtime_dir",
    "user_config_dir",
    "user_data_dir",
    "user_state_dir",
    "UserConfig",
    "user_config",
    "sync_config_path",
    "load_sync_config",
    "save_sync_config",
    "sync_client_id",
    "AppPaths",
    "app_paths",
]
