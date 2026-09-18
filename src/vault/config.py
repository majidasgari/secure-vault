"""Paths, defaults and the small user-facing configuration file (SPEC/01 §2)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import atomic_write_bytes

DEFAULT_VAULT_HOME = os.environ.get("SECURE_VAULT_HOME") or "/data/Cloud/SecureVault"
"""Default vault home; overridable at process start via ``SECURE_VAULT_HOME``."""

DEFAULT_PLAIN_THRESHOLD = 10 * 1024 * 1024
"""Files strictly larger than this are stored unencrypted (plain) inside the blob dir."""

DEFAULT_AUTO_LOCK_SECONDS = 900
"""Seconds of UI inactivity before auto-lock; ``0`` disables auto-lock."""

DEFAULT_LANGUAGE = "fa"
"""Default UI language."""


def runtime_dir() -> Path:
    """Return the per-user runtime directory, creating it with mode ``0700``.

    Honours ``XDG_RUNTIME_DIR`` and falls back to ``/tmp/secure-vault-<uid>``.
    Decrypted scratch data (store, socket, token, pid) lives here, never in the vault home.
    """
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base:
        path = Path(base) / "secure-vault"
    else:
        path = Path("/tmp") / f"secure-vault-{os.getuid()}"
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # pragma: no cover - best effort on exotic filesystems
        pass
    return path


def user_config_dir() -> Path:
    """Return the per-user configuration directory (not created here)."""
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        return Path(base) / "secure-vault"
    return Path.home() / ".config" / "secure-vault"


def user_data_dir() -> Path:
    """Return the per-user data directory, creating it with mode ``0700``.

    Honours ``XDG_DATA_HOME`` and falls back to ``~/.local/share/secure-vault``. The
    semantic vector cache lives here by default: it is large, machine-local and
    rebuildable, so it must not sit in the synced vault home.
    """
    base = os.environ.get("XDG_DATA_HOME")
    path = (Path(base) if base else Path.home() / ".local" / "share") / "secure-vault"
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # pragma: no cover - best effort on exotic filesystems
        pass
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
    "DEFAULT_VAULT_HOME",
    "DEFAULT_PLAIN_THRESHOLD",
    "DEFAULT_AUTO_LOCK_SECONDS",
    "DEFAULT_LANGUAGE",
    "runtime_dir",
    "user_config_dir",
    "user_data_dir",
    "UserConfig",
    "user_config",
    "AppPaths",
    "app_paths",
]
