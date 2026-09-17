"""Open a vault file in the operating system's default text editor (SPEC/08 §B.7b).

The vault only ever hands a *decrypted copy* to an external program, and only for ``normal``
files:

1. the file is written to ``<runtime_dir>/secure-vault/edit/<hash>.md`` (tmpfs, mode ``0600``);
2. the OS default text editor is started on that path (``$VISUAL``/``$EDITOR`` first, then a
   list of known editors, then ``xdg-open`` on Linux / ``start`` on Windows);
3. a watcher notices when the editor writes the file and pushes the content back into the
   vault through the session (so the vault stays the source of truth);
4. the temporary file is deleted on lock, on quit and after the write-back settles.

``secret``/``secretfile`` files never take this path — the native viewer with a Copy button is
the only way their content is displayed (see ``vault.ui.viewer``).
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from . import i18n

_LOG = logging.getLogger(__name__)

#: Editors tried before falling back to the desktop's default handler, in preference order.
_KNOWN_EDITORS = (
    "kate",
    "gnome-text-editor",
    "gedit",
    "xed",
    "mousepad",
    "leafpad",
    "notepadqq",
    "featherpad",
    "pluma",
)


def editor_command(path: Path) -> list[str] | None:
    """Return the command that opens ``path`` in the OS default (text) editor."""
    for env in ("VISUAL", "EDITOR"):
        value = os.environ.get(env, "").strip()
        if value:
            return value.split() + [str(path)]
    if os.name == "nt":
        return ["cmd", "/c", "start", "", str(path)]
    if sys.platform == "darwin":
        return ["open", "-t", str(path)]
    for candidate in _KNOWN_EDITORS + ("sensible-editor",):
        found = shutil.which(candidate) or _absolute(candidate)
        if found:
            return [found, str(path)]
    opener = shutil.which("xdg-open") or _absolute("xdg-open")
    if opener:
        return [opener, str(path)]
    return None


def _absolute(name: str) -> str | None:
    """Find ``name`` in the usual system directories.

    Desktop launches sometimes inherit a minimal ``PATH``; without this the vault claimed no
    text editor existed at all on a machine that clearly has one.
    """
    for directory in ("/usr/bin", "/usr/local/bin", "/bin", "/snap/bin"):
        candidate = Path(directory) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


class ExternalEditor:
    """Manages the decrypted temporary copy handed to an external editor."""

    def __init__(
        self,
        session: Any,
        *,
        runtime_dir: Path,
        on_saved: Callable[[str], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        """Bind the helper to the unlocked session it may write back into."""
        self.session = session
        self.runtime_dir = Path(runtime_dir)
        self.on_saved = on_saved
        self.on_error = on_error
        self._open: dict[Path, dict[str, Any]] = {}

    # ------------------------------------------------------------------ helpers
    @property
    def edit_dir(self) -> Path:
        """Directory holding the temporary copies (created lazily, mode 0700)."""
        directory = self.runtime_dir / "secure-vault" / "edit"
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:  # pragma: no cover - best effort
            pass
        return directory

    def temp_path(self, logical_path: str) -> Path:
        """Return the temporary path used for ``logical_path``."""
        digest = hashlib.sha256(logical_path.encode("utf-8")).hexdigest()[:16]
        name = Path(logical_path).name or "note.md"
        suffix = Path(name).suffix if Path(name).suffix else ".md"
        return self.edit_dir / f"{digest}{suffix}"

    # -------------------------------------------------------------------- api
    def open(self, logical_path: str, *, sensitivity: str = "normal") -> Path | None:
        """Write a temporary copy and start the editor; returns the temp path used."""
        if sensitivity != "normal":
            self._report(i18n.tr("editor.external_only_normal", level=sensitivity))
            return None
        try:
            data = self.session.read_file(logical_path, source="ui")
        except Exception as exc:  # noqa: BLE001 - report, never crash the UI
            self._report(f"{exc}")
            return None
        target = self.temp_path(logical_path)
        target.write_bytes(data)
        try:
            os.chmod(target, 0o600)
        except OSError:  # pragma: no cover - best effort
            pass
        command = editor_command(target)
        if command is None:
            self._report(i18n.tr("editor.external_missing"))
            return None
        try:
            subprocess.Popen(command, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        except OSError as exc:
            _LOG.warning("could not start %s: %s", command[0], exc)
            self._report(i18n.tr("editor.external_failed"))
            return None
        self._open[target] = {"path": logical_path, "mtime": target.stat().st_mtime}
        _LOG.info("opened %s in %s", logical_path, command[0])
        return target

    def poll(self) -> list[str]:
        """Save back any temporary file the editor changed; returns the saved paths."""
        saved: list[str] = []
        for target, record in list(self._open.items()):
            try:
                mtime = target.stat().st_mtime
            except OSError:
                self._open.pop(target, None)
                continue
            if mtime <= float(record["mtime"]):
                continue
            record["mtime"] = mtime
            logical = str(record["path"])
            try:
                data = target.read_bytes()
                self.session.write_file(logical, data, source="ui")
            except Exception as exc:  # noqa: BLE001
                _LOG.warning("could not save %s back into the vault: %s", logical, exc)
                continue
            saved.append(logical)
            if self.on_saved is not None:
                self.on_saved(logical)
        return saved

    def close(self, logical_path: str | None = None) -> None:
        """Delete the temporary copies (all of them, or just one logical path)."""
        for target, record in list(self._open.items()):
            if logical_path is not None and record["path"] != logical_path:
                continue
            self._discard(target)

    def close_all(self) -> None:
        """Delete every temporary copy (used on lock and on quit)."""
        for target in list(self._open):
            self._discard(target)
        # Sweep leftovers from a previous run of this process.
        try:
            for stray in self.edit_dir.glob("*"):
                if stray.is_file() and stray not in self._open:
                    stray.unlink()
        except OSError:  # pragma: no cover - best effort
            pass

    # ---------------------------------------------------------------- internal
    def _discard(self, target: Path) -> None:
        self._open.pop(target, None)
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:  # pragma: no cover
            _LOG.warning("could not remove %s: %s", target, exc)

    def _report(self, message: str) -> None:
        _LOG.info("external editor: %s", message)
        if self.on_error is not None:
            self.on_error(message)


__all__ = ["ExternalEditor", "editor_command"]
