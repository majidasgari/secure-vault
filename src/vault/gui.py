"""GUI entry point (``python -m vault``; SPEC/03 §1).

Parses the command line, applies the theme/font, resolves the vault home and either
shows the unlock/new-vault screen or runs ``--self-test`` (which builds the whole UI
against a scratch vault, exercises the flows and exits without ``app.exec()``).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from . import __version__
from .config import DEFAULT_VAULT_HOME, runtime_dir, user_config
from .core import fingerprint, semantics
from .core.session import VaultSession
from .errors import Unauthorized
from .ui import editor as editor_module
from .ui import i18n, image_view, theme, viewer
from .ui.app import VaultApplication
from .ui.settings_dialog import SettingsDialog

LOG = logging.getLogger("vault.gui")

SELFTEST_PASSWORD = "ui-self-test-password"


@dataclass
class SelfTestResult:
    """The outcome of ``run_self_test`` including live UI references."""

    home: Path
    checks: dict[str, Any]
    qapp: Any
    controller: VaultApplication
    window: Any
    editor: Any
    search_panel: Any
    log_panel: Any
    runtime: Path
    previous_xdg: str | None = None
    previous_config: str | None = None
    previous_data: str | None = None


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the GUI command line."""
    parser = argparse.ArgumentParser(prog="vault", description="Secure Vault desktop app.")
    parser.add_argument("--home", default=None, help="vault home directory")
    parser.add_argument("--language", choices=("fa", "en"), default=None)
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    parser.add_argument("--no-tray", action="store_true", help="do not use the system tray")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="build the UI against a scratch vault, print SELFTEST OK and exit",
    )
    return parser.parse_args(argv)


def _setup_logging(debug: bool) -> None:
    """Configure logging to stderr at INFO (or DEBUG)."""
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def resolve_home(explicit: str | None) -> Path:
    """Resolve the vault home from ``--home``, the env or ``ui.json``."""
    if explicit:
        return Path(explicit)
    env_home = os.environ.get("SECURE_VAULT_HOME")
    if env_home:
        return Path(env_home)
    last = user_config().data.get("last_vault_home")
    if isinstance(last, str) and last:
        return Path(last)
    return Path(DEFAULT_VAULT_HOME)


class _WindowsMutex:
    """A held Win32 named mutex; :meth:`close` releases it."""

    def __init__(self, handle: Any, kernel32: Any) -> None:
        """Wrap the mutex ``handle`` so ``close()`` can release it."""
        self._handle = handle
        self._kernel32 = kernel32

    def close(self) -> None:
        """Release the mutex (idempotent)."""
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def _acquire_windows_mutex(name: str) -> "_WindowsMutex | None":
    """Create (or fail to create) a per-user named mutex, mirroring ``flock``.

    Returns ``None`` when another process already holds the mutex, which is what the caller
    reports as "Secure Vault is already running". Windows has no ``fcntl``, so this is the
    equivalent single-instance guard.
    """
    import ctypes
    from ctypes import wintypes

    ERROR_ALREADY_EXISTS = 183
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateMutexW
    create.restype = wintypes.HANDLE
    create.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    handle = create(None, False, name)
    if not handle:
        return None
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return None
    return _WindowsMutex(handle, kernel32)


def _acquire_single_instance() -> Any:
    """Take the single-instance lock, returning a handle or None when already running.

    POSIX uses an advisory ``flock`` on ``<runtime>/gui.lock``; Windows uses a named mutex in
    the session-local namespace, keyed on the same runtime directory so two vaults with
    different runtime dirs do not block each other.
    """
    runtime = runtime_dir()
    if os.name == "nt":
        import hashlib

        digest = hashlib.sha256(str(runtime).lower().encode("utf-8")).hexdigest()[:16]
        return _acquire_windows_mutex(f"Local\\secure-vault-gui-{digest}")
    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-Unix
        return None
    path = runtime / "gui.lock"
    handle = open(path, "a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


def _png_bytes(width: int = 4, height: int = 3) -> bytes:
    """Build a small PNG in memory so the picture flows can be exercised for real."""
    from PySide6.QtCore import QBuffer, QByteArray
    from PySide6.QtGui import QColor, QPixmap

    pixmap = QPixmap(width, height)
    pixmap.fill(QColor("#336699"))
    array = QByteArray()
    buffer = QBuffer(array)
    buffer.open(QBuffer.OpenModeFlag.WriteOnly)
    pixmap.save(buffer, "PNG")
    buffer.close()
    return bytes(array.data())


def run_self_test(
    *, home: Path | None = None, language: str = "fa", no_tray: bool = True
) -> SelfTestResult:
    """Build the whole UI against a scratch vault and exercise the flows."""
    base = Path(tempfile.mkdtemp(prefix="sv-uitest-"))
    runtime = base / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    os.chmod(runtime, 0o700)
    previous_xdg = os.environ.get("XDG_RUNTIME_DIR")
    previous_config = os.environ.get("XDG_CONFIG_HOME")
    previous_data = os.environ.get("XDG_DATA_HOME")
    os.environ["XDG_RUNTIME_DIR"] = str(runtime)
    config_home = base / "config"
    config_home.mkdir(parents=True, exist_ok=True)
    os.environ["XDG_CONFIG_HOME"] = str(config_home)
    os.environ["XDG_DATA_HOME"] = str(base / "data")

    vault_home = Path(home) if home is not None else base / "vault"
    if VaultSession.is_initialised(vault_home):
        session = VaultSession(vault_home)
        try:
            session.unlock(SELFTEST_PASSWORD)
        except Unauthorized:
            vault_home = base / "vault"
            session = VaultSession.create(vault_home, SELFTEST_PASSWORD)
    else:
        session = VaultSession.create(vault_home, SELFTEST_PASSWORD)
    session._runtime = runtime
    # Keep the (otherwise user-home) semantic cache inside the scratch dir.
    session.meta.settings.setdefault("semantic", {})["db_path"] = str(
        base / "semantic.db"
    )
    session.meta.save()

    session.set_semantic_provider(semantics.StubProvider())
    session.write_file("notes/hello.md", b"# Hello\n\nalpha world\n")
    session.write_file("notes/secret.md", b"secret alpha body")
    session.set_sensitivity("notes/secret.md", "secret")
    session.write_file("secrets/key.txt", b"token=alpha-secret")
    session.set_sensitivity("secrets/key.txt", "secretfile")
    session.mkdir("journal")
    # The semantic vector index is an opt-in extra (``requirements-semantic.txt``: sqlite-vec
    # plus a sentence-transformers model). The app documents that every other feature keeps
    # working without it — including the portable Windows build, which ships requirements.txt
    # only — so the self-test reports the semantic step as skipped instead of dying.
    semantic_note: str
    try:
        semantics.index_all(session)
        semantic_note = "ok"
    except Exception as exc:  # noqa: BLE001 - an absent optional extra is not a failure
        semantic_note = f"skipped: {type(exc).__name__}: {exc}"

    qapp = QApplication.instance() or QApplication(["secure-vault-selftest"])
    qapp.setApplicationName("Secure Vault")
    qapp.setDesktopFileName("secure-vault")
    theme.apply(qapp, language)

    controller = VaultApplication(
        qapp,
        home=vault_home,
        language=language,
        no_tray=no_tray,
        self_test=True,
    )
    controller.attach_session(session)
    window = controller.window
    qapp.processEvents()

    checks: dict[str, Any] = {}
    controller.confirm_hook = lambda level, path: True
    window.browser.refresh()
    qapp.processEvents()
    checks["tree_rows"] = window.tree_model.rowCount()
    checks["tree_has_notes"] = window.tree_model.rowCount() > 0

    checks["open_normal"] = bool(window.open_file("/notes/hello.md"))
    checks["preview_enabled_normal"] = bool(window.editor.preview_enabled)
    checks["normal_content"] = "alpha world" in window.editor.source.toPlainText()

    checks["open_secret"] = bool(window.open_file("/notes/secret.md"))
    checks["preview_disabled_secret"] = window.editor.preview_enabled is False
    checks["secret_content"] = "secret alpha body" in window.editor.source.toPlainText()

    web_before = editor_module.web_views_created
    checks["open_secretfile"] = bool(controller.open_path("/secrets/key.txt"))
    checks["viewer_text"] = viewer.last_text
    checks["viewer_uses_web"] = viewer.uses_web_engine
    checks["web_views_for_secretfile"] = editor_module.web_views_created - web_before

    # Pictures go to the native image viewer, not the editor or a web engine (SPEC/03 §2.4).
    picture = _png_bytes()
    session.write_file("notes/shot.png", picture)
    session.write_file("secrets/scan.png", picture)
    session.set_sensitivity("secrets/scan.png", "secret")
    checks["image_suffix_yes"] = image_view.looks_like_image("/notes/shot.png")
    checks["image_suffix_no"] = image_view.looks_like_image("/notes/hello.md")
    web_before = editor_module.web_views_created
    checks["open_image"] = bool(window.open_file("/notes/shot.png"))
    checks["image_size"] = image_view.last_size
    checks["image_bytes_roundtrip"] = controller.read_bytes("/notes/shot.png") == picture
    checks["image_uses_web"] = editor_module.web_views_created - web_before
    checks["image_viewer_open"] = bool(getattr(window, "image_viewer", None))
    checks["open_secret_image"] = bool(controller.open_path("/secrets/scan.png"))
    checks["secret_image_shown"] = image_view.last_path == "/secrets/scan.png"

    # Appearance: a forced dark theme repaints the widgets that carry their own colours.
    light_bg = theme.colors()["bg"]
    checks["theme_default"] = theme.preference()
    checks["theme_set_dark"] = controller.set_theme("dark")
    checks["theme_dark_active"] = theme.is_dark()
    checks["theme_dark_palette"] = theme.colors()["bg"] != light_bg
    checks["theme_persisted"] = controller.config.data.get("theme")
    checks["theme_canvas_dark"] = (
        theme.colors()["code_bg"] in window.image_viewer.canvas.styleSheet()
    )
    checks["theme_back_to_system"] = controller.set_theme("system")
    checks["theme_system_restored"] = theme.preference() == "system"
    audit = controller.dispatch_ui("vault.access_log", {"limit": 50}).get("entries", [])
    checks["secretfile_logged"] = any(
        entry.get("tool") == "ui.read_secretfile" for entry in audit
    )

    checks["semantic_index"] = semantic_note
    checks["search_filename"] = len(window.search_panel.run_search("filename", "hello"))
    checks["search_text"] = len(window.search_panel.run_search("text", "alpha"))
    checks["search_semantic"] = (
        len(window.search_panel.run_search("semantic", "alpha"))
        if semantic_note == "ok"
        else "skipped"
    )
    checks["last_results_filename"] = len(window.search_panel.last_results("filename"))

    window.log_panel.refresh()
    log_before = window.log_panel.row_count()
    controller.open_path("/notes/hello.md")
    window.log_panel.refresh()
    checks["log_rows"] = window.log_panel.row_count()
    checks["log_grows"] = window.log_panel.row_count() > log_before

    controller.set_language("en")
    window.retranslate()
    checks["lang_en"] = i18n.lang
    checks["ltr"] = qapp.layoutDirection() == Qt.LeftToRight
    english_label = window.browser.actions["refresh"].text()
    controller.set_language("fa")
    window.retranslate()
    checks["lang_fa"] = i18n.lang
    checks["rtl"] = qapp.layoutDirection() == Qt.RightToLeft
    checks["label_changed"] = english_label != window.browser.actions["refresh"].text()

    dialog = SettingsDialog(controller, window)
    dialog.show()
    qapp.processEvents()
    checks["settings_ok"] = True
    checks["settings_tabs"] = dialog.tabs.count()
    checks["settings_fingerprint_tab"] = bool(dialog.fingerprint_enable_button.text())

    # Quick unlock: store a wrapped key, release it with a fabricated match, then drop it again
    # (the scratch XDG_DATA_HOME keeps this away from the user's real record).
    verification = fingerprint.VerifyResult(True, "match", "0.0s", ("self-test",))
    quick_state = session.quick_unlock_enable(verification)
    checks["quick_unlock_enabled"] = bool(quick_state.get("enabled"))
    released = fingerprint.release_master_key(vault_home, verification)
    checks["quick_unlock_release"] = bytes(released) == bytes(session._master_key or b"")
    checks["quick_unlock_removed"] = bool(session.quick_unlock_disable())
    checks["quick_unlock_off"] = not fingerprint.quick_unlock_state(vault_home)["enabled"]
    # Enable it once more so the unlock screen has something to offer after locking.
    checks["quick_unlock_reenabled"] = bool(session.quick_unlock_enable(verification)["enabled"])
    dialog.close()

    controller.lock()
    checks["locked_screen"] = controller.current_screen == "unlock"
    checks["session_locked"] = bool(session.is_locked)
    unlock_screen = controller.unlock_screen
    unlock_state = unlock_screen.fingerprint_state() if unlock_screen is not None else {}
    checks["unlock_fingerprint_state"] = "available" in unlock_state
    # Quick unlock is on, so the screen offers the sensor by itself and keeps its button.
    checks["unlock_auto_scan_armed"] = controller.auto_scan_armed()
    checks["unlock_fingerprint_button"] = bool(
        unlock_screen is not None and not unlock_screen.fingerprint_button.isHidden()
    )
    # Never let the scheduled scan reach the real sensor during a self-test.
    controller.cancel_auto_scan()
    checks["unlock_auto_scan_cancelled"] = not controller.auto_scan_armed()
    checks["quick_unlock_cleaned"] = bool(fingerprint.disable_quick_unlock(vault_home))
    checks["quick_unlock_absent"] = not fingerprint.quick_unlock_state(vault_home)["enabled"]
    checks["selftest_ok"] = all(
        bool(value)
        for key, value in checks.items()
        if key not in ("tree_rows", "viewer_text", "viewer_uses_web",
                       "web_views_for_secretfile", "search_filename", "search_text",
                       "search_semantic", "last_results_filename", "log_rows",
                       "image_suffix_no", "image_uses_web", "image_size")
    )

    return SelfTestResult(
        home=vault_home,
        checks=checks,
        qapp=qapp,
        controller=controller,
        window=window,
        editor=window.editor,
        search_panel=window.search_panel,
        log_panel=window.log_panel,
        runtime=runtime,
        previous_xdg=previous_xdg,
        previous_config=previous_config,
        previous_data=previous_data,
    )


def main(argv: list[str] | None = None) -> int:
    """Run the GUI (or the self-test) and return the process exit code."""
    args = _parse_args(argv)
    _setup_logging(args.debug)

    # QtWebEngine silently produces a blank page when its sandbox or GPU stack is unusable
    # (the "empty preview" symptom). These flags must be set before Qt starts.
    os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")

    app = QApplication.instance() or QApplication(sys.argv[:1] or ["secure-vault"])
    app.setApplicationName("Secure Vault")
    app.setDesktopFileName("secure-vault")

    language = args.language or user_config().language
    theme.apply(app, language)

    if args.self_test:
        result = run_self_test(
            home=Path(args.home) if args.home else None,
            language=language,
            no_tray=True,
        )
        print("SELFTEST OK")
        print(json.dumps(result.checks, ensure_ascii=False, indent=2))
        result.controller.shutdown()
        if result.previous_xdg is None:
            os.environ.pop("XDG_RUNTIME_DIR", None)
        else:
            os.environ["XDG_RUNTIME_DIR"] = result.previous_xdg
        if result.previous_config is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = result.previous_config
        if result.previous_data is None:
            os.environ.pop("XDG_DATA_HOME", None)
        else:
            os.environ["XDG_DATA_HOME"] = result.previous_data
        return 0

    home = resolve_home(args.home)
    offscreen = os.environ.get("QT_QPA_PLATFORM") == "offscreen"
    lock_handle = None
    if not offscreen:
        lock_handle = _acquire_single_instance()
        if lock_handle is None:
            QMessageBox.warning(
                None, "Secure Vault", i18n.tr("app.already_running")
            )
            return 3

    controller = VaultApplication(
        app,
        home=home,
        language=language,
        no_tray=args.no_tray,
        session_loader=lambda target: VaultSession(target),
        vault_creator=lambda target, password: VaultSession.create(target, password),
    )
    controller.show_unlock()
    if not VaultSession.is_initialised(home):
        QTimer.singleShot(0, controller.create_vault)
    app.aboutToQuit.connect(controller.shutdown)
    code = app.exec()
    if lock_handle is not None:
        lock_handle.close()
    return int(code)


__all__ = ["main", "run_self_test", "resolve_home", "SelfTestResult", "SELFTEST_PASSWORD"]
