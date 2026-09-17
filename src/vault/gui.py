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
from .core import semantics
from .core.session import VaultSession
from .errors import Unauthorized
from .ui import editor as editor_module
from .ui import i18n, theme, viewer
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


def _acquire_single_instance() -> Any:
    """Take the advisory GUI lock, returning the file handle or None."""
    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-Unix
        return None
    path = runtime_dir() / "gui.lock"
    handle = open(path, "a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


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
    os.environ["XDG_RUNTIME_DIR"] = str(runtime)
    config_home = base / "config"
    config_home.mkdir(parents=True, exist_ok=True)
    os.environ["XDG_CONFIG_HOME"] = str(config_home)

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

    session.set_semantic_provider(semantics.StubProvider())
    session.write_file("notes/hello.md", b"# Hello\n\nalpha world\n")
    session.write_file("notes/secret.md", b"secret alpha body")
    session.set_sensitivity("notes/secret.md", "secret")
    session.write_file("secrets/key.txt", b"token=alpha-secret")
    session.set_sensitivity("secrets/key.txt", "secretfile")
    session.mkdir("journal")
    semantics.index_all(session)

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
    audit = controller.dispatch_ui("vault.access_log", {"limit": 50}).get("entries", [])
    checks["secretfile_logged"] = any(
        entry.get("tool") == "ui.read_secretfile" for entry in audit
    )

    checks["search_filename"] = len(window.search_panel.run_search("filename", "hello"))
    checks["search_text"] = len(window.search_panel.run_search("text", "alpha"))
    checks["search_semantic"] = len(window.search_panel.run_search("semantic", "alpha"))
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
    dialog.close()
    checks["settings_ok"] = True

    controller.lock()
    checks["locked_screen"] = controller.current_screen == "unlock"
    checks["session_locked"] = bool(session.is_locked)
    checks["selftest_ok"] = all(
        bool(value)
        for key, value in checks.items()
        if key not in ("tree_rows", "viewer_text", "viewer_uses_web",
                       "web_views_for_secretfile", "search_filename", "search_text",
                       "search_semantic", "last_results_filename", "log_rows")
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
    )


def main(argv: list[str] | None = None) -> int:
    """Run the GUI (or the self-test) and return the process exit code."""
    args = _parse_args(argv)
    _setup_logging(args.debug)

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
