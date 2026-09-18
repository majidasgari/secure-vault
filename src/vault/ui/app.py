"""Application controller and startup wiring (SPEC/03 §1, §2.5).

:class:`VaultApplication` owns the :class:`~vault.api.service.Service`, the socket
server, the windows, the tray and the auto-lock timer. All vault data operations go
through ``Service.dispatch(..., role="ui")``; the session object it is given is used
only for locking, the auto-lock clock and the agent secret-request flow.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from PySide6.QtCore import QObject, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QVBoxLayout,
)

from .. import __version__
from ..api.service import ActivityFeed, Service
from ..api.socket_server import VaultSocketServer
from ..errors import AlreadyExists
from ..util import now_ms
from ..config import runtime_dir, user_config
from ..core.meta import DEFAULT_IMPORT_MIRROR
from ..errors import Unauthorized, VaultError
from ..util import normalize_vault_path
from ..web.auth import TOKEN_FILENAME
from ..web.server import WebServer
from . import i18n, notifications, theme, viewer

LOG = logging.getLogger("vault.ui.app")

WEB_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "host": "127.0.0.1",
    "port": 8788,
    "allow_lan": False,
    "open_browser_on_start": False,
}
from .external import ExternalEditor
from .main_window import MainWindow
from .models import DataHub
from .settings_dialog import SettingsDialog
from .tray import TrayIcon
from .unlock import UnlockScreen

AUTO_LOCK_TICK_MS = 1000
#: How often the external-editor helper looks for changes to save back into the vault.
EXTERNAL_POLL_MS = 1500
#: How often the import dialog refreshes its percentage from the importer's progress state.
IMPORT_POLL_MS = 400

#: Importer phase name -> i18n key (used by the progress dialog).
_PHASE_KEYS = {
    "folders": "import.phase_folders",
    "notes": "import.phase_notes",
    "assets": "import.phase_assets",
    "strays": "import.phase_strays",
    "reindex": "import.phase_reindex",
}


class ReindexProgress:
    """Adapts :meth:`VaultSession.reindex_search` progress to the import dialog's shape."""

    def __init__(self) -> None:
        """Start with an empty progress state."""
        self.progress: dict[str, Any] = {
            "phase": "reindex",
            "phase_done": 0,
            "phase_total": 0,
            "done": 0,
            "total": 0,
            "percent": 0,
            "finished": False,
        }

    def __call__(self, phase: str, done: int, total: int) -> None:
        """Record one tick (called from the worker thread)."""
        total = max(1, int(total))
        self.progress.update(
            phase=phase,
            phase_done=int(done),
            phase_total=total,
            done=int(done),
            total=total,
            percent=int(round(100.0 * done / total)),
        )


class SemanticProgress:
    """Adapts :meth:`VaultSession.index_semantics` progress to the progress dialog's shape."""

    def __init__(self) -> None:
        """Start with an empty progress state."""
        self.progress: dict[str, Any] = {
            "phase": "semantic",
            "phase_done": 0,
            "phase_total": 0,
            "done": 0,
            "total": 0,
            "percent": 0,
            "finished": False,
        }

    def __call__(self, done: int, total: int) -> None:
        """Record one tick (called from the worker thread)."""
        total = max(1, int(total))
        self.progress.update(
            phase="semantic",
            phase_done=int(done),
            phase_total=total,
            done=int(done),
            total=total,
            percent=int(round(100.0 * done / total)),
        )


def _format_duration(seconds: float) -> str:
    """Return a short, localized "time left" string."""
    total = int(max(0, round(seconds)))
    if total < 60:
        return i18n.tr("import.unit_seconds", count=total)
    minutes = int(round(total / 60))
    if minutes < 60:
        return i18n.tr("import.unit_minutes", count=minutes)
    return i18n.tr("import.unit_hours", count=int(round(minutes / 60)))


def error_message(exc: Exception) -> str:
    """Render a :class:`VaultError` as a translated message, never a traceback."""
    code = getattr(exc, "code", None)
    if isinstance(code, str):
        key = f"error.{code}"
        translated = i18n.tr(key)
        if not translated.startswith("\u27e6"):
            return translated
    return str(exc)


class SecretRequestDialog(QDialog):
    """The non-modal agent secret-request dialog (SPEC/03 §2.5)."""

    def __init__(
        self,
        parent: Any,
        request: dict,
        on_decision: Callable[[dict, bool], None],
    ) -> None:
        """Build the dialog for ``request`` and call ``on_decision`` when answered."""
        super().__init__(parent)
        self.request = request
        self._on_decision = on_decision
        self.setModal(False)
        path = "/" + str(request.get("path", "")).lstrip("/")

        layout = QVBoxLayout(self)
        self.message = QLabel(i18n.tr("request.message", path=path), self)
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        self.show_button = QPushButton(i18n.tr("request.show_copy"), self)
        self.show_button.clicked.connect(lambda: self._decide(True))
        self.deny_button = QPushButton(i18n.tr("request.deny"), self)
        self.deny_button.clicked.connect(lambda: self._decide(False))
        layout.addWidget(self.show_button)
        layout.addWidget(self.deny_button)
        self.setWindowTitle(i18n.tr("request.title"))

    def _decide(self, approved: bool) -> None:
        """Forward the decision and close the dialog."""
        self._on_decision(self.request, approved)
        self.close()


class VaultApplication(QObject):
    """Owns the service, the socket server, the windows and the timers."""

    secret_requested = Signal(object)
    # Emitted from any thread with a metadata-only activity event (SPEC/09 §7).
    activity_reported = Signal(object)
    # Emitted from the importer worker thread with the report dict (SPEC/03 §4 Importer).
    import_finished = Signal(object)
    # Emitted from the reindex worker thread with the rebuild result.
    reindex_finished = Signal(object)
    # Emitted from the semantic-index worker thread with the ``indexed``/``skipped`` result.
    semantic_finished = Signal(object)

    def __init__(
        self,
        qapp: Any,
        *,
        home: Path,
        language: str = "fa",
        no_tray: bool = False,
        self_test: bool = False,
        session_loader: Callable[[Path], Any] | None = None,
        vault_creator: Callable[[Path, str], Any] | None = None,
        parent: Any = None,
    ) -> None:
        """Create the controller for ``home`` (no session yet)."""
        super().__init__(parent)
        self.qapp = qapp
        self.home = Path(home)
        self.no_tray = no_tray
        self.self_test = self_test
        self._session_loader = session_loader
        self._vault_creator = vault_creator
        self.config = user_config()
        self.language = language
        self.start_minimized = bool(self.config.data.get("start_minimized", False))

        self.session: Any = None
        self.service: Service | None = None
        self.server: VaultSocketServer | None = None
        #: Why the daemon socket could not be started (shown once the tray exists).
        self.daemon_conflict: Exception | None = None
        #: Throttle for agent-access notifications: (source, kind, path) -> last ts.
        self._agent_notified: dict[tuple[str, str, str], int] = {}
        self.web: WebServer | None = None
        self.web_conflict = False
        self.activity = ActivityFeed()
        self.hub = DataHub()
        self.window: MainWindow | None = None
        self.unlock_screen: UnlockScreen | None = None
        self.tray: TrayIcon | None = None
        self.current_screen = "none"
        self.confirm_hook: Callable[[str, str], bool] | None = None
        self._secret_dialogs: list[SecretRequestDialog] = []
        # Joplin import (SPEC/03 §4 "Importer"): the report of the last run, exposed so the
        # smoke tests can assert the UI path without a modal dialog.
        self.last_import_report: dict[str, Any] | None = None
        self.last_import_mirror: str | None = None
        self.last_import_error: str | None = None
        self._external: ExternalEditor | None = None
        self._external_timer: QTimer | None = None
        self._web_error: str | None = None
        self._import_importer: Any | None = None
        self._import_timer: QTimer | None = None
        self._import_started_at: float = 0.0
        self._last_browser_open: tuple[str, float] = ("", 0.0)
        self.import_running = False
        self._import_progress: QProgressDialog | None = None

        i18n.set_language(language)
        theme.apply(qapp, language)
        self.secret_requested.connect(self._show_secret_request)
        self.activity_reported.connect(self._handle_activity)
        self.import_finished.connect(self._on_import_finished)
        self.reindex_finished.connect(self._on_reindex_finished)
        self.semantic_finished.connect(self._on_semantic_finished)

        self._auto_lock_timer = QTimer(self)
        self._auto_lock_timer.setInterval(AUTO_LOCK_TICK_MS)
        self._auto_lock_timer.timeout.connect(self._auto_lock_tick)

    # ------------------------------------------------------------------ screen
    @property
    def vault_home(self) -> Path:
        """The active vault home directory."""
        if self.session is not None:
            return Path(self.session.home)
        return self.home

    def show_unlock(self) -> UnlockScreen:
        """Create (once) and show the unlock screen."""
        if self.unlock_screen is None:
            self.unlock_screen = UnlockScreen()
            self.unlock_screen.unlock_requested.connect(self.unlock)
            self.unlock_screen.open_vault_requested.connect(self.choose_vault)
            self.unlock_screen.create_vault_requested.connect(self.create_vault)
            self.unlock_screen.language_selected.connect(self.set_language)
        self.unlock_screen.set_vault_info(i18n.tr("app.title"), str(self.home))
        self.unlock_screen.set_language(self.language)
        if self.window is not None:
            self.window.hide()
        self.unlock_screen.show()
        self.current_screen = "unlock"
        if self.tray is not None:
            self.tray.set_locked(True)
        return self.unlock_screen

    def attach_session(self, session: Any) -> MainWindow:
        """Bind ``session``, start the socket server and build the main window."""
        self.session = session
        self.home = Path(session.home)
        self.config.data["last_vault_home"] = str(self.home)
        try:
            self.config.save()
        except Exception:  # noqa: BLE001 - persistence is best effort
            pass
        session.data_changed = self.hub
        if self.service is None:
            self.service = Service(session, on_secret_request=self._on_secret_request)
            session.on_activity = self._on_activity
            self._start_server()
            self._start_web()
        self._build_tray()
        self._build_main_window()
        self._sync_editor_web()
        self._auto_lock_timer.start()
        self.current_screen = "main"
        if self.tray is not None:
            self.tray.set_locked(False)
        return self.window  # type: ignore[return-value]

    def _build_main_window(self) -> None:
        """Create the main window once and refresh it."""
        if self.window is None:
            self.window = MainWindow(self)
            self.hub.subscribe(self.window.browser.refresh)
            self.hub.subscribe(self.window.log_panel.refresh_soon)
            self.window.editor.open_in_browser.connect(self.open_in_browser)
            self.window.editor.direction_changed.connect(self._on_editor_direction)
            self.window.editor.note_changed.connect(self.set_file_note)
            mode = self.config.data.get("editor_direction")
            if isinstance(mode, str) and mode in ("auto", "rtl", "ltr"):
                self.window.editor.set_direction_mode(mode)
            if self.start_minimized and self.tray_available():
                self.window.hide()
            else:
                self.window.show()
        else:
            self.window.refresh()
            self.window.show()

    def _build_tray(self) -> None:
        """Create the tray icon when allowed and available."""
        if self.no_tray or self.tray is not None:
            return
        from ..config import app_paths

        self.tray = TrayIcon(
            icon_path=app_paths().assets_dir / "icon.svg",
            on_show=self._show_window,
            on_open_web=self.open_web,
            on_copy_link=self.copy_web_link,
            on_lock=self.lock,
            on_search=self._show_search,
            on_settings=self.open_settings,
            on_recent=self.open_in_browser,
            on_quit=self.quit,
        )
        self.tray.set_locked(not (self.session is None or self.session.is_locked))
        if self.tray.available:
            self.tray.set_activity(self.activity.events())
        if self.daemon_conflict is not None:
            notifications.notify(
                i18n.tr("notification.daemon_conflict_title"),
                i18n.tr(
                    "notification.daemon_conflict_body",
                    socket=str(getattr(self.daemon_conflict, "details", {}).get("socket", "")),
                ),
                tray=self.tray,
            )

    def _show_window(self) -> None:
        """Bring the main window to the front."""
        if self.window is not None:
            self.window.show()
            self.window.raise_()

    def _show_search(self) -> None:
        """Show the main window and focus the search box."""
        self._show_window()
        if self.window is not None:
            self.window.search_panel.focus_query()

    # ------------------------------------------------------------------ unlock
    def unlock(self, password: str) -> bool:
        """Unlock the vault, returning True on success."""
        if self.session is None:
            if self._session_loader is None:
                return False
            self.session = self._session_loader(self.home)
        try:
            self.session.unlock(password)
        except Unauthorized:
            if self.unlock_screen is not None:
                self.unlock_screen.notify_failure()
                self.unlock_screen.show_error(i18n.tr("unlock.wrong_password"))
            return False
        except VaultError as exc:
            if self.unlock_screen is not None:
                self.unlock_screen.show_error(error_message(exc))
            return False
        if self.unlock_screen is not None:
            self.unlock_screen.reset_failures()
            self.unlock_screen.hide()
        self.attach_session(self.session)
        return True

    def choose_vault(self) -> None:
        """Ask for another vault folder and switch to its unlock screen."""
        from PySide6.QtWidgets import QFileDialog

        chosen = QFileDialog.getExistingDirectory(
            self.unlock_screen, i18n.tr("unlock.open_another"), str(self.home)
        )
        if not chosen:
            return
        self.home = Path(chosen)
        self.session = None
        if self.unlock_screen is not None:
            self.unlock_screen.set_vault_info(i18n.tr("app.title"), str(self.home))
            self.unlock_screen.clear_error()

    def create_vault(self) -> None:
        """Open the new-vault wizard and create the vault on success."""
        from .new_vault import NewVaultDialog

        dialog = NewVaultDialog(self.unlock_screen)
        if dialog.exec() != QDialog.Accepted:
            return
        home, password, structure = dialog.values()
        if self._vault_creator is None:
            return
        try:
            session = self._vault_creator(home, password)
        except VaultError as exc:
            if self.unlock_screen is not None:
                self.unlock_screen.show_error(error_message(exc))
            return
        if structure:
            self._create_structure(session)
        self.session = session
        if self.unlock_screen is not None:
            self.unlock_screen.hide()
        self.attach_session(session)

    def _create_structure(self, session: Any) -> None:
        """Create the recommended top-level folders in a new vault."""
        service = Service(session)
        for folder in ("notes", "journal", "secrets", "attachments"):
            try:
                service.dispatch(
                    "vault.mkdir", {"path": f"/{folder}"}, role="ui", session_id="ui"
                )
            except Exception:  # noqa: BLE001 - best effort
                pass

    def lock(self) -> None:
        """Lock the vault and return to the unlock screen."""
        if self.session is None:
            return
        try:
            self.dispatch_ui("vault.lock", {})
        except Exception:  # noqa: BLE001 - still show the unlock screen
            pass
        if self.window is not None:
            self.window.editor.clear()
            self.window.set_current_path(None)
        if self._external is not None:
            self._external.close_all()          # never leave a decrypted copy behind
        self.show_unlock()
        self._sync_editor_web()

    def _auto_lock_tick(self) -> None:
        """Lock the vault when the session reports the idle timeout elapsed."""
        if self.session is None or self.session.is_locked:
            return
        try:
            if self.session.auto_lock_due():
                self.lock()
        except Exception:  # noqa: BLE001 - never let the timer crash the app
            pass
        if self.window is not None:
            self.window.refresh_status()
        if self.tray is not None:
            self.tray.set_activity(self.activity.events())

    # ------------------------------------------------------------------ service
    def dispatch_ui(self, method: str, params: dict) -> dict:
        """Dispatch one UI-role command through the in-process service."""
        if self.service is None:
            raise VaultError("vault_not_ready")
        return self.service.dispatch(method, params, role="ui", session_id="ui")

    def get_settings(self) -> dict:
        """Return the vault settings."""
        try:
            return self.dispatch_ui("vault.get_settings", {})
        except Exception:  # noqa: BLE001
            return {}

    def set_settings(self, payload: dict) -> dict:
        """Persist vault settings through the service."""
        result = self.dispatch_ui("vault.set_settings", payload)
        self.hub.notify()
        return result

    def connection_count(self) -> int:
        """Return the number of live socket connections (0 when no server)."""
        if self.server is None:
            return 0
        try:
            return int(self.server.connection_count())
        except Exception:  # noqa: BLE001
            return 0

    # ------------------------------------------------------------- data helpers
    @staticmethod
    def _api(path: str) -> str:
        """Normalize a path to the API-absolute form."""
        if not path or path == "/":
            return "/"
        return "/" + path.lstrip("/")

    def list_entries(self, path: str) -> list[dict]:
        """List the direct children of ``path`` (metadata works while locked)."""
        result = self.dispatch_ui("vault.list_folder", {"path": self._api(path)})
        return list(result.get("entries", []))

    def stat(self, path: str) -> dict:
        """Return the listing entry for ``path``."""
        api = self._api(path)
        if api == "/":
            return {"path": "/", "is_dir": True, "sensitivity": "normal",
                    "size": 0, "mtime": 0}
        parent = api.rsplit("/", 1)[0] or "/"
        for entry in self.list_entries(parent):
            if entry.get("path") == api:
                return entry
        raise VaultError("not_found", details={"path": api})

    def read(self, path: str) -> str:
        """Read a file's text content as the UI role."""
        result = self.dispatch_ui("vault.read_file", {"path": self._api(path)})
        return str(result.get("content", ""))

    def folder_note(self, path: str) -> str | None:
        """Return the note attached to ``path``."""
        result = self.dispatch_ui("vault.folder_note", {"path": self._api(path)})
        return result.get("note")

    def set_folder_note(self, path: str, text: str) -> None:
        """Persist the note attached to ``path``."""
        self.dispatch_ui(
            "vault.set_folder_note", {"path": self._api(path), "text": text}
        )
        self.hub.notify()

    def file_note(self, path: str) -> str | None:
        """Return the short note attached to a file."""
        result = self.dispatch_ui("vault.file_note", {"path": self._api(path)})
        return result.get("note")

    def set_file_note(self, path: str, text: str) -> None:
        """Persist the short note attached to a file."""
        try:
            self.dispatch_ui(
                "vault.set_file_note", {"path": self._api(path), "text": text}
            )
        except VaultError as exc:
            if self.window is not None:
                QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return
        self.hub.notify()

    def open_path(self, path: str) -> bool:
        """Open a file honoring the sensitivity rules (SPEC/03 §2.4)."""
        api = self._api(path)
        try:
            entry = self.stat(api)
        except VaultError as exc:
            if self.window is not None:
                QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return False
        level = str(entry.get("sensitivity", "normal"))
        try:
            note = self.file_note(api)
        except VaultError:
            note = None
        if level == "normal":
            content = self.read(api)
            self.window.editor.set_content(api, content, preview_enabled=True)
            self.window.editor.set_note(note or "")
        elif level == "secret":
            if not self._confirm(level, api):
                return False
            content = self.read(api)
            self.window.editor.set_content(api, content, preview_enabled=False)
            self.window.editor.set_note(note or "")
            notifications.notify(
                i18n.tr("notification.secret_opened"), api, tray=self.tray
            )
        else:
            if not self._confirm(level, api):
                return False
            content = self.read(api)
            viewer.open_viewer(self.window, api, content, tray=self.tray)
            self._log_secretfile(api)
        return True

    def _confirm(self, level: str, path: str) -> bool:
        """Ask the user to confirm opening a confidential file."""
        if self.confirm_hook is not None:
            return bool(self.confirm_hook(level, path))
        if self.window is None:
            return False
        choice = QMessageBox.question(
            self.window,
            i18n.tr("dialog.confirm_open"),
            i18n.tr("dialog.confirm_open_text", path=path),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return choice == QMessageBox.Yes

    def _log_secretfile(self, path: str) -> None:
        """Append the dedicated ``ui.read_secretfile`` audit row."""
        if self.service is None:
            return
        try:
            self.service._log(
                role="ui",
                tool="ui.read_secretfile",
                target=path.lstrip("/"),
                outcome="allow",
                session_id="ui",
            )
        except Exception:  # noqa: BLE001 - audit logging is best effort
            pass

    def save_file(self, path: str, text: str) -> None:
        """Write editor content back to the vault."""
        self.dispatch_ui(
            "vault.write_file", {"path": self._api(path), "content": text}
        )
        self.hub.notify()

    # ------------------------------------------------------------------ actions
    def new_note(self) -> None:
        """Create a new note in the selected folder."""
        from PySide6.QtWidgets import QInputDialog

        folder = self.window.browser.current_folder if self.window else "/"
        name, ok = QInputDialog.getText(
            self.window, i18n.tr("dialog.new_note"), i18n.tr("dialog.new_note_prompt")
        )
        if not ok or not name.strip():
            return
        path = self._api(folder.rstrip("/") + "/" + name.strip())
        try:
            self.dispatch_ui(
                "vault.write_file",
                {"path": path, "content": "", "sensitivity": "normal"},
            )
        except VaultError as exc:
            QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return
        self.hub.notify()
        self.window.open_file(path)

    def new_folder(self) -> None:
        """Create a new folder in the selected folder."""
        from PySide6.QtWidgets import QInputDialog

        folder = self.window.browser.current_folder if self.window else "/"
        name, ok = QInputDialog.getText(
            self.window, i18n.tr("dialog.new_folder"),
            i18n.tr("dialog.new_folder_prompt"),
        )
        if not ok or not name.strip():
            return
        path = self._api(folder.rstrip("/") + "/" + name.strip())
        try:
            self.dispatch_ui("vault.mkdir", {"path": path})
        except VaultError as exc:
            QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return
        self.hub.notify()

    def import_joplin(
        self,
        *,
        wait: bool = False,
        mirror_root: str | None = None,
        globs: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """Run the Joplin importer against the configured mirror (SPEC/04).

        In the GUI this runs on a worker thread with a busy indicator, because the real
        mirror takes minutes; ``wait=True`` (used by the smoke tests and the headless
        self-test) runs it inline instead. The vault must be unlocked, and the importer
        itself refuses a vault home that overlaps the mirror.
        """
        if self.session is None:
            return None
        settings = self.get_settings() or {}
        import_settings = dict(settings.get("import_joplin") or {})
        mirror = Path(
            mirror_root
            or import_settings.get("mirror_root")
            or DEFAULT_IMPORT_MIRROR
        )
        globs = list(globs if globs is not None else import_settings.get("sensitive_globs") or [])
        # Exposed for the tests and the log: the path the importer will actually read, so a
        # wrong setting is never silently replaced by the built-in default.
        self.last_import_mirror = str(mirror)
        if self.session.is_locked:
            self._show_import_error(i18n.tr("error.VAULT_LOCKED"))
            return None
        if self.import_running:
            return None
        from ..importers.joplin_mirror import JoplinMirrorImporter

        if not mirror.is_dir():
            self._show_import_error(i18n.tr("import.mirror_missing", path=str(mirror)))
            return None
        importer = JoplinMirrorImporter(mirror, mark_secret_globs=globs)
        self.import_running = True
        if wait or self.self_test:
            try:
                report = importer.run(self.session).to_dict()
            except Exception as exc:  # noqa: BLE001 - surface any importer failure in the UI
                self.import_running = False
                self._show_import_error(error_message(exc))
                return None
            self.import_running = False
            self._on_import_finished(report)
            return report
        self._show_import_progress(importer)
        worker = threading.Thread(
            target=self._run_import_worker, args=(importer,), name="vault-import", daemon=True
        )
        worker.start()
        return None

    def _run_import_worker(self, importer: Any) -> None:
        """Run the importer off the GUI thread and hand the report back via a signal."""
        try:
            payload = importer.run(self.session).to_dict()
        except Exception as exc:  # noqa: BLE001
            payload = {"error": error_message(exc)}
        self.import_finished.emit(payload)

    def _show_import_progress(self, importer: Any | None = None) -> None:
        """Show a percentage bar while the importer runs (no-op when headless).

        The bar is determinate: the importer publishes ``progress`` (phase, done, total,
        percent) and this polls it, so a long import of 876 notes never looks stuck.
        """
        if self.self_test:
            return
        dialog = QProgressDialog(self.window)
        dialog.setWindowTitle(i18n.tr("menu.import"))
        dialog.setLabelText(i18n.tr("import.running"))
        dialog.setRange(0, 100)
        dialog.setValue(0)
        dialog.setMinimumDuration(0)
        dialog.setCancelButton(None)
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        dialog.show()
        self._import_progress = dialog
        self._import_importer = importer
        self._import_started_at = time.monotonic()
        timer = QTimer(self)
        timer.setInterval(IMPORT_POLL_MS)
        timer.timeout.connect(self._poll_import_progress)
        timer.start()
        self._import_timer = timer

    def _poll_import_progress(self) -> None:
        """Show the importer's own percentage, with a rough "time left" estimate."""
        dialog, importer = self._import_progress, self._import_importer
        if dialog is None or importer is None:
            return
        state = getattr(importer, "progress", None) or {}
        percent = max(0, min(100, int(state.get("percent") or 0)))
        done = int(state.get("done") or 0)
        total = int(state.get("total") or 0)
        phase = _PHASE_KEYS.get(str(state.get("phase") or ""), "import.phase_notes")
        dialog.setValue(percent)
        text = i18n.tr(
            "import.progress",
            phase=i18n.tr(phase),
            percent=percent,
            done=done,
            total=total,
        )
        started = self._import_started_at or time.monotonic()
        elapsed = max(0.001, time.monotonic() - started)
        if 0 < done < total:
            remaining = (elapsed / done) * (total - done)
            text += " · " + i18n.tr("import.remaining", value=_format_duration(remaining))
        dialog.setLabelText(text)

    def _close_import_progress(self) -> None:
        """Close the busy indicator if it is open."""
        timer, self._import_timer = self._import_timer, None
        if timer is not None:
            timer.stop()
            timer.deleteLater()
        self._import_importer = None
        dialog, self._import_progress = self._import_progress, None
        if dialog is not None:
            dialog.close()
            dialog.deleteLater()

    def reindex_search(self) -> bool:
        """Rebuild the search index in the background (one-time housekeeping).

        A store written before the indexer stopped storing inline base64 keeps hundreds of
        megabytes of useless tokens; this reclaims them (measured: 253 MB → 68 MB on a real
        vault) without touching a single file.
        """
        if self.self_test:
            return True
        if self.session is None or self.session.is_locked:
            self._notify_web_problem(i18n.tr("error.VAULT_LOCKED"))
            return False
        if self.import_running:
            return False
        self.import_running = True
        adapter = ReindexProgress()
        self._show_import_progress(adapter)
        thread = threading.Thread(
            target=self._reindex_worker, args=(adapter,), name="vault-reindex", daemon=True
        )
        thread.start()
        return True

    def _reindex_worker(self, adapter: ReindexProgress) -> None:
        """Run the rebuild off the GUI thread and report the result."""
        try:
            result = self.session.reindex_search(progress=adapter)
        except Exception as exc:  # noqa: BLE001 - report, never crash the UI
            payload: dict[str, Any] = {"error": error_message(exc)}
        else:
            payload = dict(result)
        adapter.progress["finished"] = True
        self.reindex_finished.emit(payload)

    def _on_reindex_finished(self, payload: Any) -> None:
        """Close the dialog and tell the user what the rebuild reclaimed."""
        self._close_import_progress()
        self.import_running = False
        data = dict(payload or {})
        if data.get("error"):
            self._show_import_error(str(data["error"]))
            return
        self.hub.notify()
        size = 0
        try:
            size = int(self.session.store.stats().get("bytes", 0))
        except Exception:  # noqa: BLE001 - the size is informational only
            size = 0
        notifications.notify(
            i18n.tr("reindex.done_title"),
            i18n.tr(
                "reindex.done_body",
                indexed=int(data.get("indexed", 0)),
                size=f"{size / 1048576:.0f} MB",
            ),
            tray=self.tray,
        )

    def _on_import_finished(self, payload: Any) -> None:
        """Record the report and show it to the user (never a modal in self-test mode)."""
        self._close_import_progress()
        self.import_running = False
        report = dict(payload or {})
        self.last_import_report = report
        if report.get("error"):
            self._show_import_error(str(report["error"]))
            return
        if self.self_test:
            return
        counts = {
            key: report.get(key, 0)
            for key in (
                "notes_created",
                "notes_updated",
                "notes_skipped",
                "folders_created",
                "assets_imported",
            )
        }
        counts["errors"] = len(report.get("errors") or [])
        QMessageBox.information(
            self.window, i18n.tr("import.done_title"), i18n.tr("import.done_text", **counts)
        )

    def _show_import_error(self, message: str) -> None:
        """Tell the user why the import did not run."""
        if self.self_test:
            self.last_import_error = message
            return
        self.last_import_error = message
        QMessageBox.warning(self.window, i18n.tr("menu.import"), message)

    def rename_path(self, src: str, dst: str) -> None:
        """Move/rename a path."""
        try:
            self.dispatch_ui(
                "vault.file_ops", {"op": "move", "src": self._api(src), "dst": self._api(dst)}
            )
        except VaultError as exc:
            QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return
        self.hub.notify()

    def delete_path(self, path: str) -> None:
        """Delete a path recursively."""
        try:
            self.dispatch_ui(
                "vault.file_ops",
                {"op": "delete", "src": self._api(path), "recursive": True},
            )
        except VaultError as exc:
            QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return
        self.hub.notify()

    def set_level(self, path: str, level: str) -> None:
        """Change a file's sensitivity level (lowering requires confirmation)."""
        try:
            current = self.stat(path).get("sensitivity", "normal")
        except VaultError:
            return
        order = {"normal": 0, "secret": 1, "secretfile": 2}
        if order.get(level, 0) < order.get(str(current), 0):
            choice = QMessageBox.question(
                self.window,
                i18n.tr("dialog.lower_level"),
                i18n.tr("dialog.lower_level_text", path=path, level=level),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if choice != QMessageBox.Yes:
                return
        try:
            self.dispatch_ui(
                "vault.set_sensitivity", {"path": self._api(path), "level": level}
            )
        except VaultError as exc:
            QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return
        self.hub.notify()

    def edit_tags(self, path: str) -> None:
        """Edit a file's tags through a simple comma-separated prompt."""
        from PySide6.QtWidgets import QInputDialog

        try:
            entry = self.stat(path)
        except VaultError:
            return
        current = ", ".join(entry.get("tags", []) or [])
        text, ok = QInputDialog.getText(
            self.window, i18n.tr("dialog.tags"), i18n.tr("dialog.tags_prompt"),
            text=current,
        )
        if not ok:
            return
        tags = [part.strip() for part in text.split(",") if part.strip()]
        try:
            self.dispatch_ui("vault.set_tags", {"path": self._api(path), "tags": tags})
        except VaultError as exc:
            QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return
        self.hub.notify()

    def remember_folder(self, path: str) -> None:
        """Persist the last selected folder in ``ui.json``."""
        self.config.last_folder = path
        self.config.save()

    def set_ui_option(self, key: str, value: Any) -> None:
        """Persist a UI-only preference (e.g. ``start_minimized``) in ``ui.json``."""
        self.config.data[key] = value
        try:
            self.config.save()
        except Exception:  # noqa: BLE001 - persistence is best effort
            pass
        if key == "start_minimized":
            self.start_minimized = bool(value)

    def verify_integrity(self) -> None:
        """Run blob verification and report the result."""
        try:
            result = self.dispatch_ui("vault.verify_blobs", {})
        except VaultError as exc:
            QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return
        QMessageBox.information(
            self.window,
            i18n.tr("menu.verify"),
            i18n.tr(
                "settings.verify_result",
                checked=result.get("checked", 0),
                bad=len(result.get("bad", [])),
            ),
        )

    def semantic_index_now(self) -> bool:
        """Rebuild the semantic index in the background (SPEC/01 §11).

        Embedding every note can take minutes, so it runs off the GUI thread with a busy
        indicator, exactly like the full-text rebuild.
        """
        if self.self_test:
            return True
        if self.session is None or self.session.is_locked:
            self._notify_web_problem(i18n.tr("error.VAULT_LOCKED"))
            return False
        if self.import_running:
            return False
        self.import_running = True
        adapter = SemanticProgress()
        self._show_semantic_progress(adapter)
        thread = threading.Thread(
            target=self._semantic_index_worker,
            args=(adapter,),
            name="vault-semantic",
            daemon=True,
        )
        thread.start()
        return True

    def _semantic_index_worker(self, adapter: SemanticProgress) -> None:
        """Run the semantic build off the GUI thread and report the result.

        The provider is resolved and the corpus embedded directly on the session (like
        the full-text rebuild), so the worker owns the progress callback and the GUI
        thread only polls it.
        """
        try:
            result = self.session.index_semantics(force=True, progress=adapter)
        except Exception as exc:  # noqa: BLE001 - report, never crash the UI
            payload: dict[str, Any] = {"error": error_message(exc)}
        else:
            payload = dict(result)
        adapter.progress["finished"] = True
        self.semantic_finished.emit(payload)

    def _show_semantic_progress(self, adapter: SemanticProgress) -> None:
        """Show a determinate progress bar while the embeddings are computed."""
        if self.self_test:
            return
        dialog = QProgressDialog(self.window)
        dialog.setWindowTitle(i18n.tr("menu.semantic_index"))
        dialog.setLabelText(i18n.tr("semantic.running"))
        dialog.setRange(0, 100)
        dialog.setValue(0)
        dialog.setCancelButton(None)
        dialog.setMinimumDuration(0)
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        dialog.show()
        self._import_progress = dialog
        self._import_importer = adapter
        self._import_started_at = time.monotonic()
        timer = QTimer(self)
        timer.setInterval(IMPORT_POLL_MS)
        timer.timeout.connect(self._poll_semantic_progress)
        timer.start()
        self._import_timer = timer

    def _poll_semantic_progress(self) -> None:
        """Show the embedding count/percentage plus a rough "time left" estimate."""
        dialog, importer = self._import_progress, self._import_importer
        if dialog is None or importer is None:
            return
        state = getattr(importer, "progress", None) or {}
        percent = max(0, min(100, int(state.get("percent") or 0)))
        done = int(state.get("done") or 0)
        total = int(state.get("total") or 0)
        dialog.setValue(percent)
        text = i18n.tr("semantic.progress", percent=percent, done=done, total=total)
        started = self._import_started_at or time.monotonic()
        elapsed = max(0.001, time.monotonic() - started)
        if 0 < done < total:
            remaining = (elapsed / done) * (total - done)
            text += " · " + i18n.tr("import.remaining", value=_format_duration(remaining))
        dialog.setLabelText(text)

    def _on_semantic_finished(self, payload: Any) -> None:
        """Close the indicator and tell the user how many files were indexed."""
        self._close_import_progress()
        self.import_running = False
        data = dict(payload or {})
        if data.get("error"):
            if self.self_test:
                self.last_import_error = str(data["error"])
            else:
                QMessageBox.warning(
                    self.window, i18n.tr("menu.semantic_index"), str(data["error"])
                )
            return
        self.hub.notify()
        notifications.notify(
            i18n.tr("menu.semantic_index"),
            i18n.tr("settings.semantic_indexed", count=int(data.get("indexed", 0))),
            tray=self.tray,
        )

    def open_settings(self) -> None:
        """Open the settings dialog."""
        if self.window is None:
            return
        dialog = SettingsDialog(self, self.window)
        dialog.exec()
        self.hub.notify()

    def open_log_file(self) -> None:
        """Open the daemon log file with the desktop handler."""
        path = Path.home() / ".local" / "state" / "secure-vault" / "daemon.log"
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def about(self) -> None:
        """Show the About dialog."""
        QMessageBox.about(
            self.window,
            i18n.tr("about.title"),
            i18n.tr("about.text", version=__version__),
        )

    # ------------------------------------------------------------------ language
    def set_language(self, lang: str) -> None:
        """Switch the UI language live and persist it."""
        self.language = lang
        i18n.set_language(lang)
        theme.apply(self.qapp, lang)
        self.config.language = lang
        try:
            self.config.save()
        except Exception:  # noqa: BLE001
            pass
        if self.unlock_screen is not None:
            self.unlock_screen.set_language(lang)
        if self.tray is not None:
            self.tray.retranslate()

    # ------------------------------------------------------------- secret flow
    def _on_secret_request(self, request: dict) -> str:
        """Called from the socket thread: marshal onto the Qt thread."""
        self.secret_requested.emit(dict(request))
        return "pending"

    def _show_secret_request(self, request: dict) -> None:
        """Show the non-modal secret-request dialog."""
        dialog = SecretRequestDialog(self.window, request, self._resolve_request)
        self._secret_dialogs.append(dialog)
        notifications.notify(
            i18n.tr("notification.secret_request"),
            "/" + str(request.get("path", "")).lstrip("/"),
            tray=self.tray,
        )
        dialog.show()

    def _resolve_request(self, request: dict, approved: bool) -> None:
        """Open the native viewer (when approved) and resolve the request."""
        path = "/" + str(request.get("path", "")).lstrip("/")
        if approved:
            try:
                content = self.read(path)
                viewer.open_viewer(self.window, path, content, tray=self.tray)
                self._log_secretfile(path)
            except VaultError as exc:
                if self.window is not None:
                    QMessageBox.warning(
                        self.window, i18n.tr("app.title"), error_message(exc)
                    )
        try:
            self.dispatch_ui(
                "vault.resolve_open_secret",
                {"request_id": request.get("request_id"), "approved": approved},
            )
        except Exception:  # noqa: BLE001 - the request may already be gone
            pass

    # ------------------------------------------------------------------ startup
    def _start_server(self) -> None:
        """Start the local socket server in the background."""
        try:
            runtime = runtime_dir()
            self.server = VaultSocketServer(self.service, runtime_dir=runtime)
            self.server.start()
        except AlreadyExists as exc:
            # Another process owns the socket: MCP calls go there and its activity never reaches
            # this tray. Say so instead of failing silently.
            self.server = None
            self.daemon_conflict = exc
            LOG.warning("daemon socket already served by another process: %s", exc)
        except Exception:  # noqa: BLE001 - no socket; the UI still works
            self.server = None

    # ---------------------------------------------------------------- web shell
    def web_settings(self) -> dict[str, Any]:
        """Return the effective ``web`` settings (defaults merged)."""
        settings = dict(WEB_DEFAULTS)
        try:
            raw = self.get_settings().get("web")
        except Exception:  # noqa: BLE001 - locked/absent vault uses the defaults
            raw = None
        if isinstance(raw, dict):
            settings.update(raw)
        return settings

    def _start_web(self) -> None:
        """Start the web UI in-process on the same session (SPEC/09 §A.1).

        Conflicts are never taken over: an existing ``web.token`` or a taken port
        leaves :attr:`web` as None and :attr:`web_conflict` True, and the tray's
        "open web UI" points at the already-running instance instead.
        """
        if self.service is None or self.web is not None:
            return
        settings = self.web_settings()
        if not bool(settings.get("enabled", True)):
            return
        host = str(settings.get("host") or "127.0.0.1")
        try:
            port = int(settings.get("port", 8788))
        except (TypeError, ValueError):
            port = 8788
        if self.self_test:
            # Headless self-tests must never fight over the default port.
            port = 0
        runtime = runtime_dir()
        stale = runtime / TOKEN_FILENAME
        if stale.exists():
            # A token file may be left behind by a crashed/stopped server: only treat it as a
            # live peer when its port actually answers, otherwise start our own server (and
            # remove the stale file, which would block us forever).
            if self._web_peer_alive():
                self.web_conflict = True
                LOG.warning(
                    "another web UI is already serving this vault (%s); not starting a second one",
                    stale,
                )
                return
            LOG.warning("removing a stale web token file: %s", stale)
            try:
                stale.unlink()
            except OSError:
                pass
        try:
            self.web = WebServer(self.service, host=host, port=port, runtime_dir=runtime)
            self.web.start()
        except OSError as exc:
            LOG.warning("could not start the in-process web UI on port %s: %s", port, exc)
            self.web = None
            self._web_error = i18n.tr("web.reason_port_busy", port=port)
            if port:
                # The configured port is taken by something that is not our web UI (a live
                # peer is handled above). Giving up here made both "open in browser" buttons
                # unusable, so take any free port instead.
                try:
                    self.web = WebServer(self.service, host=host, port=0, runtime_dir=runtime)
                    self.web.start()
                except OSError as exc2:
                    LOG.warning("could not start the in-process web UI at all: %s", exc2)
                    self.web = None
                    self._web_error = i18n.tr("web.reason_no_start")
                else:
                    self._web_error = None
                    LOG.info(
                        "web UI started on free port %s because %s was busy",
                        self.web.port,
                        port,
                    )
        if self.web is not None and bool(settings.get("open_browser_on_start")):
            self.open_web()

    def _sync_editor_web(self) -> None:
        """Tell the editor the effective web port and lock state."""
        if self.window is None:
            return
        locked = self.session is None or bool(self.session.is_locked)
        self.window.editor.web_port = self.web.port if self.web is not None else None
        self.window.editor.set_locked(locked)

    # ------------------------------------------------------- external editor
    def _external_editor(self) -> ExternalEditor | None:
        """Return (creating it lazily) the external-editor helper for this session."""
        if self.session is None:
            return None
        if self._external is None:
            self._external = ExternalEditor(
                self.session,
                runtime_dir=runtime_dir(),
                on_saved=self._on_external_saved,
                on_error=self._on_external_error,
            )
            self._external_timer = QTimer(self)
            self._external_timer.setInterval(EXTERNAL_POLL_MS)
            self._external_timer.timeout.connect(self._poll_external)
            self._external_timer.start()
        return self._external

    def _poll_external(self) -> None:
        """Push back edits made in the external editor (SPEC/08 §B.7b)."""
        if self._external is None:
            return
        saved = self._external.poll()
        if saved:
            self.hub.notify()

    def _on_external_saved(self, path: str) -> None:
        """Tell the user that the external editor's change went into the vault."""
        notifications.notify(
            i18n.tr("editor.open_text_editor"),
            i18n.tr("editor.external_saved") + " " + path,
            tray=self.tray,
        )

    def _on_external_error(self, message: str) -> None:
        """Show why the external editor could not be used."""
        notifications.notify(
            i18n.tr("editor.open_text_editor"), message, tray=self.tray
        )

    def open_in_text_editor(self, path: str) -> bool:
        """Open ``path`` in the OS default text editor with automatic write-back.

        Only ``normal`` files: a ``secret``/``secretfile`` path is refused with an explanation
        (its content is displayed solely by the native viewer with the Copy button).
        """
        if self.self_test:
            return True
        if self.session is None or self.session.is_locked:
            self._notify_web_problem(i18n.tr("editor.browser_locked"))
            return False
        helper = self._external_editor()
        if helper is None:
            return False
        # Read the level from the metadata index (never assume "normal": guessing wrong would
        # hand a secret file to an external process). The UI passes the API form ("/folder/x")
        # while the index stores the canonical form, so normalize first — without this every
        # click reported "not found".
        try:
            logical = normalize_vault_path(path)
            row = self.session.index.require_file(logical)
            sensitivity = str(row.get("sensitivity") or "normal")
        except Exception as exc:  # noqa: BLE001 - unknown path: refuse rather than guess
            LOG.warning("open_in_text_editor: %r is not in the index (%s)", path, exc)
            self._on_external_error(i18n.tr("editor.external_not_found", path=path))
            return False
        target = helper.open(logical, sensitivity=sensitivity)
        if target is None:
            return False
        notifications.notify(
            i18n.tr("editor.open_text_editor"),
            i18n.tr("editor.external_started") + "\n" + str(target),
            tray=self.tray,
        )
        return True

    def _web_peer_alive(self, timeout: float = 0.4) -> bool:
        """True when the token file points at a web UI that actually answers."""
        path = runtime_dir() / TOKEN_FILENAME
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            port = int(data.get("port") or WEB_DEFAULTS["port"])
            host = str(data.get("host") or WEB_DEFAULTS["host"])
        except (OSError, ValueError, TypeError):
            return False
        import socket as _socket

        try:
            with _socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def web_link(self) -> str | None:
        """Return the token URL of the running (or already-running) web UI.

        Never logged; the token is only ever handed to the clipboard/browser.
        """
        if self.web is not None:
            return f"{self.web.url}?token={self.web.token}"
        path = runtime_dir() / TOKEN_FILENAME
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        token = data.get("token")
        if not isinstance(token, str) or not token:
            return None
        port = data.get("port") or WEB_DEFAULTS["port"]
        host = WEB_DEFAULTS["host"]
        return f"http://{host}:{port}/?token={token}"

    def open_web(self) -> bool:
        """Open the web UI in the default browser (starting it if needed)."""
        if self.web is None and not self.web_conflict:
            self._start_web()
        link = self.web_link()
        if not link:
            notifications.notify(
                i18n.tr("tray.open_web"), i18n.tr("tray.web_unavailable"),
                tray=self.tray,
            )
            return False
        if self.self_test:
            return True
        QDesktopServices.openUrl(QUrl(link))
        return True

    def copy_web_link(self) -> bool:
        """Copy the token URL to the clipboard (one-time convenience, never logged)."""
        link = self.web_link()
        if not link:
            return False
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(link)
        notifications.notify(
            i18n.tr("tray.copy_link"), i18n.tr("notification.copied"), tray=self.tray
        )
        return True

    def open_in_browser(self, path: str) -> bool:
        """Open ``path`` in the web UI at its note route (SPEC/08 §B.7).

        The token must survive: the deep-link is ``<link>#/note/<path>`` where ``link`` already
        carries ``?token=…``. Dropping the token (as the first version did, by splitting on
        ``?``) opened a page that could not authenticate, which looked like "nothing happens".
        Failures are always reported — a silent ``False`` was the other half of that complaint.
        """
        if self.self_test:
            return True
        if self.session is None or self.session.is_locked:
            self._notify_web_problem(i18n.tr("editor.browser_locked"))
            return False
        if self.web is None and not self.web_conflict:
            self._start_web()
        link = self.web_link()
        if not link:
            self._notify_web_problem(self._web_unavailable_message())
            return False
        # Never open the same note twice from a double click (or a duplicated signal wiring).
        now = time.monotonic()
        if self._last_browser_open[0] == path and now - self._last_browser_open[1] < 1.5:
            return True
        self._last_browser_open = (str(path), now)
        url = link + "#/note/" + quote(str(path), safe="")
        if QDesktopServices.openUrl(QUrl(url)):
            return True
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(url)
        self._notify_web_problem(i18n.tr("editor.browser_copied"))
        return False

    def _web_unavailable_message(self) -> str:
        """Explain why the web UI could not be opened (with the recorded reason)."""
        reason = self._web_error or i18n.tr("web.reason_no_start")
        return i18n.tr("web.unavailable_reason", reason=reason)

    def _notify_web_problem(self, message: str) -> None:
        """Tell the user why the browser view did not open (never fail silently)."""
        LOG.info("web UI unavailable: %s", message)
        notifications.notify(i18n.tr("tray.open_web"), message, tray=self.tray)
        if self.window is not None and not self.self_test:
            QMessageBox.warning(self.window, i18n.tr("tray.open_web"), message)

    # ----------------------------------------------------------------- activity
    def _on_activity(self, event: dict) -> None:
        """Called from any thread: marshal the metadata event onto the Qt thread."""
        self.activity_reported.emit(dict(event))

    #: Minimum gap between two identical agent notifications (same source/kind/path).
    AGENT_NOTIFY_INTERVAL_MS = 1500

    def _notify_agent_access(self, event: dict) -> None:
        """Raise a desktop notification for an MCP/socket call (SPEC/09 §7)."""
        source = str(event.get("source", ""))
        kind = str(event.get("kind", ""))
        raw_path = event.get("path")
        path = "/" + str(raw_path).lstrip("/") if raw_path else ""
        key = (source, kind, path)
        now = now_ms()
        if now - self._agent_notified.get(key, 0) < self.AGENT_NOTIFY_INTERVAL_MS:
            return
        self._agent_notified[key] = now
        action = i18n.tr("web.activity_kind_" + kind)
        if action.startswith("web.activity_kind_"):
            action = kind
        body = i18n.tr("notification.agent_body", action=action, path=path)
        if event.get("tool"):
            body = i18n.tr("notification.agent_body_tool", tool=str(event["tool"]), path=path)
        notifications.notify(
            i18n.tr("notification.agent_title", source=source),
            body,
            tray=self.tray,
        )

    def _handle_activity(self, event: dict) -> None:
        """Update the feed, the tray badge/tooltip and the window status line."""
        self.activity.add(event)
        events = self.activity.events()
        if self.tray is not None:
            self.tray.set_activity(events)
        if (
            event.get("kind") == "read"
            and event.get("sensitivity") in ("secret", "secretfile")
        ):
            path = "/" + str(event.get("path", "")).lstrip("/")
            notifications.notify(
                i18n.tr("notification.secret_read"),
                i18n.tr(
                    "notification.secret_read_body",
                    path=path,
                    source=str(event.get("source", "")),
                ),
                tray=self.tray,
            )
        elif (
            str(event.get("source")) in ActivityFeed.AGENT_SOURCES
            and str(event.get("outcome", "allow")) != "error"
        ):
            self._notify_agent_access(event)
        if self.window is not None and event.get("kind") == "read":
            self.window.set_last_read(event)

    def _on_editor_direction(self, mode: str) -> None:
        """Persist the editor's bidi mode in ``ui.json`` (SPEC/08 §A.3)."""
        if mode not in ("auto", "rtl", "ltr"):
            return
        self.config.data["editor_direction"] = mode
        try:
            self.config.save()
        except Exception:  # noqa: BLE001 - persistence is best effort
            pass

    def tray_available(self) -> bool:
        """Return True when a system tray icon is active."""
        return bool(self.tray is not None and self.tray.available)

    def quit(self) -> None:
        """Shut everything down and quit the application."""
        self.shutdown()
        self.qapp.quit()

    def shutdown(self) -> None:
        """Stop timers, the server and the session."""
        self._auto_lock_timer.stop()
        if self.server is not None:
            try:
                self.server.stop()
            except Exception:  # noqa: BLE001
                pass
            self.server = None
        if self.web is not None:
            try:
                self.web.stop()
            except Exception:  # noqa: BLE001
                pass
            self.web = None
        if self.tray is not None:
            self.tray.hide()
        if self.window is not None:
            self.window.set_quitting(True)
        if self.session is not None:
            try:
                self.session.close()
            except Exception:  # noqa: BLE001
                pass


__all__ = ["VaultApplication", "SecretRequestDialog", "error_message", "AUTO_LOCK_TICK_MS"]
