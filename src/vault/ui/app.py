"""Application controller and startup wiring (SPEC/03 §1, §2.5).

:class:`VaultApplication` owns the :class:`~vault.api.service.Service`, the socket
server, the windows, the tray and the auto-lock timer. All vault data operations go
through ``Service.dispatch(..., role="ui")``; the session object it is given is used
only for locking, the auto-lock clock and the agent secret-request flow.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QObject, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QDialog, QLabel, QMessageBox, QPushButton, QVBoxLayout

from .. import __version__
from ..api.service import Service
from ..api.socket_server import VaultSocketServer
from ..config import runtime_dir, user_config
from ..errors import Unauthorized, VaultError
from . import i18n, notifications, theme, viewer
from .main_window import MainWindow
from .models import DataHub
from .settings_dialog import SettingsDialog
from .tray import TrayIcon
from .unlock import UnlockScreen

AUTO_LOCK_TICK_MS = 1000


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
        self.show_button = QPushButton(i18n.tr("request.show"), self)
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
        self.hub = DataHub()
        self.window: MainWindow | None = None
        self.unlock_screen: UnlockScreen | None = None
        self.tray: TrayIcon | None = None
        self.current_screen = "none"
        self.confirm_hook: Callable[[str, str], bool] | None = None
        self._secret_dialogs: list[SecretRequestDialog] = []

        i18n.set_language(language)
        theme.apply(qapp, language)
        self.secret_requested.connect(self._show_secret_request)

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
            self._start_server()
        self._build_tray()
        self._build_main_window()
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
            self.hub.subscribe(self.window.log_panel.refresh)
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
            on_lock=self.lock,
            on_search=self._show_search,
            on_settings=self.open_settings,
            on_quit=self.quit,
        )
        self.tray.set_locked(not (self.session is None or self.session.is_locked))

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
        self.show_unlock()

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
        if level == "normal":
            content = self.read(api)
            self.window.editor.set_content(api, content, preview_enabled=True)
        elif level == "secret":
            if not self._confirm(level, api):
                return False
            content = self.read(api)
            self.window.editor.set_content(api, content, preview_enabled=False)
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

    def import_joplin(self) -> None:
        """Joplin import is delivered in P4; explain rather than fail."""
        QMessageBox.information(
            self.window, i18n.tr("menu.import"), i18n.tr("settings.import_unavailable")
        )

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

    def semantic_index_now(self) -> None:
        """Rebuild the semantic index and report the result."""
        try:
            result = self.dispatch_ui("vault.semantic_index", {"force": True})
        except VaultError as exc:
            QMessageBox.warning(self.window, i18n.tr("app.title"), error_message(exc))
            return
        QMessageBox.information(
            self.window,
            i18n.tr("menu.semantic_index"),
            i18n.tr("settings.semantic_indexed", count=result.get("indexed", 0)),
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
        except Exception:  # noqa: BLE001 - another daemon or no socket; UI still works
            self.server = None

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
