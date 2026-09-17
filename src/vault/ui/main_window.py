"""Main application window (SPEC/03 §2.3)."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QDockWidget,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QTabWidget,
)

from . import i18n
from .browser import BrowserPanel
from .editor import EditorPanel
from .log_panel import LogPanel
from .search_panel import SearchPanel

_LEVELS = ("normal", "secret", "secretfile")


class MainWindow(QMainWindow):
    """The post-unlock window: browser dock, editor and log/search docks."""

    def __init__(self, controller: Any, parent: Any = None) -> None:
        """Build the window against ``controller``."""
        super().__init__(parent)
        self.controller = controller
        self._current_path: str | None = None
        self._last_read: dict | None = None
        self._quitting = False
        self.setObjectName("main-window")
        self.resize(1180, 760)

        self.editor = EditorPanel(self)
        self.editor.save_requested.connect(self._on_save_requested)
        # NOTE: ``open_in_browser`` is wired once, in VaultApplication._build_main_window.
        # Wiring it here as well emitted two identical requests and opened two browser tabs.
        self.editor.open_text_editor.connect(controller.open_in_text_editor)
        self.setCentralWidget(self.editor)

        self.browser = BrowserPanel(controller, self)
        self.browser.file_activated.connect(self.open_file)
        self.browser.folder_selected.connect(self._on_folder_selected)
        self.browser.new_note_requested.connect(controller.new_note)
        self.browser.new_folder_requested.connect(controller.new_folder)
        self.browser.import_requested.connect(controller.import_joplin)
        self.browser.refresh_requested.connect(self.refresh)
        self.browser.lock_requested.connect(controller.lock)
        self.browser.settings_requested.connect(controller.open_settings)
        self.browser.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.browser.list.customContextMenuRequested.connect(self._show_file_menu)

        self.browser_dock = QDockWidget(self)
        self.browser_dock.setObjectName("browser-dock")
        self.browser_dock.setWidget(self.browser)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.browser_dock)

        self.right_tabs = QTabWidget(self)
        self.log_panel = LogPanel(controller.dispatch_ui, self.right_tabs)
        self.search_panel = SearchPanel(controller.dispatch_ui, self.right_tabs)
        self.search_panel.result_activated.connect(self.open_file)
        self.right_tabs.addTab(self.log_panel, "")
        self.right_tabs.addTab(self.search_panel, "")
        self.right_dock = QDockWidget(self)
        self.right_dock.setObjectName("right-dock")
        self.right_dock.setWidget(self.right_tabs)
        self.addDockWidget(Qt.RightDockWidgetArea, self.right_dock)

        self._build_status_bar()
        self._build_menus()

        self.browser.set_folder("/")
        self.refresh()
        self.retranslate()
        i18n.bind(self, self.retranslate)

    # ------------------------------------------------------------------ status
    def _build_status_bar(self) -> None:
        """Create the four status-bar labels."""
        self.lock_label = QLabel(self)
        self.path_label = QLabel(self)
        self.count_label = QLabel(self)
        self.mcp_label = QLabel(self)
        bar = self.statusBar()
        # Inside a Persian window the mixed Latin/Persian pieces must not be re-ordered by the
        # bidi algorithm, which is what made the bar look scrambled.
        bar.setLayoutDirection(
            Qt.LayoutDirection.RightToLeft
            if i18n.lang == "fa"
            else Qt.LayoutDirection.LeftToRight
        )
        bar.addWidget(self.lock_label)
        bar.addWidget(self.path_label, 1)
        bar.addPermanentWidget(self.count_label)
        bar.addPermanentWidget(self.mcp_label)

    def refresh_status(self) -> None:
        """Refresh the status bar from ``vault.status``."""
        try:
            status = self.controller.dispatch_ui("vault.status", {})
        except Exception:  # noqa: BLE001 - locked/absent vault still shows a bar
            status = {}
        locked = bool(status.get("locked", True))
        self.lock_label.setText(
            i18n.tr("status.locked" if locked else "status.unlocked")
        )
        self.path_label.setText("\u200e" + str(self.controller.vault_home) + "\u200e")
        self.count_label.setText(i18n.tr("status.files", count=status.get("files", 0)))
        try:
            connections = int(self.controller.connection_count())
        except Exception:  # noqa: BLE001
            connections = 0
        # LRM around the Latin-only fragments keeps them intact inside the RTL sentence.
        text = "\u200e" + i18n.tr("status.mcp", count=connections) + "\u200e"
        if self._last_read is not None and self._last_read.get("path"):
            path = "/" + str(self._last_read["path"]).lstrip("/")
            text += " · " + i18n.tr("status.last_read", path="\u200e" + path + "\u200e")
        self.mcp_label.setText(text)

    def set_last_read(self, event: dict) -> None:
        """Remember the last read event and refresh the status line (SPEC/09 §8)."""
        self._last_read = dict(event)
        self.refresh_status()

    # ------------------------------------------------------------------ menus
    def _build_menus(self) -> None:
        """Build the menu bar and shortcuts."""
        self.actions: dict[str, QAction] = {}
        self._menus: dict[str, Any] = {}

        def add(menu: Any, name: str, shortcut: str | None, slot: Any,
                checkable: bool = False) -> QAction:
            action = QAction(self)
            if shortcut:
                action.setShortcut(QKeySequence(shortcut))
            action.setCheckable(checkable)
            action.triggered.connect(slot)
            menu.addAction(action)
            self.actions[name] = action
            return action

        file_menu = self.menuBar().addMenu("")
        self._menus["file"] = file_menu
        add(file_menu, "new_note", "Ctrl+N", self.controller.new_note)
        add(file_menu, "new_folder", None, self.controller.new_folder)
        add(file_menu, "import", None, self.controller.import_joplin)
        file_menu.addSeparator()
        save_action = add(file_menu, "save", "Ctrl+S", self.editor.save)
        add(file_menu, "browser_edit", None, self._open_current_in_browser)
        file_menu.addSeparator()
        add(file_menu, "lock", "Ctrl+L", self.controller.lock)
        add(file_menu, "quit", "Ctrl+Q", self.controller.quit)

        edit_menu = self.menuBar().addMenu("")
        self._menus["edit"] = edit_menu
        edit_menu.addAction(save_action)
        add(edit_menu, "find", "Ctrl+F", lambda: self.search_panel.focus_query())

        view_menu = self.menuBar().addMenu("")
        self._menus["view"] = view_menu
        add(view_menu, "browser_dock", None,
            lambda checked: self.browser_dock.setVisible(checked), checkable=True)
        self.actions["browser_dock"].setChecked(True)
        add(view_menu, "right_dock", None,
            lambda checked: self.right_dock.setVisible(checked), checkable=True)
        self.actions["right_dock"].setChecked(True)
        add(view_menu, "preview", None,
            lambda checked: self.editor.set_preview_enabled(checked), checkable=True)
        self.actions["preview"].setChecked(True)

        tools_menu = self.menuBar().addMenu("")
        self._menus["tools"] = tools_menu
        add(tools_menu, "settings", None, self.controller.open_settings)
        add(tools_menu, "verify", None, self.controller.verify_integrity)
        add(tools_menu, "semantic_index", None, self.controller.semantic_index_now)

        help_menu = self.menuBar().addMenu("")
        self._menus["help"] = help_menu
        add(help_menu, "about", None, self.controller.about)
        add(help_menu, "open_log", None, self.controller.open_log_file)

    # ------------------------------------------------------------------ files
    @property
    def tree_model(self) -> Any:
        """Return the browser tree model (smoke-test convenience)."""
        return self.browser.tree_model

    def current_path(self) -> str | None:
        """Return the path currently shown in the editor (or viewer)."""
        return self._current_path

    def set_current_path(self, path: str | None) -> None:
        """Remember and display the current file path."""
        self._current_path = path
        if path:
            self.statusBar().showMessage(path, 4000)

    def open_file(self, path: str) -> bool:
        """Open ``path`` after guarding unsaved changes."""
        if not self.guard_unsaved():
            return False
        result = self.controller.open_path(path)
        if result:
            self.set_current_path(path)
        return bool(result)

    def guard_unsaved(self) -> bool:
        """Return True when it is safe to replace the editor content."""
        if not self.editor.is_dirty():
            return True
        choice = QMessageBox.question(
            self,
            i18n.tr("editor.unsaved_title"),
            i18n.tr("editor.unsaved_text"),
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
            QMessageBox.Save,
        )
        if choice == QMessageBox.Save:
            self.editor.save()
            return True
        if choice == QMessageBox.Discard:
            return True
        return False

    def refresh(self) -> None:
        """Refresh the browser and the status bar."""
        self.browser.refresh()
        self.refresh_status()

    def _open_current_in_browser(self) -> None:
        """Open the current note in the web UI (SPEC/08 §B.7)."""
        path = self._current_path or self.editor.current_path
        if path:
            self.controller.open_in_browser(path)

    def _on_folder_selected(self, path: str) -> None:
        """Remember the selected folder in the user config."""
        try:
            self.controller.remember_folder(path)
        except Exception:  # noqa: BLE001 - persistence is best effort
            pass

    def _on_save_requested(self, path: str, text: str) -> None:
        """Persist an editor save through the controller."""
        try:
            self.controller.save_file(path, text)
        except Exception as exc:  # noqa: BLE001 - show a friendly error
            QMessageBox.warning(self, i18n.tr("editor.save_failed"), str(exc))
            return
        self.editor.mark_saved()
        self.refresh_status()
        self.log_panel.refresh()

    # ------------------------------------------------------------------ context
    def _show_file_menu(self, position: Any) -> None:
        """Show the per-file context menu."""
        index = self.browser.list.indexAt(position)
        entry = self.browser.list_model.entry_at(index)
        if entry is None:
            return
        path = str(entry.get("path", ""))
        level = str(entry.get("sensitivity", "normal"))
        menu = QMenu(self)
        menu.addAction(i18n.tr("menu.open"), lambda: self.open_file(path))
        if level in ("secret", "secretfile"):
            menu.addAction(
                i18n.tr("menu.open_native"), lambda: self.controller.open_path(path)
            )
        menu.addSeparator()
        # The two "work on this note elsewhere" entry points (SPEC/08 §B).
        menu.addAction(
            i18n.tr("editor.edit_in_browser"),
            lambda: self.controller.open_in_browser(path),
        )
        if level == "normal":
            menu.addAction(
                i18n.tr("editor.open_text_editor"),
                lambda: self.controller.open_in_text_editor(path),
            )
        menu.addSeparator()
        menu.addAction(i18n.tr("menu.rename"), lambda: self._rename(path))
        menu.addAction(i18n.tr("menu.delete"), lambda: self._delete(path))
        menu.addAction(
            i18n.tr("menu.copy_path"),
            lambda: QGuiApplication.clipboard().setText(path),
        )
        level_menu = menu.addMenu(i18n.tr("menu.set_level"))
        for name in _LEVELS:
            level_menu.addAction(
                i18n.tr(f"level.{name}"),
                lambda _checked=False, value=name: self.controller.set_level(path, value),
            )
        menu.addAction(i18n.tr("menu.tags"), lambda: self.controller.edit_tags(path))
        menu.exec(self.browser.list.viewport().mapToGlobal(position))

    def _rename(self, path: str) -> None:
        """Prompt for a new name and rename the file."""
        name, ok = QInputDialog.getText(
            self, i18n.tr("dialog.rename"), i18n.tr("dialog.rename_prompt")
        )
        if not ok or not name.strip():
            return
        parent = path.rsplit("/", 1)[0] if "/" in path.strip("/") else ""
        destination = f"{parent}/{name.strip()}" if parent else f"/{name.strip()}"
        self.controller.rename_path(path, destination)

    def _delete(self, path: str) -> None:
        """Confirm and delete a path."""
        choice = QMessageBox.question(
            self,
            i18n.tr("dialog.delete"),
            i18n.tr("dialog.delete_confirm", path=path),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if choice == QMessageBox.Yes:
            self.controller.delete_path(path)

    # ------------------------------------------------------------------ close
    def set_quitting(self, quitting: bool) -> None:
        """Mark that the app is quitting (so close is not a hide-to-tray)."""
        self._quitting = bool(quitting)

    def closeEvent(self, event: Any) -> None:  # noqa: N802 - Qt naming
        """Guard unsaved changes, then hide to the tray unless the app is quitting."""
        if not self.guard_unsaved():
            event.ignore()
            return
        if not self._quitting and self.controller.tray_available():
            self.hide()
            event.ignore()
            return
        event.accept()

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings to menus, docks and status bar."""
        self.setWindowTitle(i18n.tr("app.title"))
        self.browser_dock.setWindowTitle(i18n.tr("browser.title"))
        self.right_dock.setWindowTitle(i18n.tr("right.title"))
        self.right_tabs.setTabText(0, i18n.tr("log.tab"))
        self.right_tabs.setTabText(1, i18n.tr("search.tab"))
        self._menus["file"].setTitle(i18n.tr("menu.file"))
        self._menus["edit"].setTitle(i18n.tr("menu.edit"))
        self._menus["view"].setTitle(i18n.tr("menu.view"))
        self._menus["tools"].setTitle(i18n.tr("menu.tools"))
        self._menus["help"].setTitle(i18n.tr("menu.help"))
        labels = {
            "new_note": "menu.new_note",
            "new_folder": "menu.new_folder",
            "import": "menu.import",
            "save": "menu.save",
            "browser_edit": "menu.browser_edit",
            "lock": "menu.lock",
            "quit": "menu.quit",
            "find": "menu.find",
            "browser_dock": "menu.browser_dock",
            "right_dock": "menu.right_dock",
            "preview": "menu.preview",
            "settings": "menu.settings",
            "verify": "menu.verify",
            "semantic_index": "menu.semantic_index",
            "about": "menu.about",
            "open_log": "menu.open_log",
        }
        for name, action in self.actions.items():
            if name in labels:
                action.setText(i18n.tr(labels[name]))
        self.refresh_status()


__all__ = ["MainWindow"]
