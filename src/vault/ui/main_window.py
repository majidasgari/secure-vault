"""Main application window (SPEC/03 §2.3)."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QByteArray, Qt, QTimer
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QDockWidget,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
)

from . import bidi, i18n, image_view
from .browser import BrowserPanel
from .editor import EditorPanel
from .learning_panel import LearningPanel
from .log_panel import LogPanel
from .search_panel import SearchPanel

_LEVELS = ("normal", "secret", "secretfile")

#: The four side panels, in their default tab order. Each is a dock of its own: any of them can
#: be dragged to another edge or stacked, and two docks in one place become a tab group.
PANELS = (
    ("browser", "browser.title"),
    ("search", "search.tab"),
    ("learning", "learn.title"),
    ("log", "log.tab"),
)



def _unhex(value: Any) -> bytes | None:
    """Decode a hex string written by :meth:`MainWindow.layout_state` (None when unusable)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


class MainWindow(QMainWindow):
    """The post-unlock window: browser dock, editor and log/search docks."""

    def __init__(self, controller: Any, parent: Any = None) -> None:
        """Build the window against ``controller``."""
        super().__init__(parent)
        self.controller = controller
        self._current_path: str | None = None
        self._last_read: dict | None = None
        self._quitting = False
        #: A remembered side-dock width waiting for the window to be shown (see apply_dock_width).
        self._dock_width: int | None = None
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
        # «همگام‌سازی» is a toolbar button as well as a Tools item: the one action of the two that
        # people look for by eye, and it used to be reachable only from the menu.
        self.browser.sync_requested.connect(controller.sync_now)
        self.browser.lock_requested.connect(controller.lock)
        self.browser.settings_requested.connect(controller.open_settings)
        self.browser.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.browser.list.customContextMenuRequested.connect(self._show_file_menu)
        # The tree lists folders without their parent being open, so it needs the same
        # rename/delete entry points; without a menu here they were unreachable exactly where
        # a folder is easiest to find.
        self.browser.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.browser.tree.customContextMenuRequested.connect(self._show_tree_menu)

        self.log_panel = LogPanel(controller.dispatch_ui, self)
        self.search_panel = SearchPanel(controller.dispatch_ui, self)
        self.search_panel.result_activated.connect(self.open_file)
        self.learning_panel = LearningPanel(controller.dispatch_ui, self)
        self.learning_panel.open_requested.connect(self.open_file)
        # One dock per panel. They start as one tab group on the right (the everyday pane first,
        # then search, the learning cards and last the access log), but each is an independent
        # dock: drag it anywhere, or drop it on another one to get a tab group of just those two.
        self.dock_panels: dict[str, Any] = {
            "browser": self.browser,
            "search": self.search_panel,
            "learning": self.learning_panel,
            "log": self.log_panel,
        }
        self.docks: dict[str, QDockWidget] = {}
        #: Which panel's tab is raised (kept here: `saveState` does not record the active tab).
        self._raised_panel = "browser"
        self.setDockNestingEnabled(True)
        self.setDockOptions(
            QMainWindow.DockOption.AllowNestedDocks
            | QMainWindow.DockOption.AllowTabbedDocks
            | QMainWindow.DockOption.AnimatedDocks
        )
        first: QDockWidget | None = None
        for name, _key in PANELS:
            dock = QDockWidget(self)
            dock.setObjectName(f"panel-{name}")
            dock.setWidget(self.dock_panels[name])
            dock.setAllowedAreas(Qt.AllDockWidgetAreas)
            dock.setFeatures(
                QDockWidget.DockWidgetFeature.DockWidgetMovable
                | QDockWidget.DockWidgetFeature.DockWidgetFloatable
                | QDockWidget.DockWidgetFeature.DockWidgetClosable
            )
            self.addDockWidget(Qt.RightDockWidgetArea, dock)
            if first is None:
                first = dock
            else:
                self.tabifyDockWidget(first, dock)
            dock.visibilityChanged.connect(
                lambda visible, panel=name: self._on_dock_visibility(panel, visible)
            )
            self.docks[name] = dock
        first.setVisible(True)
        first.raise_()

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
        self.sync_label = QLabel(self)
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
        bar.addPermanentWidget(self.sync_label)
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
        self.path_label.setText(bidi.ltr_isolate(str(self.controller.vault_home)))
        self.count_label.setText(i18n.tr("status.files", count=status.get("files", 0)))
        sync = status.get("sync") or {}
        journal = (sync.get("mode") or "legacy") == "journal"
        # Each mode's actions are meaningless in the other one: no lock or mirror in journal
        # mode (docs/SYNC.md §11).
        for name, shown in (
            ("sync", not journal),
            ("migrate_sync", not journal),
            ("take_control", not journal),
            ("sync_journal", journal),
            ("conflicts", journal),
        ):
            if name in self.actions:
                self.actions[name].setVisible(shown)
        if not sync.get("configured"):
            sync_text = i18n.tr("status.sync_off")
        elif sync.get("readonly"):
            sync_text = i18n.tr("status.sync_readonly")
        elif sync.get("last_error"):
            sync_text = i18n.tr("status.sync_error")
        else:
            sync_text = i18n.tr("status.sync_owned")
        self.sync_label.setText(bidi.ltr_isolate(sync_text))
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
        # One checkable entry per panel, backed by the dock's own toggle action: closing a panel
        # with its ✕ unchecks the entry by itself, and the panel can be brought back from here.
        for name, _key in PANELS:
            action = self.docks[name].toggleViewAction()
            view_menu.addAction(action)
            self.actions[f"{name}_dock"] = action

        tools_menu = self.menuBar().addMenu("")
        self._menus["tools"] = tools_menu
        add(tools_menu, "settings", None, self.controller.open_settings)
        add(tools_menu, "verify", None, self.controller.verify_integrity)
        add(tools_menu, "semantic_index", None, self.controller.semantic_index_now)
        tools_menu.addSeparator()
        add(tools_menu, "sync", None, self.controller.sync_now)
        add(tools_menu, "sync_journal", None, self.controller.sync_journal_now)
        add(tools_menu, "migrate_sync", None, self.controller.migrate_sync)
        add(tools_menu, "conflicts", None, self.controller.show_conflicts)
        add(tools_menu, "take_control", None, self.controller.take_write_access)

        help_menu = self.menuBar().addMenu("")
        self._menus["help"] = help_menu
        add(help_menu, "about", None, self.controller.about)
        add(help_menu, "open_log", None, self.controller.open_log_file)

    def _on_dock_visibility(self, panel: str, visible: bool) -> None:
        """Remember which panel's tab is raised (the winner of a tab group)."""
        if visible:
            self._raised_panel = panel

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

    def open_image(self, path: str, data: bytes, *, sensitivity: str = "normal",
                   note: str = "") -> None:
        """Show a picture from the vault in the native viewer (SPEC/03 §2.4, §10)."""
        previous = getattr(self, "image_viewer", None)
        if previous is not None:
            try:
                previous.close()
            except RuntimeError:  # noqa: BLE001 - already gone
                pass
        self.image_viewer = image_view.open_image(
            self, path, data, sensitivity=sensitivity, tray=self.controller.tray
        )
        if note:
            self.image_viewer.setToolTip(note)

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

    def refresh_theme(self) -> None:
        """Repaint everything that carries theme colours itself (SPEC/03 §10)."""
        for holder in (self.editor, getattr(self, "image_viewer", None)):
            if holder is None:
                continue
            for name in ("apply_theme",):
                method = getattr(holder, name, None)
                if callable(method):
                    try:
                        method()
                    except Exception:  # noqa: BLE001 - cosmetic
                        pass
        for view in (getattr(self.browser, "note_edit", None),):
            if view is not None:
                try:
                    view.viewport().update()
                except Exception:  # noqa: BLE001 - cosmetic
                    pass

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

    # ---------------------------------------------------------------- learning
    def learning_card(self, path: str) -> dict | None:
        """Return the learning card for ``path`` (None when the note is not in the cycle)."""
        try:
            listing = self.controller.dispatch_ui("vault.learning_list", {})
        except Exception:  # noqa: BLE001 - a locked vault has no cycle to read
            return None
        for card in (listing.get("due") or []) + (listing.get("upcoming") or []):
            if card.get("path") == path:
                return card
        return None

    def _toggle_learning(self, path: str, in_cycle: bool) -> None:
        """Add a note to its learning cycle, or show the cards when it is already in one."""
        if in_cycle:
            self.show_learning()
            return
        try:
            self.controller.dispatch_ui("vault.learning_start", {"path": path})
        except Exception as exc:  # noqa: BLE001 - report it, never crash a menu action
            QMessageBox.warning(self, i18n.tr("learn.title"), str(exc))
            return
        self.learning_panel.refresh()
        self.statusBar().showMessage(i18n.tr("learn.added"), 4000)

    def show_panel(self, name: str) -> None:
        """Reveal one panel and raise its tab, wherever the user has put it."""
        dock = self.docks.get(name)
        if dock is None:
            return
        if dock.isHidden():
            dock.setVisible(True)
        dock.raise_()
        self._raised_panel = name

    def show_browser(self) -> None:
        """Reveal the browser panel (the tree, the file list and their notes)."""
        self.show_panel("browser")

    def show_search(self) -> None:
        """Reveal the search panel and put the caret in its query box."""
        self.show_panel("search")
        self.search_panel.focus_query()

    def show_learning(self) -> None:
        """Reveal the learning panel and refresh its cards."""
        self.show_panel("learning")
        self.learning_panel.refresh()

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
        if image_view.looks_like_image(path):
            menu.addAction(
                i18n.tr("menu.view_image"), lambda: self.controller.open_path(path)
            )
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
        menu.addAction(i18n.tr("menu.emoji"), lambda: self.controller.edit_emoji(path))
        menu.addAction(i18n.tr("menu.tags"), lambda: self.controller.edit_tags(path))
        # The learning cycle is reached from the note it belongs to, and from the View menu when
        # no row is selected. A folder is never a card, so the action is not offered for one.
        if not entry.get("is_dir"):
            in_cycle = self.learning_card(path) is not None
            menu.addAction(
                i18n.tr("learn.in_progress" if in_cycle else "learn.start"),
                lambda: self._toggle_learning(path, in_cycle),
            )
        menu.exec(self.browser.list.viewport().mapToGlobal(position))

    def tree_menu(self, path: str) -> QMenu:
        """Build the folder context menu for ``path`` (shown by `_show_tree_menu`).

        Kept separate from the showing so a test can read the actions, and so the tree's menu
        and the file list's menu can drift only on purpose.
        """
        menu = QMenu(self)
        menu.addAction(i18n.tr("menu.open"), lambda: self.browser.set_folder(path))
        menu.addAction(i18n.tr("menu.new_note"), lambda: self.controller.new_note())
        menu.addSeparator()
        menu.addAction(i18n.tr("menu.rename"), lambda: self._rename(path))
        menu.addAction(
            i18n.tr("menu.delete_folder"), lambda: self._delete(path, is_dir=True)
        )
        menu.addAction(
            i18n.tr("menu.copy_path"),
            lambda: QGuiApplication.clipboard().setText(path),
        )
        return menu

    def _show_tree_menu(self, position: Any) -> None:
        """Show the folder context menu for the tree (the file list has `_show_file_menu`)."""
        index = self.browser.tree.indexAt(position)
        node = index.internalPointer() if index.isValid() else None
        path = str(getattr(node, "path", "") or "")
        if not path:
            return
        self.tree_menu(path).exec(self.browser.tree.viewport().mapToGlobal(position))

    def _rename(self, path: str) -> None:
        """Prompt for a new name and rename the file.

        The current name is filled in: renaming a picture or an attachment (a hash-named file)
        by retyping the whole name from an empty box was the wrong way round.
        """
        current = str(path).rstrip("/").rsplit("/", 1)[-1]
        name, ok = QInputDialog.getText(
            self, i18n.tr("dialog.rename"), i18n.tr("dialog.rename_prompt"), text=current
        )
        if not ok or not name.strip() or name.strip() == current:
            return
        parent = path.rsplit("/", 1)[0] if "/" in path.strip("/") else ""
        destination = f"{parent}/{name.strip()}" if parent else f"/{name.strip()}"
        result = self.controller.rename_path(path, destination)
        if not result:
            return
        # The open note follows its own rename, and the notes that linked to the file were
        # rewritten by the vault itself — say how many, or the change looks like it did nothing.
        if self._current_path == path:
            self.set_current_path(destination)
        updated = int(result.get("references_updated") or 0)
        if updated:
            self.statusBar().showMessage(i18n.tr("dialog.renamed_refs", count=updated), 6000)

    def _delete(self, path: str, *, is_dir: bool = False) -> None:
        """Confirm and delete a path (a folder's confirmation says it takes its contents)."""
        message_key = "dialog.delete_folder_confirm" if is_dir else "dialog.delete_confirm"
        choice = QMessageBox.question(
            self,
            i18n.tr("dialog.delete"),
            i18n.tr(message_key, path=path),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if choice == QMessageBox.Yes:
            self.controller.delete_path(path)

    # ------------------------------------------------------------------ layout
    def layout_state(self) -> dict[str, Any]:
        """Return the arrangement the user has set (geometry, dock layout, open panels).

        Everything the user can rearrange is captured here, so the next start looks the way
        they left it instead of snapping back to a built-in default.
        """
        state: dict[str, Any] = {
            # Each dock's *own* shown/hidden flag: `isHidden()` is False while the whole window
            # is hidden to the tray, which is when this is usually written.
            "docks": {name: not dock.isHidden() for name, dock in self.docks.items()},
            "dock_raised": self._raised_panel,
        }
        # `saveState()` alone did not bring the side area's width back, and a hidden dock has no
        # width of its own to remember — so the number is kept only while a panel is on screen.
        width_dock = self._width_dock()
        if width_dock is not None and not width_dock.isHidden() and width_dock.width() > 0:
            state["right_width"] = int(width_dock.width())
        # The file table's column layout travels as percentages: one arrangement for every folder.
        ratios = self.browser.column_ratios()
        if ratios:
            state["columns"] = ratios
        try:
            state["geometry"] = bytes(self.saveGeometry().data()).hex()
            state["state"] = bytes(self.saveState().data()).hex()
        except Exception:  # noqa: BLE001 - a missing geometry is not worth a failure
            pass
        return state

    def _width_dock(self) -> QDockWidget | None:
        """Return the panel whose width stands for the side area (browser first)."""
        for name, _key in PANELS:
            dock = self.docks[name]
            if not dock.isHidden():
                return dock
        return self.docks.get("browser")

    def save_layout(self) -> None:
        """Persist the arrangement into ``ui.json`` (best effort, never raises)."""
        try:
            config = getattr(self.controller, "config", None)
            if config is None:
                return
            config.window = self.layout_state()
            config.save()
        except Exception:  # noqa: BLE001 - persistence is best effort
            pass

    def restore_layout(self, saved: Any) -> bool:
        """Apply a saved arrangement; return True when anything could be restored."""
        if not isinstance(saved, dict):
            return False
        restored = False
        geometry = _unhex(saved.get("geometry"))
        if geometry:
            restored = bool(self.restoreGeometry(QByteArray(geometry))) or restored
        dock_state = _unhex(saved.get("state"))
        if dock_state and self.restoreState(QByteArray(dock_state)):
            restored = True
        # ``restoreState`` restores positions, sizes and tab groups but not whether a dock is
        # closed, so those flags are applied here.
        flags = saved.get("docks")
        if isinstance(flags, dict):
            for name, dock in self.docks.items():
                visible = flags.get(name)
                if isinstance(visible, bool) and visible != (not dock.isHidden()):
                    dock.setVisible(visible)
                    restored = True
        elif isinstance(saved.get("right_dock"), bool):
            # A layout written before the panels became docks: one flag for the whole side area,
            # one tab index — map both onto the four panels it used to hold.
            visible = bool(saved["right_dock"])
            for dock in self.docks.values():
                if visible != (not dock.isHidden()):
                    dock.setVisible(visible)
            restored = True
            tab = saved.get("right_tab")
            if isinstance(tab, int) and 0 <= tab < len(PANELS):
                self.show_panel(PANELS[tab][0])
        raised = saved.get("dock_raised")
        if isinstance(raised, str) and raised in self.docks:
            self.show_panel(raised)
            restored = True
        width = saved.get("right_width")
        if isinstance(width, int) and width > 0:
            self.apply_dock_width(width)
            restored = True
        if self.browser.set_column_ratios(saved.get("columns")):
            restored = True
        return restored

    def apply_dock_width(self, width: int) -> None:
        """Bring the side area back to a remembered width.

        ``resizeDocks`` is silently ignored until the window has been laid out and shown once, which
        is why the width used to come back as the dock's own minimum: the value is kept for the
        first ``showEvent`` and applied there.
        """
        width = int(width)
        if width <= 0:
            return
        if self.isVisible():
            self._apply_dock_width(width)
        else:
            #: Read and cleared by showEvent — a later drag must win over a startup width.
            self._dock_width = width

    def _apply_dock_width(self, width: int) -> None:
        """The one call that actually resizes the docks (never raises: a width is cosmetic)."""
        docks = [
            dock for dock in self.docks.values()
            if not dock.isHidden() and self.dockWidgetArea(dock) == Qt.RightDockWidgetArea
        ] or ([self._width_dock()] if self._width_dock() is not None else [])
        try:
            self.resizeDocks(docks, [int(width)] * len(docks), Qt.Horizontal)
        except Exception:  # noqa: BLE001 - a remembered width is cosmetic
            pass

    def showEvent(self, event: Any) -> None:  # noqa: N802 - Qt API
        """Apply a remembered dock width once the layout is live, then forget it.

        ``resizeDocks`` does nothing before the first show, so this is the earliest moment the
        width sticks; the value is dropped afterwards so a later drag by the user wins.
        """
        super().showEvent(event)
        width, self._dock_width = self._dock_width, None
        if width:
            QTimer.singleShot(0, lambda: self._apply_dock_width(width))

    # ------------------------------------------------------------------ close
    def hideEvent(self, event: Any) -> None:  # noqa: N802 - Qt API
        """Remember the arrangement whenever the window goes away (tray, lock, minimise)."""
        self.save_layout()
        super().hideEvent(event)

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
        for name, key in PANELS:
            dock = self.docks[name]
            dock.setWindowTitle(i18n.tr(key))
            action = self.actions.get(f"{name}_dock")
            if action is not None:
                # The toggle action's text was fixed to the old title when it was created.
                action.setText(i18n.tr(key))
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
            "settings": "menu.settings",
            "verify": "menu.verify",
            "semantic_index": "menu.semantic_index",
            "sync": "menu.sync",
            "sync_journal": "menu.sync_journal",
            "migrate_sync": "menu.migrate_sync",
            "conflicts": "menu.conflicts",
            "take_control": "tray.take_control",
            "about": "menu.about",
            "open_log": "menu.open_log",
        }
        for name, action in self.actions.items():
            if name in labels:
                action.setText(i18n.tr(labels[name]))
        self.refresh_status()


__all__ = ["MainWindow"]
