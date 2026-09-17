"""Browser dock: folder tree, file list and the folder note (SPEC/03 §2.3)."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPlainTextEdit,
    QTableView,
    QToolBar,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from . import i18n
from .models import VaultListModel, VaultTreeModel

_NOTE_DEBOUNCE_MS = 1000


class BrowserPanel(QWidget):
    """The left dock: search, folder tree, file list and folder note."""

    file_activated = Signal(str)
    folder_selected = Signal(str)
    new_note_requested = Signal()
    new_folder_requested = Signal()
    import_requested = Signal()
    refresh_requested = Signal()
    lock_requested = Signal()
    settings_requested = Signal()

    def __init__(self, controller: Any, parent: Any = None) -> None:
        """Build the browser against ``controller``'s listing/note helpers."""
        super().__init__(parent)
        self._controller = controller
        self._current_folder = "/"
        self._loading_note = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.search_box = QLineEdit(self)
        layout.addWidget(self.search_box)

        self.toolbar = QToolBar(self)
        self.actions: dict[str, QAction] = {}
        for name, signal in (
            ("new_note", self.new_note_requested),
            ("new_folder", self.new_folder_requested),
            ("import", self.import_requested),
            ("refresh", self.refresh_requested),
            ("lock", self.lock_requested),
            ("settings", self.settings_requested),
        ):
            action = QAction(self)
            action.triggered.connect(signal.emit)
            self.toolbar.addAction(action)
            self.actions[name] = action
        layout.addWidget(self.toolbar)

        self.tree_model = VaultTreeModel(controller.list_entries, self)
        self.tree = QTreeView(self)
        self.tree.setModel(self.tree_model)
        self.tree.setHeaderHidden(False)
        self.tree.selectionModel().selectionChanged.connect(self._on_tree_selection)
        layout.addWidget(self.tree, 2)

        self.list_model = VaultListModel(self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.list_model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(0)
        self.proxy.setDynamicSortFilter(True)
        self.list = QTableView(self)
        self.list.setModel(self.proxy)
        self.list.setSelectionBehavior(QTableView.SelectRows)
        self.list.setEditTriggers(QTableView.NoEditTriggers)
        self.list.verticalHeader().setVisible(False)
        self.list.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.list.horizontalHeader().setStretchLastSection(True)
        self.list.doubleClicked.connect(self._on_file_activated)
        layout.addWidget(self.list, 3)

        self.note_box = QGroupBox(self)
        self.note_box.setCheckable(True)
        self.note_box.setChecked(True)
        note_layout = QVBoxLayout(self.note_box)
        self.note_edit = QPlainTextEdit(self.note_box)
        note_layout.addWidget(self.note_edit)
        layout.addWidget(self.note_box)

        self._note_timer = QTimer(self)
        self._note_timer.setSingleShot(True)
        self._note_timer.setInterval(_NOTE_DEBOUNCE_MS)
        self._note_timer.timeout.connect(self._save_note)
        self.note_edit.textChanged.connect(self._on_note_changed)
        self.search_box.textChanged.connect(self._on_search)
        self.note_box.toggled.connect(self.note_edit.setVisible)

        self.retranslate()
        i18n.bind(self, self.retranslate)

    # ------------------------------------------------------------------ folder
    @property
    def current_folder(self) -> str:
        """The currently selected folder (API-absolute)."""
        return self._current_folder

    def set_folder(self, path: str) -> None:
        """Select ``path`` and load its children and note."""
        self._current_folder = path or "/"
        try:
            entries = self._controller.list_entries(self._current_folder)
        except Exception:  # noqa: BLE001 - a locked/absent folder shows empty
            entries = []
        self.list_model.set_entries(entries)
        self._load_note()
        self.folder_selected.emit(self._current_folder)

    def refresh(self) -> None:
        """Reload the tree, the current folder and the note."""
        self.tree_model.refresh()
        self.set_folder(self._current_folder)

    def _on_tree_selection(self) -> None:
        """Load the folder for the selected tree item."""
        indexes = self.tree.selectionModel().selectedIndexes()
        if not indexes:
            return
        node = indexes[0].internalPointer()
        if node is None:
            return
        self.set_folder(node.path)

    def _on_file_activated(self, index: Any) -> None:
        """Emit the activated file path."""
        entry = self.list_model.entry_at(index)
        if entry is None or entry.get("is_dir"):
            return
        self.file_activated.emit(str(entry.get("path", "")))

    def _on_search(self, text: str) -> None:
        """Filter the file list by filename."""
        self.proxy.setFilterFixedString(text)

    # ------------------------------------------------------------------ note
    def _load_note(self) -> None:
        """Load the folder note for the current folder."""
        try:
            note = self._controller.folder_note(self._current_folder) or ""
        except Exception:  # noqa: BLE001 - locked vault has no readable note
            note = ""
        self._loading_note = True
        try:
            self.note_edit.setPlainText(note)
        finally:
            self._loading_note = False

    def _on_note_changed(self) -> None:
        """Schedule a debounced folder-note save."""
        if not self._loading_note:
            self._note_timer.start()

    def _save_note(self) -> None:
        """Persist the folder note."""
        try:
            self._controller.set_folder_note(
                self._current_folder, self.note_edit.toPlainText()
            )
        except Exception:  # noqa: BLE001 - best effort; a locked vault cannot save
            pass

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.search_box.setPlaceholderText(i18n.tr("browser.search_placeholder"))
        labels = {
            "new_note": "browser.new_note",
            "new_folder": "browser.new_folder",
            "import": "browser.import",
            "refresh": "browser.refresh",
            "lock": "browser.lock",
            "settings": "browser.settings",
        }
        for name, action in self.actions.items():
            action.setText(i18n.tr(labels[name]))
        self.note_box.setTitle(i18n.tr("browser.folder_note"))
        self.list_model.headerDataChanged.emit(Qt.Horizontal, 0, 3)


__all__ = ["BrowserPanel"]
