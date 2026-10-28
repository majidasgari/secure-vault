"""Browser dock: folder tree, file list and the folder note (SPEC/03 §2.3)."""

from __future__ import annotations

import time
from typing import Any

from PySide6.QtCore import QEvent, QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QPixmap
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QTableView,
    QToolBar,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from . import i18n, image_view
from .models import VaultListModel, VaultTreeModel

#: Narrowest the name column may get: below this the rows turn into a single word per line.
_MIN_NAME_WIDTH = 96

def _clean_ratios(value: Any) -> tuple[float, ...] | None:
    """Validate a remembered column layout: one positive fraction per column, normalised to one."""
    if not isinstance(value, (list, tuple)) or len(value) != VaultListModel.COLUMN_NOTE + 1:
        return None
    try:
        fractions = [float(item) for item in value]
    except (TypeError, ValueError):
        return None
    if any(fraction <= 0 for fraction in fractions):
        return None
    total = sum(fractions)
    if total <= 0:
        return None
    return tuple(fraction / total for fraction in fractions)


_NOTE_DEBOUNCE_MS = 1000


class BrowserPanel(QWidget):
    """The left dock: search, folder tree, file list and folder note."""

    file_activated = Signal(str)
    folder_selected = Signal(str)
    new_note_requested = Signal()
    new_folder_requested = Signal()
    import_requested = Signal()
    refresh_requested = Signal()
    sync_requested = Signal()
    lock_requested = Signal()
    settings_requested = Signal()

    def __init__(self, controller: Any, parent: Any = None) -> None:
        """Build the browser against ``controller``'s listing/note helpers."""
        super().__init__(parent)
        self._controller = controller
        self._current_folder = "/"
        self._fitting = False
        self._fitting_again = False
        #: Column widths as fractions of the table's width — ONE layout for every folder.
        self._column_ratios: tuple[float, ...] | None = None
        self._loading_note = False
        self._selecting = False
        self._activated_path = ""
        self._activated_at = 0.0

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
            ("sync", self.sync_requested),
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
        # A row is allowed to be several lines: the name and the note wrap into the room that is
        # left and the table never scrolls sideways, so every cell of a row stays readable instead
        # of a wide column pushing the rest out of view.
        header = self.list.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(False)
        self.list.setWordWrap(True)
        self.list.setTextElideMode(Qt.ElideNone)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # Row heights follow the wrapped text, and are recomputed when the panel changes width.
        self.list.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        # A drag on a column boundary is the user setting the layout by hand: remember it as
        # fractions, so the same proportions come back for this folder and every other one.
        header.sectionResized.connect(self._on_section_resized)
        # The table's own viewport, not just the panel: a vertical scrollbar appearing narrows it
        # by ~14 px and the columns have to fit again.
        self.list.viewport().installEventFilter(self)
        self.list.doubleClicked.connect(self._on_file_activated)
        layout.addWidget(self.list, 3)

        # A thumbnail of the picture selected in the list: attachments are hash-named, so the
        # name alone tells the user nothing about which picture it is.
        self.preview = QLabel(self)
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setMaximumHeight(200)
        self.preview.hide()
        layout.addWidget(self.preview, 0)
        self._preview_path: str | None = None

        # One adaptive note box: it edits the selected item's note, whether that item is a
        # folder (selected in the tree or list) or a file.
        self.note_box = QGroupBox(self)
        self.note_box.setCheckable(True)
        self.note_box.setChecked(True)
        note_layout = QVBoxLayout(self.note_box)
        self.note_edit = QPlainTextEdit(self.note_box)
        self.note_edit.setMaximumHeight(72)
        note_layout.addWidget(self.note_edit)
        layout.addWidget(self.note_box)
        #: ``("folder"|"file", path)`` currently bound to the note editor.
        self._note_target: tuple[str, str] = ("folder", "/")

        self._note_timer = QTimer(self)
        self._note_timer.setSingleShot(True)
        self._note_timer.setInterval(_NOTE_DEBOUNCE_MS)
        self._note_timer.timeout.connect(self._save_note)
        self.note_edit.textChanged.connect(self._on_note_changed)
        self.search_box.textChanged.connect(self._on_search)
        self.note_box.toggled.connect(self.note_edit.setVisible)
        self.list.selectionModel().selectionChanged.connect(self._on_file_selection)

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
        self._note_target = ("folder", self._current_folder)
        try:
            entries = self._controller.list_entries(self._current_folder)
        except Exception:  # noqa: BLE001 - a locked/absent folder shows empty
            entries = []
        self.list_model.set_entries(entries)
        self._fit_columns()
        self._hide_preview()
        self._load_note()
        # The list can navigate too (a double-click on a folder row), so the tree follows: two
        # panes showing different folders read as a bug.
        self.select_in_tree(self._current_folder)
        self.folder_selected.emit(self._current_folder)

    def resizeEvent(self, event: Any) -> None:  # noqa: N802 - Qt API
        """Re-split the two wrapping columns whenever the panel changes width."""
        super().resizeEvent(event)
        self._fit_columns()

    def eventFilter(self, watched: Any, event: Any) -> bool:  # noqa: N802 - Qt API
        """Refit when the table's viewport changes width on its own (a scrollbar appearing)."""
        if watched is self.list.viewport() and event.type() == QEvent.Resize:
            self._fit_columns()
        return super().eventFilter(watched, event)

    def _fit_columns(self) -> None:
        """Fit every column inside the viewport, so the table never scrolls sideways.

        The short columns (level, size, date) keep the width their content asks for; the name and
        the note share what is left — name first — and wrap, which is why a row may be several
        lines. When even that does not fit, nothing is clipped or hidden: every column is scaled
        down in proportion and the cells wrap into the narrower width.
        """
        if self._fitting:
            # A vertical scrollbar appearing narrows the viewport mid-fit; ask for one more pass
            # rather than looping straight into ourselves.
            self._fitting_again = True
            return
        header = self.list.horizontalHeader()
        available = self.list.viewport().width()
        if available <= 0:
            return
        count = self.list.model().columnCount()
        if not count:
            return
        if self._column_ratios and len(self._column_ratios) == count:
            # A remembered layout is authoritative: re-deriving it from rounded pixels would let
            # the proportions drift a little on every restart.
            widths = [max(1, int(round(available * ratio))) for ratio in self._column_ratios]
            self._apply_widths(header, widths, available)
            return
        widths = self._content_widths(header, count, available)
        if widths is None:
            return
        self._apply_widths(header, widths, available, learn=True)

    def _content_widths(self, header: Any, count: int, available: int) -> list[int] | None:
        """First-run widths: short columns by content, the name and the note share the rest."""
        hints = [max(1, header.sectionSizeHint(column)) for column in range(count)]
        text = (VaultListModel.COLUMN_NAME, VaultListModel.COLUMN_NOTE)
        fixed = sum(hint for column, hint in enumerate(hints) if column not in text)
        rest = available - fixed
        if rest >= 2 * _MIN_NAME_WIDTH:
            name = int(rest * 0.6)
            widths = list(hints)
            widths[VaultListModel.COLUMN_NAME] = name
            widths[VaultListModel.COLUMN_NOTE] = rest - name
        else:
            # Too narrow for the content widths: scale everything, wide cells wrap instead.
            total = sum(hints)
            widths = [max(1, int(hint * available / total)) for hint in hints]
            widths[VaultListModel.COLUMN_NAME] += available - sum(widths)
        return widths

    def _apply_widths(
        self, header: Any, widths: list[int], available: int, *, learn: bool = False
    ) -> None:
        """Set the sections so they add up to the viewport exactly, and keep them as fractions."""
        # A vertical scrollbar appearing narrows the viewport, which fires resizeEvent again; the
        # guard keeps that from turning into a loop.
        widths = list(widths)
        widths[-1] += available - sum(widths)
        self._fitting = True
        try:
            for column, width in enumerate(widths):
                header.resizeSection(column, width)
            self.list.resizeRowsToContents()
        finally:
            self._fitting = False
        if learn:
            self._column_ratios = tuple(width / available for width in widths)
        if self._fitting_again:
            self._fitting_again = False
            QTimer.singleShot(0, self._fit_columns)

    def column_ratios(self) -> list[float] | None:
        """The column layout as fractions of the table's width (None before the first fit)."""
        return list(self._column_ratios) if self._column_ratios else None

    def set_column_ratios(self, ratios: Any) -> bool:
        """Adopt a remembered column layout; every folder then uses the same proportions."""
        fractions = _clean_ratios(ratios)
        if fractions is None:
            return False
        self._column_ratios = fractions
        self._fit_columns()
        return True

    def _on_section_resized(self, column: int, old: int, new: int) -> None:
        """Learn a hand-dragged layout as fractions (the fit itself is guarded, so it is not one)."""
        if self._fitting:
            return
        header = self.list.horizontalHeader()
        count = self.list.model().columnCount()
        widths = [header.sectionSize(index) for index in range(count)]
        available = sum(widths)
        if available <= 0:
            return
        self._column_ratios = tuple(width / available for width in widths)
        self.list.resizeRowsToContents()
        # A programmatic resize (not a boundary drag) can leave the total short of the viewport;
        # one deferred fit renormalises it and keeps the "never scrolls sideways" promise.
        QTimer.singleShot(0, self._fit_columns)

    def select_in_tree(self, path: str) -> None:
        """Point the folder tree at ``path``, expanding the parents it needs."""
        index = self.tree_model.index_for_path(path)
        if not index.isValid():
            return
        chain = []
        parent = index.parent()
        while parent.isValid():
            chain.append(parent)
            parent = parent.parent()
        for item in reversed(chain):
            self.tree.expand(item)
        if self.tree.currentIndex() == index:
            return
        # Guarded: changing the tree's selection emits ``selectionChanged``, which would call
        # ``set_folder`` again for the folder we are already in.
        self._selecting = True
        try:
            self.tree.setCurrentIndex(index)
            self.tree.scrollTo(index)
        finally:
            self._selecting = False

    def refresh(self) -> None:
        """Reload the tree, the current folder and the note."""
        self.tree_model.refresh()
        self.set_folder(self._current_folder)

    def _on_tree_selection(self) -> None:
        """Load the folder for the selected tree item."""
        if self._selecting:
            return
        indexes = self.tree.selectionModel().selectedIndexes()
        if not indexes:
            return
        node = indexes[0].internalPointer()
        if node is None:
            return
        self.set_folder(node.path)

    def _on_file_activated(self, index: Any) -> None:
        """Open the activated row: a folder becomes the current folder, a file is shown.

        The list shows folders as well as notes, so a double-click on one has to walk into it —
        before this it was the only row in the pane that ignored the double-click.
        """
        entry = self.list_model.entry_at(index)
        if entry is None:
            return
        if entry.get("is_dir"):
            self.set_folder(str(entry.get("path") or "/"))
            return
        path = str(entry.get("path", ""))
        #: One gesture, one open. Some platforms deliver a double-click as two activations (KDE
        #: turns on single-click activation, so `activated` and `doubleClicked` both arrive): a
        #: secret file then asked twice and opened twice, and the second window sat exactly on
        #: the first one — which is why closing one looked like the Close button doing nothing.
        moment = time.monotonic()
        if path == self._activated_path and moment - self._activated_at < 1.0:
            return
        self._activated_path, self._activated_at = path, moment
        self.file_activated.emit(path)

    def _on_search(self, text: str) -> None:
        """Filter the file list by filename."""
        self.proxy.setFilterFixedString(text)

    # ------------------------------------------------------------------ note
    def _note_kind(self) -> str:
        """Return the kind (``folder``/``file``) currently bound to the note box."""
        return self._note_target[0]

    def _update_note_title(self) -> None:
        """Title the box after the selected item's kind."""
        key = (
            "browser.folder_note"
            if self._note_kind() == "folder"
            else "browser.file_note"
        )
        self.note_box.setTitle(i18n.tr(key))

    def _load_note(self) -> None:
        """Load the note of the currently selected folder or file."""
        kind, path = self._note_target
        try:
            if kind == "folder":
                note = self._controller.folder_note(path) or ""
            else:
                note = self._controller.file_note(path) or ""
        except Exception:  # noqa: BLE001 - locked vault has no readable note
            note = ""
        self._loading_note = True
        try:
            self.note_edit.setPlainText(note)
        finally:
            self._loading_note = False
        self._update_note_title()

    def _on_note_changed(self) -> None:
        """Schedule a debounced note save."""
        if not self._loading_note:
            self._note_timer.start()

    def _save_note(self) -> None:
        """Persist the note of the currently selected folder or file."""
        kind, path = self._note_target
        try:
            if kind == "folder":
                self._controller.set_folder_note(path, self.note_edit.toPlainText())
            else:
                self._controller.set_file_note(path, self.note_edit.toPlainText())
        except Exception:  # noqa: BLE001 - best effort; a locked vault cannot save
            pass

    def _on_file_selection(self, *_args: Any) -> None:
        """Bind the note box to the item selected in the file list."""
        rows = self.list.selectionModel().selectedRows()
        entry = self.list_model.entry_at(rows[0]) if rows else None
        if entry is None:
            # Nothing selected: fall back to the current folder's own note.
            self._note_target = ("folder", self._current_folder)
        elif entry.get("is_dir"):
            self._note_target = ("folder", str(entry.get("path") or "/"))
        else:
            self._note_target = ("file", str(entry.get("path") or ""))
        self._load_note()
        self.update_image_preview(entry)

    def update_image_preview(self, entry: dict | None) -> None:
        """Show a thumbnail of the selected picture (nothing for anything else).

        Only `normal` pictures are read here: a `secret`/`secretfile` image opens through the
        native viewer, which asks first — a listing click must not be an approval.
        """
        entry = entry or {}
        path = str(entry.get("path") or "")
        is_picture = bool(
            path and not entry.get("is_dir") and image_view.looks_like_image(path)
        )
        if not is_picture:
            self._hide_preview()
            return
        if str(entry.get("sensitivity") or "normal") != "normal":
            self.preview.setPixmap(QPixmap())
            self.preview.setText(i18n.tr("browser.preview_locked"))
            self.preview.show()
            self._preview_path = None
            return
        if path == self._preview_path and not self.preview.pixmap().isNull():
            self.preview.show()
            return
        try:
            data = self._controller.read_bytes(path)
        except Exception:  # noqa: BLE001 - unreadable picture: no preview, never an error
            self._hide_preview()
            return
        pixmap = image_view.decode(data)
        if pixmap is None:
            self._hide_preview()
            return
        self.preview.setPixmap(
            pixmap.scaled(240, 190, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        )
        self.preview.setToolTip(path)
        self.preview.show()
        self._preview_path = path

    def _hide_preview(self) -> None:
        """Drop the thumbnail (a folder or a note was selected)."""
        self._preview_path = None
        self.preview.clear()
        self.preview.hide()

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.search_box.setPlaceholderText(i18n.tr("browser.search_placeholder"))
        labels = {
            "new_note": "browser.new_note",
            "new_folder": "browser.new_folder",
            "import": "browser.import",
            "refresh": "browser.refresh",
            "sync": "menu.sync",
            "lock": "browser.lock",
            "settings": "browser.settings",
        }
        for name, action in self.actions.items():
            action.setText(i18n.tr(labels[name]))
        self._update_note_title()
        self.list_model.headerDataChanged.emit(Qt.Horizontal, 0, 4)


__all__ = ["BrowserPanel"]
