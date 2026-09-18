"""Qt models over the vault index (SPEC/03 §5).

``VaultTreeModel`` is a lazy folder tree; ``VaultListModel`` is the file table for the
selected folder. Both tolerate a locked/empty session and refresh through a tiny
:class:`DataHub` notification list (also attached to the session as ``data_changed``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Iterable

from PySide6.QtCore import QAbstractItemModel, QAbstractTableModel, QModelIndex, Qt

from . import i18n

LEVEL_ICONS: dict[str, str] = {
    "normal": "\U0001F513",
    "secret": "\U0001F512",
    "secretfile": "\U0001F511",
}
"""Emoji shown per sensitivity level (unlocked / locked / key)."""

LEVEL_ORDER = ("normal", "secret", "secretfile")


class DataHub:
    """A minimal callback list used to refresh models after a mutation."""

    def __init__(self) -> None:
        """Create an empty hub."""
        self._subscribers: list[Callable[[], None]] = []

    def subscribe(self, callback: Callable[[], None]) -> None:
        """Register ``callback`` to be invoked on :meth:`notify`."""
        self._subscribers.append(callback)

    def notify(self) -> None:
        """Invoke every subscriber, ignoring individual failures."""
        for callback in list(self._subscribers):
            try:
                callback()
            except Exception:  # noqa: BLE001 - one view must not break the others
                pass

    __call__ = notify


def format_size(size: int) -> str:
    """Return a compact human-readable size such as ``"1.5 MB"``."""
    if size < 0:
        size = 0
    if size < 1024:
        return f"{size} B"
    value = float(size)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1024.0
        if value < 1024.0 or unit == "TB":
            return f"{value:.1f} {unit}"
    return f"{size} B"  # pragma: no cover - unreachable


def format_mtime(mtime: int) -> str:
    """Format a millisecond epoch as a local ``YYYY-MM-DD HH:MM`` string."""
    try:
        return datetime.fromtimestamp(int(mtime) / 1000.0).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return ""


class _Node:
    """One directory node of the lazy tree."""

    __slots__ = ("path", "name", "parent", "children", "loaded")

    def __init__(self, path: str, name: str, parent: "_Node | None") -> None:
        """Create an unloaded node for ``path``."""
        self.path = path
        self.name = name
        self.parent = parent
        self.children: list[_Node] = []
        self.loaded = False


class VaultTreeModel(QAbstractItemModel):
    """A lazily-populated tree of the vault's folders."""

    def __init__(self, provider: Callable[[str], list[dict]], parent: Any = None) -> None:
        """Wrap a ``provider(path) -> entries`` callable."""
        super().__init__(parent)
        self._provider = provider
        self._root = _Node("/", "", None)
        self._root.loaded = False

    # ------------------------------------------------------------------ helpers
    def _node(self, index: QModelIndex) -> _Node:
        """Return the node behind ``index`` (or the root for an invalid index)."""
        if index.isValid():
            return index.internalPointer()  # type: ignore[return-value]
        return self._root

    def _ensure(self, node: _Node) -> None:
        """Load ``node``'s children once."""
        if node.loaded:
            return
        node.loaded = True
        node.children = []
        if node.path is None:
            return
        try:
            entries = self._provider(node.path)
        except Exception:  # noqa: BLE001 - a locked/absent folder is simply empty
            entries = []
        dirs = [entry for entry in entries if entry.get("is_dir")]
        dirs.sort(key=lambda entry: str(entry.get("name", "")).lower())
        for entry in dirs:
            node.children.append(
                _Node(str(entry["path"]), str(entry.get("name", "")), node)
            )

    def _row_of(self, node: _Node) -> int:
        """Return ``node``'s row inside its parent (0 when it has none)."""
        if node.parent is None:
            return 0
        try:
            return node.parent.children.index(node)
        except ValueError:  # pragma: no cover - defensive
            return 0

    def refresh(self) -> None:
        """Discard cached children and reload the visible tree."""
        self.beginResetModel()
        self._root = _Node("/", "", None)
        self.endResetModel()

    # -------------------------------------------------------------- Qt interface
    def index(self, row: int, column: int, parent: QModelIndex = QModelIndex()) -> QModelIndex:
        """Return the index of child ``(row, column)`` of ``parent``."""
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        node = self._node(parent)
        self._ensure(node)
        if 0 <= row < len(node.children):
            return self.createIndex(row, column, node.children[row])
        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:  # type: ignore[override]
        """Return the parent index of ``index``."""
        if not index.isValid():
            return QModelIndex()
        node = index.internalPointer()
        parent = node.parent  # type: ignore[union-attr]
        if parent is None or parent is self._root:
            return QModelIndex()
        return self.createIndex(self._row_of(parent), 0, parent)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        """Return the number of children of ``parent``."""
        if parent.column() > 0:
            return 0
        node = self._node(parent)
        self._ensure(node)
        return len(node.children)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        """The tree has a single column."""
        return 1

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        """Return the folder name for the display role."""
        if not index.isValid():
            return None
        node = index.internalPointer()
        if role == Qt.DisplayRole:
            return node.name or "/"  # type: ignore[union-attr]
        return None

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.DisplayRole) -> Any:
        """Return the translated column header."""
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return i18n.tr("browser.column_name")
        return None


class VaultListModel(QAbstractTableModel):
    """The file/folder table for the currently selected folder."""

    COLUMN_NAME = 0
    COLUMN_LEVEL = 1
    COLUMN_SIZE = 2
    COLUMN_MTIME = 3
    COLUMN_NOTE = 4

    def __init__(self, parent: Any = None) -> None:
        """Create an empty list model."""
        super().__init__(parent)
        self._entries: list[dict] = []

    def set_entries(self, entries: Iterable[dict]) -> None:
        """Replace the table contents."""
        self.beginResetModel()
        self._entries = [dict(entry) for entry in entries]
        self.endResetModel()

    def entries(self) -> list[dict]:
        """Return a copy of the current entries."""
        return [dict(entry) for entry in self._entries]

    def entry_at(self, index: QModelIndex) -> dict | None:
        """Return the entry behind ``index`` (accepts proxy indexes)."""
        if not index.isValid():
            return None
        source = index
        model = index.model()
        if hasattr(model, "mapToSource"):
            source = model.mapToSource(index)  # type: ignore[attr-defined]
        row = source.row()
        if 0 <= row < len(self._entries):
            return dict(self._entries[row])
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        """Return the number of rows."""
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        """Return the five documented columns."""
        return 5

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        """Return cell content for the display role."""
        if not index.isValid() or not (0 <= index.row() < len(self._entries)):
            return None
        entry = self._entries[index.row()]
        column = index.column()
        if role == Qt.DisplayRole:
            if column == self.COLUMN_NAME:
                return entry.get("name", "")
            if column == self.COLUMN_LEVEL:
                return LEVEL_ICONS.get(str(entry.get("sensitivity")), "")
            if column == self.COLUMN_SIZE:
                if entry.get("is_dir"):
                    return ""
                return format_size(int(entry.get("size", 0)))
            if column == self.COLUMN_MTIME:
                return format_mtime(int(entry.get("mtime", 0)))
            if column == self.COLUMN_NOTE:
                return entry.get("note") or ""
        if role == Qt.ToolTipRole and column == self.COLUMN_NOTE:
            return entry.get("note") or None
        if role == Qt.TextAlignmentRole and column in (self.COLUMN_SIZE, self.COLUMN_MTIME):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        if role == Qt.UserRole:
            return entry.get("path")
        return None

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.DisplayRole) -> Any:
        """Return translated column headers."""
        if role != Qt.DisplayRole or orientation != Qt.Horizontal:
            return None
        return {
            self.COLUMN_NAME: i18n.tr("browser.column_name"),
            self.COLUMN_LEVEL: i18n.tr("browser.column_level"),
            self.COLUMN_SIZE: i18n.tr("browser.column_size"),
            self.COLUMN_MTIME: i18n.tr("browser.column_mtime"),
            self.COLUMN_NOTE: i18n.tr("browser.column_note"),
        }.get(section)


__all__ = [
    "LEVEL_ICONS",
    "LEVEL_ORDER",
    "DataHub",
    "VaultTreeModel",
    "VaultListModel",
    "format_size",
    "format_mtime",
]
