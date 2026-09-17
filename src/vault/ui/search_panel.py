"""Search panel: three independent searches in three tabs (SPEC/03 §2.3, §6)."""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from . import i18n

_KIND_ALIASES = {
    "filename": "filename",
    "filenames": "filename",
    "text": "text",
    "semantic": "semantic",
}
_KIND_METHODS = {
    "filename": "vault.search_filenames",
    "text": "vault.search_text",
    "semantic": "vault.search_semantic",
}
_KIND_LABEL_KEYS = {
    "filename": "search.tab_filenames",
    "text": "search.tab_text",
    "semantic": "search.tab_semantic",
}


def _api_path(logical: str) -> str:
    """Render a storage path as the API-absolute form used by the service."""
    if logical in ("", "/"):
        return "/"
    return "/" + logical.lstrip("/")


class _SearchTab(QWidget):
    """One search kind: query box, button, results list and empty-state label."""

    activated = Signal(str)

    def __init__(self, parent: Any = None) -> None:
        """Create an empty search tab."""
        super().__init__(parent)
        self.results: list[dict] = []

        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        self.query = QLineEdit(self)
        self.query.returnPressed.connect(self.run)
        self.button = QPushButton(self)
        self.button.clicked.connect(self.run)
        row.addWidget(self.query, 1)
        row.addWidget(self.button)
        layout.addLayout(row)

        self.empty = QLabel(self)
        self.empty.setWordWrap(True)
        layout.addWidget(self.empty)

        self.list = QListWidget(self)
        self.list.itemActivated.connect(self._on_activated)
        self.list.itemDoubleClicked.connect(self._on_activated)
        layout.addWidget(self.list, 1)

        self._handler: Callable[[str], None] | None = None
        i18n.bind(self, self.retranslate)

    def set_handler(self, handler: Callable[[str], None]) -> None:
        """Set the callable invoked with the query when the user searches."""
        self._handler = handler

    def run(self) -> None:
        """Trigger the handler for the current query."""
        if self._handler is not None:
            self._handler(self.query.text())

    def set_results(self, results: list[dict]) -> None:
        """Replace the result list."""
        self.results = list(results)
        self.list.clear()
        for result in self.results:
            path = _api_path(str(result.get("logical_path", "")))
            level = str(result.get("sensitivity", "normal"))
            item = QListWidgetItem(f"{path}  [{i18n.tr(f'level.{level}')}]")
            item.setData(256, path)
            self.list.addItem(item)
        self.empty.setVisible(not self.results)

    def _on_activated(self, item: QListWidgetItem) -> None:
        """Emit the activated path."""
        path = item.data(256)
        if path:
            self.activated.emit(str(path))

    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.button.setText(i18n.tr("search.button"))
        self.query.setPlaceholderText(i18n.tr("search.placeholder"))
        if not self.results:
            self.empty.setText(i18n.tr("search.empty"))


class SearchPanel(QWidget):
    """The three-tab search dock."""

    result_activated = Signal(str)

    def __init__(self, call: Callable[[str, dict], dict], parent: Any = None) -> None:
        """Wrap a ``call(method, params)`` service dispatcher."""
        super().__init__(parent)
        self._call = call
        self._last: dict[str, list[dict]] = {"filename": [], "text": [], "semantic": []}
        self._tabs: dict[str, _SearchTab] = {}

        layout = QVBoxLayout(self)
        self.tab_widget = QTabWidget(self)
        for kind in ("filename", "text", "semantic"):
            tab = _SearchTab(self)
            tab.set_handler(lambda query, k=kind: self.run_search(k, query))
            tab.activated.connect(self.result_activated)
            self._tabs[kind] = tab
            self.tab_widget.addTab(tab, "")
        layout.addWidget(self.tab_widget)

        self.semantic_status = QLabel(self)
        self.semantic_status.setWordWrap(True)
        layout.addWidget(self.semantic_status)

        self.retranslate()
        i18n.bind(self, self.retranslate)

    # ------------------------------------------------------------------ search
    def run_search(self, kind: str, query: str) -> list[dict]:
        """Run one search kind and return the results (also stored for the tests)."""
        normalized = _KIND_ALIASES.get(kind)
        if normalized is None:
            return []
        if not query:
            self._last[normalized] = []
            self._tabs[normalized].set_results([])
            return []
        try:
            result = self._call(_KIND_METHODS[normalized], {"query": query})
            results = list(result.get("results", []))
        except Exception:  # noqa: BLE001 - surface failures as an empty result set
            results = []
        self._last[normalized] = results
        self._tabs[normalized].set_results(results)
        return results

    def last_results(self, kind: str) -> list[dict]:
        """Return the results of the most recent search of ``kind``."""
        normalized = _KIND_ALIASES.get(kind)
        if normalized is None:
            return []
        return list(self._last[normalized])

    def set_query(self, kind: str, query: str) -> None:
        """Set the query text of one tab (used by the smoke test and Find)."""
        normalized = _KIND_ALIASES.get(kind)
        if normalized is not None:
            self._tabs[normalized].query.setText(query)

    def focus_query(self, kind: str = "filename") -> None:
        """Give keyboard focus to one tab's query box."""
        normalized = _KIND_ALIASES.get(kind)
        if normalized is not None:
            self._tabs[normalized].query.setFocus()

    # ------------------------------------------------------------------ status
    def refresh_status(self) -> None:
        """Refresh the semantic availability line from ``vault.status``."""
        try:
            status = self._call("vault.status", {})
            semantic = status.get("semantic", {})
        except Exception:  # noqa: BLE001
            semantic = {}
        if not semantic.get("enabled"):
            text = i18n.tr("search.semantic_disabled")
        elif semantic.get("available"):
            text = i18n.tr("search.semantic_available", model=semantic.get("model") or "")
        else:
            reason = semantic.get("reason") or ""
            text = i18n.tr("search.semantic_unavailable", reason=reason)
        self.semantic_status.setText(text)

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated tab titles and the semantic status."""
        for kind, tab in self._tabs.items():
            index = self.tab_widget.indexOf(tab)
            self.tab_widget.setTabText(index, i18n.tr(_KIND_LABEL_KEYS[kind]))
        self.refresh_status()


__all__ = ["SearchPanel"]
