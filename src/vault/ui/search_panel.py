"""Search panel: three independent searches in three tabs (SPEC/03 §2.3, §6)."""

from __future__ import annotations

import time
from typing import Any, Callable

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
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

    def __init__(self, parent: Any = None, *, only_secret_filter: bool = False) -> None:
        """Create an empty search tab.

        ``only_secret_filter`` adds the "credential files only" switch. Only the filename tab
        gets it: content and semantic search never read secret bodies, so the filter there
        could only ever return nothing.
        """
        super().__init__(parent)
        self.results: list[dict] = []
        self._activated_path = ""
        self._activated_at = 0.0

        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        self.query = QLineEdit(self)
        self.query.returnPressed.connect(self.run)
        self.button = QPushButton(self)
        self.button.clicked.connect(self.run)
        row.addWidget(self.query, 1)
        row.addWidget(self.button)
        layout.addLayout(row)

        box: QCheckBox | None = QCheckBox(self) if only_secret_filter else None
        self.only_secret = box
        if box is not None:
            # Toggling re-runs the current query: a filter the user has to press Search again for
            # reads as broken.
            box.toggled.connect(self.run)
            layout.addWidget(box)

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
        """Replace the result list.

        Each row reads name first, then the folder it lives in: in a credential vault the name
        is what the user is looking for, and the folder is the disambiguator.
        """
        self.results = list(results)
        self.list.clear()
        for result in self.results:
            path = _api_path(str(result.get("logical_path", "")))
            folder, _, name = path.rpartition("/")
            level = str(result.get("sensitivity", "normal"))
            matched = "، ".join(
                i18n.tr(f"search.field_{field}") for field in result.get("fields") or []
            )
            # A field hit says *what* matched (it can never say the value: the search never
            # sees a password).
            suffix = f" — {matched}" if matched else ""
            item = QListWidgetItem(
                f"{name or path}  —  {folder or '/'}  [{i18n.tr(f'level.{level}')}{suffix}]"
            )
            item.setData(256, path)
            self.list.addItem(item)
        self.empty.setVisible(not self.results)

    def _on_activated(self, item: QListWidgetItem) -> None:
        """Emit the activated path, once per gesture.

        ``itemActivated`` and ``itemDoubleClicked`` both arrive for one double-click (and KDE can
        be set to activate on a single click), so without this a secret file asked for approval
        twice and opened twice.
        """
        path = str(item.data(256) or "")
        if not path:
            return
        moment = time.monotonic()
        if path == self._activated_path and moment - self._activated_at < 1.0:
            return
        self._activated_path, self._activated_at = path, moment
        self.activated.emit(path)

    def secret_only(self) -> bool:
        """True when this tab's "credential files only" switch is on."""
        return self.only_secret is not None and self.only_secret.isChecked()

    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.button.setText(i18n.tr("search.button"))
        self.query.setPlaceholderText(i18n.tr("search.placeholder"))
        if self.only_secret is not None:
            self.only_secret.setText(i18n.tr("search.only_secret"))
            self.only_secret.setToolTip(i18n.tr("search.fields_hint"))
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
            tab = _SearchTab(self, only_secret_filter=kind == "filename")
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
            params: dict[str, Any] = {"query": query}
            if normalized == "filename":
                # The filename tab also looks inside a credential's fields (username, site,
                # address…), never its password — that is how you find an entry by login.
                params["fields"] = True
            if self._tabs[normalized].secret_only():
                params["only_secret"] = True
            result = self._call(_KIND_METHODS[normalized], params)
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
