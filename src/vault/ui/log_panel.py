"""Access-log panel: a filterable table with CSV export (SPEC/03 §2.3)."""

from __future__ import annotations

import csv
import time
from typing import Any, Callable

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import i18n

_OUTCOMES = ("", "allow", "deny", "error")
#: Minimum time between two automatic log reloads (a poll would otherwise run per notification).
_REFRESH_MS = 1500
_OUTCOME_KEYS = {
    "": "log.filter_all",
    "allow": "log.filter_allow",
    "deny": "log.filter_deny",
    "error": "log.filter_error",
}


class LogPanel(QWidget):
    """The append-only access log rendered as a table."""

    COLUMNS = ("time", "source", "tool", "path", "outcome")

    def __init__(self, call: Callable[[str, dict], dict], parent: Any = None) -> None:
        """Wrap a ``call(method, params)`` service dispatcher."""
        super().__init__(parent)
        self._call = call
        self._rows: list[dict] = []
        self._last_refresh = 0.0
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.timeout.connect(self._reload)

        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self.filter_combo = QComboBox(self)
        for value in _OUTCOMES:
            self.filter_combo.addItem("", value)
        self.filter_combo.currentIndexChanged.connect(self.refresh)
        self.refresh_button = QPushButton(self)
        self.refresh_button.clicked.connect(self.refresh)
        self.export_button = QPushButton(self)
        self.export_button.clicked.connect(self.export_csv)
        controls.addWidget(self.filter_combo, 1)
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.export_button)
        layout.addLayout(controls)

        self.table = QTableWidget(0, len(self.COLUMNS), self)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        self.retranslate()
        i18n.bind(self, self.retranslate)

    # ------------------------------------------------------------------ data
    def refresh(self) -> None:
        """Reload the log rows for the active filter, right now."""
        self._reload()

    def refresh_soon(self) -> None:
        """Reload at most once every :data:`_REFRESH_MS` (used by background notifications).

        A log query no longer writes a log row of its own, but a panel that reloads on every
        notification would still hammer the DB while an agent works. Explicit calls to
        :meth:`refresh` (the Refresh button, a filter change, the self-test) always run.
        """
        now = time.monotonic()
        elapsed = now - self._last_refresh
        if elapsed < _REFRESH_MS / 1000.0:
            if not self._refresh_timer.isActive():
                self._refresh_timer.start(int(_REFRESH_MS - elapsed * 1000))
            return
        self._reload()

    def _reload(self) -> None:
        """Query the vault and repaint the table (the actual work of :meth:`refresh`)."""
        self._last_refresh = time.monotonic()
        outcome = self.filter_combo.currentData() or ""
        params: dict[str, Any] = {"limit": 500}
        if outcome:
            params["outcome"] = outcome
        try:
            result = self._call("vault.access_log", params)
        except Exception:  # noqa: BLE001 - a locked/absent vault shows an empty log
            result = {"entries": []}
        self._rows = list(result.get("entries", []))
        self.table.setRowCount(0)
        for row in self._rows:
            index = self.table.rowCount()
            self.table.insertRow(index)
            values = (
                str(row.get("iso", row.get("ts", ""))),
                str(row.get("source", "")),
                str(row.get("tool", "")),
                str(row.get("target_path") or ""),
                str(row.get("outcome", "")),
            )
            for column, value in enumerate(values):
                self.table.setItem(index, column, QTableWidgetItem(value))

    def row_count(self) -> int:
        """Return the number of visible log rows."""
        return self.table.rowCount()

    def rows(self) -> list[dict]:
        """Return a copy of the loaded log rows."""
        return [dict(row) for row in self._rows]

    # ------------------------------------------------------------------ export
    def export_csv(self) -> str | None:
        """Ask for a path and write the log as CSV; return the chosen path."""
        path, _ = QFileDialog.getSaveFileName(
            self, i18n.tr("log.export_title"), "access-log.csv", "CSV (*.csv)"
        )
        if not path:
            return None
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                ["id", "ts", "source", "role", "tool", "target_path", "outcome",
                 "code", "details", "session"]
            )
            for row in self._rows:
                writer.writerow(
                    [
                        row.get("id", ""),
                        row.get("ts", ""),
                        row.get("source", ""),
                        row.get("role", ""),
                        row.get("tool", ""),
                        row.get("target_path", ""),
                        row.get("outcome", ""),
                        row.get("code", ""),
                        row.get("details", ""),
                        row.get("session", ""),
                    ]
                )
        return path

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.refresh_button.setText(i18n.tr("log.refresh"))
        self.export_button.setText(i18n.tr("log.export"))
        for index, value in enumerate(_OUTCOMES):
            self.filter_combo.setItemText(index, i18n.tr(_OUTCOME_KEYS[value]))
        self.table.setHorizontalHeaderLabels(
            [
                i18n.tr("log.column_time"),
                i18n.tr("log.column_source"),
                i18n.tr("log.column_tool"),
                i18n.tr("log.column_path"),
                i18n.tr("log.column_outcome"),
            ]
        )


__all__ = ["LogPanel"]
