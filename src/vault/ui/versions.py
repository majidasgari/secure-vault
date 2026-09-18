"""Version history and a git-style diff dialog (UI only).

Every save keeps its own encrypted blob (see :meth:`VaultSession._record_version`), and
this dialog lets the user compare any two of them. The diff is rendered only here; the
MCP role can never read a historical version.
"""

from __future__ import annotations

import html
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
)

from . import i18n


class VersionsDialog(QDialog):
    """Show a file's versions and a colored diff between any two of them."""

    def __init__(self, controller: Any, path: str, parent: Any = None) -> None:
        """Load the versions of ``path`` and show the latest change by default."""
        super().__init__(parent)
        self._controller = controller
        self._path = path
        self._versions: list[dict[str, Any]] = []
        self.setWindowTitle(i18n.tr("versions.title"))
        self.resize(720, 560)

        layout = QVBoxLayout(self)
        self.heading = QLabel(i18n.tr("versions.heading", path=path), self)
        layout.addWidget(self.heading)

        self.table = QTableWidget(0, 4, self)
        self.table.setHorizontalHeaderLabels(
            [
                i18n.tr("versions.version"),
                i18n.tr("versions.date"),
                i18n.tr("versions.size"),
                i18n.tr("versions.source"),
            ]
        )
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.table, 2)

        picker = QHBoxLayout()
        self.from_label = QLabel(i18n.tr("versions.from"), self)
        self.from_combo = QComboBox(self)
        self.to_label = QLabel(i18n.tr("versions.to"), self)
        self.to_combo = QComboBox(self)
        self.show_button = QPushButton(i18n.tr("versions.show_diff"), self)
        self.show_button.clicked.connect(self._show_diff)
        picker.addWidget(self.from_label)
        picker.addWidget(self.from_combo, 1)
        picker.addWidget(self.to_label)
        picker.addWidget(self.to_combo, 1)
        picker.addWidget(self.show_button)
        layout.addLayout(picker)

        self.diff_view = QTextEdit(self)
        self.diff_view.setReadOnly(True)
        self.diff_view.setLineWrapMode(QTextEdit.NoWrap)
        layout.addWidget(self.diff_view, 3)

        self._load()

    def _load(self) -> None:
        """Fetch the version list and populate the table and the pickers."""
        try:
            result = self._controller.versions(self._path)
        except Exception as exc:  # noqa: BLE001 - show the error, never crash
            self.diff_view.setPlainText(str(exc))
            return
        self._versions = list(result.get("versions") or [])
        self.table.setRowCount(len(self._versions))
        for row, version in enumerate(self._versions):
            self.table.setItem(row, 0, QTableWidgetItem(str(version["version"])))
            self.table.setItem(row, 1, QTableWidgetItem(_format_ms(version["mtime"])))
            self.table.setItem(row, 2, QTableWidgetItem(_format_size(version["size"])))
            self.table.setItem(row, 3, QTableWidgetItem(str(version["source"])))
        numbers = [int(v["version"]) for v in self._versions]
        for combo in (self.from_combo, self.to_combo):
            combo.clear()
            for number in numbers:
                combo.addItem(str(number), number)
        if numbers:
            self.from_combo.setCurrentIndex(min(1, len(numbers) - 1))
            self.to_combo.setCurrentIndex(0)
        if len(numbers) < 2:
            self.diff_view.setPlainText(i18n.tr("versions.single"))
            self.show_button.setEnabled(False)
        else:
            self._show_diff()

    def _show_diff(self) -> None:
        """Render the diff between the two picked versions."""
        from_version = self.from_combo.currentData()
        to_version = self.to_combo.currentData()
        if from_version is None or to_version is None:
            return
        try:
            result = self._controller.diff(
                self._path, int(from_version), int(to_version)
            )
        except Exception as exc:  # noqa: BLE001 - show the error, never crash
            self.diff_view.setPlainText(str(exc))
            return
        self.diff_view.setHtml(_render_diff(result.get("hunks") or []))


def _render_diff(hunks: list[dict[str, Any]]) -> str:
    """Turn diff hunks into colored, escaped HTML lines."""
    rows: list[str] = []
    for hunk in hunks:
        kind = str(hunk.get("type"))
        if kind in ("delete", "replace"):
            for line in hunk.get("a_lines") or []:
                rows.append(f'<span style="color:#c0392b">- {html.escape(str(line))}</span>')
        if kind in ("insert", "replace"):
            for line in hunk.get("b_lines") or []:
                rows.append(f'<span style="color:#1e8449">+ {html.escape(str(line))}</span>')
        if kind == "equal":
            for line in hunk.get("a_lines") or []:
                rows.append(f'<span style="color:#7f8c8d">  {html.escape(str(line))}</span>')
    if not rows:
        return f"<pre>{html.escape(i18n.tr('versions.no_changes'))}</pre>"
    return "<pre style='font-family:monospace'>" + "\n".join(rows) + "</pre>"


def _format_ms(ms: Any) -> str:
    """Format a millisecond timestamp as ``YYYY-MM-DD HH:MM`` (local time)."""
    from datetime import datetime

    try:
        return datetime.fromtimestamp(int(ms) / 1000.0).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError):
        return ""


def _format_size(size: Any) -> str:
    """Human-readable byte size."""
    value = int(size or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


__all__ = ["VersionsDialog"]
