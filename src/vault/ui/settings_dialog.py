"""Settings dialog (SPEC/03 §4)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from . import i18n

_LEVELS = ("normal", "secret", "secretfile")
_LEVEL_KEYS = {
    "normal": "level.normal",
    "secret": "level.secret",
    "secretfile": "level.secretfile",
}


class SettingsDialog(QDialog):
    """The tabbed settings dialog; all writes go through ``vault.set_settings``."""

    def __init__(self, controller: Any, parent: Any = None) -> None:
        """Build the dialog from the current vault settings."""
        super().__init__(parent)
        self._controller = controller
        self._settings = controller.get_settings()
        self.setModal(True)
        self.resize(560, 460)

        layout = QVBoxLayout(self)
        self.tabs = QTabWidget(self)
        layout.addWidget(self.tabs, 1)

        self._build_general()
        self._build_vault()
        self._build_semantic()
        self._build_importer()
        self._build_log()

        self.buttons = QDialogButtonBox(self)
        self.buttons.addButton(QDialogButtonBox.Ok)
        self.buttons.addButton(QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self._on_accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.retranslate()
        i18n.bind(self, self.retranslate)

    # ------------------------------------------------------------------ tabs
    def _build_general(self) -> None:
        """Build the General tab."""
        page = QWidget(self)
        form = QFormLayout(page)
        self.language_combo = QComboBox(page)
        self.language_combo.addItem("", "fa")
        self.language_combo.addItem("", "en")
        index = self.language_combo.findData(self._controller.language)
        if index >= 0:
            self.language_combo.setCurrentIndex(index)
        form.addRow(self._language_label(), self.language_combo)

        home_row = QHBoxLayout()
        self.home_edit = QLineEdit(str(self._controller.vault_home), page)
        self.home_edit.setReadOnly(True)
        self.open_home_button = QPushButton(page)
        self.open_home_button.clicked.connect(self._open_home)
        home_row.addWidget(self.home_edit, 1)
        home_row.addWidget(self.open_home_button)
        form.addRow(self._label("settings.vault_home"), home_row)

        self.autolock_spin = QSpinBox(page)
        self.autolock_spin.setRange(0, 24 * 60)
        self.autolock_spin.setSuffix("")
        seconds = int(self._settings.get("auto_lock_seconds", 0) or 0)
        self.autolock_spin.setValue(max(0, seconds // 60))
        form.addRow(self._label("settings.auto_lock"), self.autolock_spin)

        self.minimized_check = QCheckBox(page)
        self.minimized_check.setChecked(bool(self._controller.start_minimized))
        form.addRow(self._label("settings.start_minimized"), self.minimized_check)
        self.tabs.addTab(page, "")

    def _build_vault(self) -> None:
        """Build the Vault tab."""
        page = QWidget(self)
        form = QFormLayout(page)
        self.level_combo = QComboBox(page)
        for level in _LEVELS:
            self.level_combo.addItem("", level)
        index = self.level_combo.findData(
            self._settings.get("default_sensitivity", "normal")
        )
        if index >= 0:
            self.level_combo.setCurrentIndex(index)
        form.addRow(self._label("settings.default_sensitivity"), self.level_combo)

        threshold = int(self._settings.get("plain_threshold_bytes", 0) or 0)
        self.threshold_label = QLabel(f"{threshold // (1024 * 1024)} MB", page)
        form.addRow(self._label("settings.plain_threshold"), self.threshold_label)
        self.threshold_hint = QLabel(page)
        self.threshold_hint.setWordWrap(True)
        form.addRow(self.threshold_hint)

        self.verify_button = QPushButton(page)
        self.verify_button.clicked.connect(self._verify)
        form.addRow(self.verify_button)
        self.tabs.addTab(page, "")

    def _build_semantic(self) -> None:
        """Build the Semantic tab."""
        page = QWidget(self)
        form = QFormLayout(page)
        semantic = self._settings.get("semantic") or {}
        self.semantic_check = QCheckBox(page)
        self.semantic_check.setChecked(bool(semantic.get("enabled")))
        form.addRow(self._label("settings.semantic_enable"), self.semantic_check)
        self.semantic_model = QLineEdit(str(semantic.get("model", "")), page)
        form.addRow(self._label("settings.semantic_model"), self.semantic_model)
        self.semantic_status = QLabel(page)
        self.semantic_status.setWordWrap(True)
        form.addRow(self.semantic_status)
        self.index_button = QPushButton(page)
        self.index_button.clicked.connect(self._index_now)
        form.addRow(self.index_button)
        self.tabs.addTab(page, "")

    def _build_importer(self) -> None:
        """Build the Importer tab."""
        page = QWidget(self)
        form = QFormLayout(page)
        importer = self._settings.get("import_joplin") or {}
        self.mirror_edit = QLineEdit(str(importer.get("mirror_root", "")), page)
        form.addRow(self._label("settings.mirror_root"), self.mirror_edit)
        self.globs_edit = QLineEdit(
            ", ".join(importer.get("sensitive_globs") or []), page
        )
        form.addRow(self._label("settings.sensitive_globs"), self.globs_edit)
        self.import_button = QPushButton(page)
        self.import_button.clicked.connect(self._run_import)
        form.addRow(self.import_button)
        self.tabs.addTab(page, "")

    def _build_log(self) -> None:
        """Build the Log tab."""
        page = QWidget(self)
        form = QFormLayout(page)
        self.log_path = Path.home() / ".local" / "state" / "secure-vault" / "daemon.log"
        self.log_edit = QLineEdit(str(self.log_path), page)
        self.log_edit.setReadOnly(True)
        form.addRow(self._label("settings.log_path"), self.log_edit)
        self.open_log_button = QPushButton(page)
        self.open_log_button.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.log_path)))
        )
        form.addRow(self.open_log_button)
        self.log_level = QLabel(logging.getLevelName(logging.getLogger().level), page)
        form.addRow(self._label("settings.log_level"), self.log_level)
        self.tabs.addTab(page, "")

    # ------------------------------------------------------------------ helpers
    def _label(self, key: str) -> QLabel:
        """Create a translatable label and remember it."""
        label = QLabel(self)
        if not hasattr(self, "_labels"):
            self._labels: list[tuple[QLabel, str]] = []
        self._labels.append((label, key))
        return label

    def _language_label(self) -> QLabel:
        """Create the language label."""
        return self._label("settings.language")

    def _open_home(self) -> None:
        """Open the vault home in the desktop file manager."""
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._controller.vault_home)))

    def _verify(self) -> None:
        """Run blob verification and show the result."""
        try:
            result = self._controller.dispatch_ui("vault.verify_blobs", {})
        except Exception as exc:  # noqa: BLE001 - show a friendly error
            QMessageBox.warning(self, i18n.tr("settings.verify"), str(exc))
            return
        QMessageBox.information(
            self,
            i18n.tr("settings.verify"),
            i18n.tr(
                "settings.verify_result",
                checked=result.get("checked", 0),
                bad=len(result.get("bad", [])),
            ),
        )

    def _index_now(self) -> None:
        """Rebuild the semantic index."""
        try:
            result = self._controller.dispatch_ui("vault.semantic_index", {"force": True})
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, i18n.tr("settings.semantic_index"), str(exc))
            return
        QMessageBox.information(
            self,
            i18n.tr("settings.semantic_index"),
            i18n.tr("settings.semantic_indexed", count=result.get("indexed", 0)),
        )

    def _run_import(self) -> None:
        """Importer is delivered in P4; explain instead of failing."""
        QMessageBox.information(
            self, i18n.tr("settings.run_import"), i18n.tr("settings.import_unavailable")
        )

    # ------------------------------------------------------------------ accept
    def _on_accept(self) -> None:
        """Persist the settings through the service."""
        language = self.language_combo.currentData()
        self._controller.set_language(str(language))
        payload = {
            "language": str(language),
            "auto_lock_seconds": int(self.autolock_spin.value()) * 60,
            "default_sensitivity": str(self.level_combo.currentData()),
            "semantic": {
                "enabled": bool(self.semantic_check.isChecked()),
                "model": self.semantic_model.text().strip(),
            },
            "import_joplin": {
                "mirror_root": self.mirror_edit.text().strip(),
                "sensitive_globs": [
                    part.strip()
                    for part in self.globs_edit.text().split(",")
                    if part.strip()
                ],
            },
        }
        try:
            self._controller.set_settings(payload)
            self._controller.set_ui_option(
                "start_minimized", bool(self.minimized_check.isChecked())
            )
        except Exception as exc:  # noqa: BLE001 - inline rejection instead of crash
            QMessageBox.warning(self, i18n.tr("settings.title"), str(exc))
            return
        self.accept()

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.setWindowTitle(i18n.tr("settings.title"))
        for label, key in getattr(self, "_labels", []):
            label.setText(i18n.tr(key))
        self.tabs.setTabText(0, i18n.tr("settings.tab_general"))
        self.tabs.setTabText(1, i18n.tr("settings.tab_vault"))
        self.tabs.setTabText(2, i18n.tr("settings.tab_semantic"))
        self.tabs.setTabText(3, i18n.tr("settings.tab_importer"))
        self.tabs.setTabText(4, i18n.tr("settings.tab_log"))
        self.language_combo.setItemText(0, i18n.tr("language.fa"))
        self.language_combo.setItemText(1, i18n.tr("language.en"))
        for index, level in enumerate(_LEVELS):
            self.level_combo.setItemText(index, i18n.tr(_LEVEL_KEYS[level]))
        self.open_home_button.setText(i18n.tr("settings.open_folder"))
        self.verify_button.setText(i18n.tr("settings.verify"))
        self.threshold_hint.setText(i18n.tr("settings.plain_threshold_hint"))
        self.index_button.setText(i18n.tr("settings.semantic_index"))
        self.import_button.setText(i18n.tr("settings.run_import"))
        self.open_log_button.setText(i18n.tr("settings.open_log"))
        self._refresh_semantic_status()

    def _refresh_semantic_status(self) -> None:
        """Update the semantic availability line."""
        try:
            status = self._controller.dispatch_ui("vault.status", {})
            semantic = status.get("semantic", {})
        except Exception:  # noqa: BLE001
            semantic = {}
        if not semantic.get("enabled"):
            self.semantic_status.setText(i18n.tr("search.semantic_disabled"))
            self.index_button.setEnabled(False)
        elif semantic.get("available"):
            self.semantic_status.setText(
                i18n.tr("search.semantic_available", model=semantic.get("model") or "")
            )
            self.index_button.setEnabled(True)
        else:
            self.semantic_status.setText(
                i18n.tr("search.semantic_unavailable", reason=semantic.get("reason") or "")
            )
            self.index_button.setEnabled(False)


__all__ = ["SettingsDialog"]
