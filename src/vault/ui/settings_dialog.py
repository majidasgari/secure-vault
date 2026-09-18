"""Settings dialog (SPEC/03 §4)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.chunking import CHUNK_MODES, DEFAULT_CHUNK_MODE
from ..core.semantics import folder_included, normalize_folder_key
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
        self._build_web()
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
        try:
            status = self._controller.dispatch_ui("vault.status", {}) or {}
            self._default_db_path = str(
                (status.get("semantic") or {}).get("db_path") or ""
            )
        except Exception:  # noqa: BLE001 - the default is only a hint
            self._default_db_path = ""
        self.semantic_check = QCheckBox(page)
        self.semantic_check.setChecked(bool(semantic.get("enabled")))
        form.addRow(self._label("settings.semantic_enable"), self.semantic_check)
        self.semantic_model = QLineEdit(str(semantic.get("model", "")), page)
        form.addRow(self._label("settings.semantic_model"), self.semantic_model)
        self.chunk_combo = QComboBox(page)
        for mode in CHUNK_MODES:
            self.chunk_combo.addItem("", mode)
        selected = self.chunk_combo.findData(
            str(semantic.get("chunking") or DEFAULT_CHUNK_MODE)
        )
        self.chunk_combo.setCurrentIndex(selected if selected >= 0 else 0)
        form.addRow(self._label("settings.semantic_chunking"), self.chunk_combo)

        # Folder scope: checked = included; unchecked folders are skipped (cheap and safe).
        self._folder_states: dict[str, bool] = {
            normalize_folder_key(str(key)): bool(value)
            for key, value in (semantic.get("folder_states") or {}).items()
        }
        self._updating_tree = False
        folder_box = QWidget(page)
        folder_layout = QVBoxLayout(folder_box)
        folder_layout.setContentsMargins(0, 0, 0, 0)
        self.folder_tree = QTreeWidget(folder_box)
        self.folder_tree.setHeaderHidden(True)
        self.folder_tree.setUniformRowHeights(True)
        self.folder_tree.setMaximumHeight(180)
        self._populate_folder_tree()
        self.folder_tree.itemChanged.connect(self._on_folder_toggled)
        folder_layout.addWidget(self.folder_tree)
        folder_buttons = QHBoxLayout()
        self.select_all_button = QPushButton(folder_box)
        self.select_all_button.clicked.connect(lambda: self._set_all_folders(True))
        self.deselect_all_button = QPushButton(folder_box)
        self.deselect_all_button.clicked.connect(lambda: self._set_all_folders(False))
        folder_buttons.addWidget(self.select_all_button)
        folder_buttons.addWidget(self.deselect_all_button)
        folder_layout.addLayout(folder_buttons)
        form.addRow(self._label("settings.semantic_folders"), folder_box)

        # Vector cache location (defaults under the user's home, outside the vault).
        self.db_path_edit = QLineEdit(str(semantic.get("db_path") or ""), page)
        self.db_path_edit.setPlaceholderText(self._default_db_path)
        db_row = QWidget(page)
        db_layout = QHBoxLayout(db_row)
        db_layout.setContentsMargins(0, 0, 0, 0)
        db_layout.addWidget(self.db_path_edit, 1)
        self.db_browse_button = QPushButton(db_row)
        self.db_browse_button.clicked.connect(self._browse_db_path)
        db_layout.addWidget(self.db_browse_button)
        form.addRow(self._label("settings.semantic_db_path"), db_row)
        self.db_hint = QLabel(page)
        self.db_hint.setWordWrap(True)
        self.db_hint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow(self.db_hint)

        self.semantic_status = QLabel(page)
        self.semantic_status.setWordWrap(True)
        form.addRow(self.semantic_status)
        self.index_button = QPushButton(page)
        self.index_button.clicked.connect(self._index_now)
        form.addRow(self.index_button)
        self.tabs.addTab(page, "")

    def _populate_folder_tree(self) -> None:
        """Fill the folder tree with checkable items reflecting the stored scope."""
        self._updating_tree = True
        try:
            self.folder_tree.clear()
            try:
                tree = self._controller.dispatch_ui("vault.tree", {}).get("tree") or []
            except Exception:  # noqa: BLE001 - a locked vault has no folders yet
                tree = []
            for node in tree:
                self._add_folder_item(self.folder_tree.invisibleRootItem(), node)
            self.folder_tree.expandAll()
        finally:
            self._updating_tree = False

    def _add_folder_item(self, parent: Any, node: dict) -> None:
        """Add ``node`` (and its folder children) under ``parent``."""
        if not node.get("is_dir"):
            return
        key = normalize_folder_key(str(node.get("path") or ""))
        item = QTreeWidgetItem(parent, [str(node.get("name") or key)])
        item.setData(0, Qt.ItemDataRole.UserRole, key)
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        included = folder_included(key, self._folder_states)
        item.setCheckState(
            0, Qt.CheckState.Checked if included else Qt.CheckState.Unchecked
        )
        for child in node.get("children") or []:
            self._add_folder_item(item, child)

    def _on_folder_toggled(self, item: QTreeWidgetItem, column: int) -> None:
        """Record the override for ``item`` and let its descendants inherit it."""
        if self._updating_tree:
            return
        key = str(item.data(0, Qt.ItemDataRole.UserRole))
        checked = item.checkState(0) == Qt.CheckState.Checked
        self._folder_states[key] = checked
        self._clear_descendant_overrides(item)
        self._updating_tree = True
        try:
            self._apply_subtree_check(item, checked)
        finally:
            self._updating_tree = False

    def _clear_descendant_overrides(self, item: QTreeWidgetItem) -> None:
        """Forget explicit choices below ``item`` so they inherit again."""
        for index in range(item.childCount()):
            child = item.child(index)
            child_key = str(child.data(0, Qt.ItemDataRole.UserRole))
            self._folder_states.pop(child_key, None)
            self._clear_descendant_overrides(child)

    def _apply_subtree_check(self, item: Any, checked: bool) -> None:
        """Set every checkbox below ``item`` (inclusive of its children) in one pass."""
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for index in range(item.childCount()):
            child = item.child(index)
            child.setCheckState(0, state)
            self._apply_subtree_check(child, checked)

    def _set_all_folders(self, checked: bool) -> None:
        """Select or deselect every folder in one click."""
        self._folder_states = {} if checked else {"*": False}
        self._updating_tree = True
        try:
            self._apply_subtree_check(self.folder_tree.invisibleRootItem(), checked)
        finally:
            self._updating_tree = False

    def _browse_db_path(self) -> None:
        """Pick a directory for the vector cache."""
        chosen = QFileDialog.getExistingDirectory(
            self,
            i18n.tr("settings.semantic_db_path"),
            self.db_path_edit.text().strip() or str(Path.home()),
        )
        if chosen:
            self.db_path_edit.setText(chosen)

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
        self.reindex_button = QPushButton(page)
        self.reindex_button.clicked.connect(self._run_reindex)
        form.addRow(self.reindex_button)
        self.tabs.addTab(page, "")

    def _build_web(self) -> None:
        """Build the Web UI tab (SPEC/09 §A.1)."""
        page = QWidget(self)
        form = QFormLayout(page)
        web = self._settings.get("web") or {}
        self.web_enabled = QCheckBox(page)
        self.web_enabled.setChecked(bool(web.get("enabled", True)))
        form.addRow(self._label("settings.web_enabled"), self.web_enabled)
        self.web_host = QLineEdit(str(web.get("host", "127.0.0.1")), page)
        form.addRow(self._label("settings.web_host"), self.web_host)
        self.web_port = QSpinBox(page)
        self.web_port.setRange(0, 65535)
        self.web_port.setValue(int(web.get("port", 8788) or 0))
        form.addRow(self._label("settings.web_port"), self.web_port)
        self.web_lan = QCheckBox(page)
        self.web_lan.setChecked(bool(web.get("allow_lan", False)))
        form.addRow(self._label("settings.web_allow_lan"), self.web_lan)
        self.web_open = QCheckBox(page)
        self.web_open.setChecked(bool(web.get("open_browser_on_start", False)))
        form.addRow(self._label("settings.web_open_browser"), self.web_open)
        self.web_url = QLabel(page)
        self.web_url.setWordWrap(True)
        self.web_url.setTextInteractionFlags(Qt.TextSelectableByMouse)
        web_server = getattr(self._controller, "web", None)
        if web_server is not None:
            self.web_url.setText(f"http://{web_server.host}:{web_server.port}/")
        else:
            self.web_url.setText("—")
        form.addRow(self._label("settings.web_url"), self.web_url)
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
        """Persist the settings, then rebuild the semantic index in the background."""
        self._on_accept()
        self._controller.semantic_index_now()

    def _run_import(self) -> None:
        """Persist the current settings, then run the Joplin importer (SPEC/04)."""
        self._on_accept()
        self._controller.import_joplin()

    def _run_reindex(self) -> None:
        """Rebuild the full-text index (reclaims the inline-base64 bloat in the store)."""
        self._on_accept()
        self._controller.reindex_search()

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
                "chunking": str(self.chunk_combo.currentData()),
                "folder_states": dict(self._folder_states),
                "db_path": self.db_path_edit.text().strip(),
            },
            "import_joplin": {
                "mirror_root": self.mirror_edit.text().strip(),
                "sensitive_globs": [
                    part.strip()
                    for part in self.globs_edit.text().split(",")
                    if part.strip()
                ],
            },
            "web": {
                "enabled": bool(self.web_enabled.isChecked()),
                "host": self.web_host.text().strip() or "127.0.0.1",
                "port": int(self.web_port.value()),
                "allow_lan": bool(self.web_lan.isChecked()),
                "open_browser_on_start": bool(self.web_open.isChecked()),
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
        self.tabs.setTabText(4, i18n.tr("settings.tab_web"))
        self.tabs.setTabText(5, i18n.tr("settings.tab_log"))
        self.language_combo.setItemText(0, i18n.tr("language.fa"))
        self.language_combo.setItemText(1, i18n.tr("language.en"))
        for index, level in enumerate(_LEVELS):
            self.level_combo.setItemText(index, i18n.tr(_LEVEL_KEYS[level]))
        self.open_home_button.setText(i18n.tr("settings.open_folder"))
        self.verify_button.setText(i18n.tr("settings.verify"))
        self.threshold_hint.setText(i18n.tr("settings.plain_threshold_hint"))
        for position, mode in enumerate(CHUNK_MODES):
            self.chunk_combo.setItemText(position, i18n.tr(f"semantic.chunk_{mode}"))
        self.select_all_button.setText(i18n.tr("settings.semantic_select_all"))
        self.deselect_all_button.setText(i18n.tr("settings.semantic_deselect_all"))
        self.db_browse_button.setText(i18n.tr("settings.semantic_db_browse"))
        self.db_hint.setText(
            i18n.tr("settings.semantic_db_hint", path=self._default_db_path)
        )
        self.index_button.setText(i18n.tr("settings.semantic_index"))
        self.import_button.setText(i18n.tr("settings.run_import"))
        self.reindex_button.setText(i18n.tr("settings.reindex"))
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
