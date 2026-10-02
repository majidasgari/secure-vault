"""Restore-from-S3 wizard (docs/SYNC.md §9).

The dialog collects the bucket coordinates and (optionally) the master password of the
vault stored there, can probe the bucket before anything is written, and hands the
coordinates back to the controller, which runs
:func:`vault.core.remote_import.import_vault` in a background thread.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from ..config import DEFAULT_VAULT_HOME
from ..core import remote_import
from ..core.s3 import S3Client, S3Config
from . import i18n

#: Catalogue keys for the phases :func:`remote_import.import_vault` reports.
PROGRESS_KEYS = {
    "probe": "importvault.progress_probe",
    "files": "importvault.progress_files",
    "index": "importvault.progress_index",
    "store": "importvault.progress_store",
    "install": "importvault.progress_install",
    "done": "importvault.progress_done",
}


def progress_text(phase: str, done: int, total: int) -> str:
    """Translate one ``(phase, done, total)`` progress update."""
    key = PROGRESS_KEYS.get(phase, "importvault.progress_probe")
    if key == "importvault.progress_files":
        return i18n.tr(key, done=done, total=max(total, 0))
    return i18n.tr(key)


def megabytes(size: int | float) -> str:
    """Render a byte count as megabytes with one decimal (locale-independent digits)."""
    return f"{float(size) / (1024 * 1024):.1f}"


class ImportJob:
    """Run one background call while the GUI thread keeps painting.

    Qt widgets may only be touched from the GUI thread, so the worker never calls back into
    Qt: it mutates :attr:`state` and the GUI pumps its event loop until ``done`` flips.
    """

    def __init__(self, work: Callable[[dict[str, Any], threading.Event], Any]) -> None:
        """Wrap ``work(state, cancel_event)`` for background execution."""
        self.state: dict[str, Any] = {
            "phase": "probe",
            "done": 0,
            "total": 0,
            "finished": False,
            "result": None,
            "error": None,
        }
        self.cancel = threading.Event()
        self._work = work

    def start(self) -> "ImportJob":
        """Start the worker thread and return self for chaining."""
        threading.Thread(target=self._run, name="sv-import", daemon=True).start()
        return self

    def _run(self) -> None:
        """Execute the work item, recording the outcome in :attr:`state`."""
        try:
            self.state["result"] = self._work(self.state, self.cancel)
        except BaseException as exc:  # noqa: BLE001 - reported to the user by the caller
            self.state["error"] = exc
        finally:
            self.state["finished"] = True

    def report(self, phase: str, done: int, total: int) -> None:
        """Progress sink handed to the core import."""
        self.state["phase"] = phase
        self.state["done"] = done
        self.state["total"] = total

    def pump(self, app: Any, *, tick: Callable[[], None] | None = None) -> None:
        """Process GUI events until the worker finishes."""
        while not self.state["finished"]:
            app.processEvents()
            if tick is not None:
                tick()
            time.sleep(0.03)
        if tick is not None:
            tick()


class ImportVaultDialog(QDialog):
    """Ask where the vault should live and which bucket to restore it from."""

    def __init__(
        self,
        parent: Any = None,
        *,
        home: Path | str = DEFAULT_VAULT_HOME,
        credentials: dict[str, Any] | None = None,
        existing_vault_id: str = "",
    ) -> None:
        """Build the wizard, pre-filling the machine-local coordinates when we know them."""
        super().__init__(parent)
        self.setModal(True)
        self._existing_vault_id = existing_vault_id
        credentials = dict(credentials or {})
        last = credentials.get("last_source")
        last = last if isinstance(last, dict) else {}

        layout = QVBoxLayout(self)
        self.hint_label = QLabel(self)
        self.hint_label.setWordWrap(True)
        layout.addWidget(self.hint_label)

        form = QFormLayout()
        folder_row = QHBoxLayout()
        self.folder_edit = QLineEdit(str(home), self)
        self.browse_button = QPushButton(self)
        self.browse_button.clicked.connect(self._browse)
        folder_row.addWidget(self.folder_edit, 1)
        folder_row.addWidget(self.browse_button)
        self.folder_label = QLabel(self)
        form.addRow(self.folder_label, folder_row)

        self.bucket_edit = QLineEdit(str(last.get("bucket") or ""), self)
        self.bucket_label = QLabel(self)
        form.addRow(self.bucket_label, self.bucket_edit)

        self.prefix_edit = QLineEdit(str(last.get("prefix") or ""), self)
        self.prefix_label = QLabel(self)
        form.addRow(self.prefix_label, self.prefix_edit)

        self.endpoint_edit = QLineEdit(str(last.get("endpoint") or ""), self)
        self.endpoint_label = QLabel(self)
        form.addRow(self.endpoint_label, self.endpoint_edit)

        self.region_edit = QLineEdit(str(last.get("region") or ""), self)
        self.region_label = QLabel(self)
        form.addRow(self.region_label, self.region_edit)

        self.access_edit = QLineEdit(str(credentials.get("access_key") or ""), self)
        self.access_label = QLabel(self)
        form.addRow(self.access_label, self.access_edit)

        self.secret_edit = QLineEdit(str(credentials.get("secret_key") or ""), self)
        self.secret_edit.setEchoMode(QLineEdit.Password)
        self.secret_label = QLabel(self)
        form.addRow(self.secret_label, self.secret_edit)

        self.password_edit = QLineEdit(self)
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_label = QLabel(self)
        form.addRow(self.password_label, self.password_edit)
        layout.addLayout(form)

        self.password_hint = QLabel(self)
        self.password_hint.setWordWrap(True)
        layout.addWidget(self.password_hint)

        self.replace_check = QCheckBox(self)
        self.replace_check.setVisible(bool(existing_vault_id))
        layout.addWidget(self.replace_check)

        self.replace_hint = QLabel(self)
        self.replace_hint.setWordWrap(True)
        self.replace_hint.setVisible(bool(existing_vault_id))
        layout.addWidget(self.replace_hint)

        self.status_label = QLabel(self)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.error_label = QLabel(self)
        self.error_label.setObjectName("import-error")
        self.error_label.setStyleSheet("color: #b00020;")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        self.check_button = QPushButton(self)
        self.check_button.clicked.connect(self._check)
        layout.addWidget(self.check_button)

        self.buttons = QDialogButtonBox(self)
        self.import_button = self.buttons.addButton(
            i18n.tr("importvault.import"), QDialogButtonBox.AcceptRole
        )
        self.buttons.addButton(QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self._on_accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.retranslate()
        i18n.bind(self, self.retranslate)

    # ------------------------------------------------------------------ helpers
    def _browse(self) -> None:
        """Pick the folder the vault should be restored into."""
        chosen = QFileDialog.getExistingDirectory(
            self, i18n.tr("importvault.folder"), self.folder_edit.text()
        )
        if chosen:
            self.folder_edit.setText(chosen)

    def config(self) -> S3Config | None:
        """Build an :class:`S3Config` from the fields, or show an error and return None."""
        bucket = self.bucket_edit.text().strip()
        access = self.access_edit.text().strip()
        secret = self.secret_edit.text().strip()
        if not bucket or not access or not secret:
            self.error_label.setText(i18n.tr("importvault.error.missing_fields"))
            return None
        self.error_label.setText("")
        return S3Config(
            enabled=True,
            bucket=bucket,
            prefix=self.prefix_edit.text().strip(),
            endpoint=self.endpoint_edit.text().strip(),
            region=self.region_edit.text().strip(),
            access_key=access,
            secret_key=secret,
        )

    def _check(self) -> None:
        """Probe the bucket in the background and show what is stored there."""
        config = self.config()
        if config is None:
            return
        self.check_button.setEnabled(False)
        self.status_label.setText(i18n.tr("importvault.checking"))

        def work(state: dict[str, Any], _cancel: threading.Event) -> Any:
            return remote_import.probe_remote(S3Client(config), config)

        job = ImportJob(work).start()
        job.pump(QApplication.instance())
        self.check_button.setEnabled(True)
        if job.state["error"] is not None:
            self.status_label.setText("")
            self.error_label.setText(self._error_text(job.state["error"]))
            return
        info, _identity = job.state["result"]
        self.status_label.setText(self._summary_text(info))

    def _summary_text(self, info: Any) -> str:
        """Render the probe result for the status label."""
        lines = [
            i18n.tr(
                "importvault.summary",
                vault_id=info.vault_id,
                files=info.files,
                folders=info.folders,
                versions=info.versions,
                size=megabytes(info.payload_bytes),
                index=megabytes(info.index_bytes),
                store=megabytes(info.store_bytes),
                blobs=info.blobs,
                blob_size=megabytes(info.blob_bytes),
            )
        ]
        if info.created_at:
            lines.append(
                i18n.tr(
                    "importvault.summary_created",
                    when=datetime.fromtimestamp(info.created_at / 1000).strftime(
                        "%Y-%m-%d %H:%M"
                    ),
                )
            )
        if info.lock:
            lines.append(
                i18n.tr("importvault.lock_held", host=str(info.lock.get("host") or "?"))
            )
        return "\n".join(lines)

    @staticmethod
    def _error_text(exc: BaseException) -> str:
        """Translate a failed probe/import reason."""
        reason = str(getattr(exc, "message", "") or exc)
        return i18n.sync_reason(reason)

    def _on_accept(self) -> None:
        """Validate the fields, then accept the dialog."""
        if not self.folder_edit.text().strip():
            self.error_label.setText(i18n.tr("importvault.error.folder"))
            return
        if self.config() is None:
            return
        if self._existing_vault_id and not self.replace_check.isChecked():
            self.error_label.setText(i18n.tr("importvault.error.replace_needed"))
            return
        self.accept()

    def values(self) -> tuple[Path, S3Config, str | None, bool]:
        """Return ``(home, config, password, replace)`` for the accepted dialog."""
        config = self.config()
        assert config is not None  # guaranteed by ``_on_accept``
        password = self.password_edit.text()
        return (
            Path(self.folder_edit.text().strip()),
            config,
            password or None,
            bool(self.replace_check.isChecked()),
        )

    # ------------------------------------------------------------------ i18n
    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.setWindowTitle(i18n.tr("importvault.window_title"))
        self.hint_label.setText(i18n.tr("importvault.hint"))
        self.folder_label.setText(i18n.tr("importvault.folder"))
        self.browse_button.setText(i18n.tr("importvault.browse"))
        self.bucket_label.setText(i18n.tr("importvault.bucket"))
        self.prefix_label.setText(i18n.tr("importvault.prefix"))
        self.endpoint_label.setText(i18n.tr("importvault.endpoint"))
        self.region_label.setText(i18n.tr("importvault.region"))
        self.access_label.setText(i18n.tr("importvault.access_key"))
        self.secret_label.setText(i18n.tr("importvault.secret_key"))
        self.password_label.setText(i18n.tr("importvault.password"))
        self.password_hint.setText(i18n.tr("importvault.password_hint"))
        self.replace_check.setText(i18n.tr("importvault.replace"))
        self.replace_hint.setText(i18n.tr("importvault.replace_hint"))
        self.check_button.setText(i18n.tr("importvault.check"))
        if self.import_button is not None:
            self.import_button.setText(i18n.tr("importvault.import"))


__all__ = ["ImportJob", "ImportVaultDialog", "megabytes", "progress_text"]
