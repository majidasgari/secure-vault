"""Native plain-text viewer for ``secret``/``secretfile`` content (SPEC/03 §2.4, §9).

This dialog deliberately uses only Qt widgets: secret content must never reach a web engine. The
module exposes ``last_text`` (and ``uses_web_engine``) so the UI smoke test can assert the native
path was taken.

A credential body gets the actions its fields call for, each with its own copy button:

* **user name** and **password** — copied without ever being displayed (this is how the password is
  handed over: it exists only inside this dialog, so the clipboard is the one place it goes);
* **one-time code** — a live TOTP generated in-process by :mod:`vault.core.totp`, with a countdown
  and a progress bar.

Nothing is sent anywhere and the agent role has no way to ask for any of it: the copy buttons are
built from the parsed body, in the UI process, and the notification a copy raises names the file
and the field only.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core import credentials, totp
from . import i18n, notifications, theme

#: Families tried for the code/secret text (the app font has no tabular digits).
_MONOSPACE = ("ui-monospace", "DejaVu Sans Mono", "Consolas", "monospace")

last_text: str | None = None
"""Content of the most recently opened native viewer (module-level for the tests)."""

last_path: str | None = None
"""Path of the most recently opened native viewer."""

last_otp: dict[str, Any] | None = None
"""Display descriptor of the OTP the last viewer showed (``None`` when it had none)."""

uses_web_engine = False
"""Always False: the native viewer never imports or creates a web view."""

web_views_created = 0
"""Number of web views ever created by this module (always 0)."""


class SecretViewer(QDialog):
    """Read-only native viewer for a single secret file."""

    def __init__(
        self, parent: Any, path: str, text: str, *, tray: Any = None
    ) -> None:
        """Build the viewer for ``path`` showing ``text``."""
        super().__init__(parent)
        self.path = path
        self.text = text
        self._tray = tray
        self.setModal(False)
        self.resize(680, 460)

        layout = QVBoxLayout(self)
        self.path_label = QLabel(path, self)
        self.path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.path_label)

        # --- per-field copy actions for a credential body ---
        # The values exist only inside this dialog (the agent/bridge never receive a secretfile's
        # content), so copying one is the same exposure as the existing whole-body copy: it goes to
        # the user's own clipboard and nowhere else. A button is only built when its field exists.
        parsed = credentials.parse_body(text or "")
        self.username = str(parsed.get("username") or "")
        self.password = str(parsed.get("password") or "")
        self.field_actions = QWidget(self)
        actions = QHBoxLayout(self.field_actions)
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(6)
        self.copy_username_button = QPushButton(self.field_actions)
        self.copy_username_button.clicked.connect(self.copy_username)
        self.copy_username_button.setVisible(bool(self.username))
        actions.addWidget(self.copy_username_button)
        self.copy_password_button = QPushButton(self.field_actions)
        self.copy_password_button.clicked.connect(self.copy_password)
        self.copy_password_button.setVisible(bool(self.password))
        actions.addWidget(self.copy_password_button)
        actions.addStretch(1)
        self.field_actions.setVisible(bool(self.username or self.password))
        layout.addWidget(self.field_actions)

        # --- live one-time code (hidden when the body carries no OTP field) ---
        self._otp_value = totp.otp_value_from_body(text)
        self.otp: totp.OtpCode | None = (
            totp.value_to_code(self._otp_value) if self._otp_value else None
        )
        self.otp_box = QWidget(self)
        otp_layout = QVBoxLayout(self.otp_box)
        otp_layout.setContentsMargins(0, 0, 0, 0)
        otp_layout.setSpacing(4)

        head = QHBoxLayout()
        self.otp_title = QLabel(self.otp_box)
        head.addWidget(self.otp_title)
        head.addStretch(1)
        self.otp_remaining = QLabel(self.otp_box)
        self.otp_remaining.setTextInteractionFlags(Qt.TextSelectableByMouse)
        head.addWidget(self.otp_remaining)
        self.otp_copy_button = QPushButton(self.otp_box)
        self.otp_copy_button.clicked.connect(self.copy_otp)
        head.addWidget(self.otp_copy_button)
        otp_layout.addLayout(head)

        self.otp_code = QLabel(self.otp_box)
        self.otp_code.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.otp_code.setLayoutDirection(Qt.LeftToRight)
        self.otp_code.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        font = QFont(self.otp_code.font())
        font.setFamilies(list(_MONOSPACE))
        font.setPointSize(font.pointSize() + 8)
        font.setBold(True)
        self.otp_code.setFont(font)
        otp_layout.addWidget(self.otp_code)

        self.otp_bar = QProgressBar(self.otp_box)
        self.otp_bar.setTextVisible(False)
        self.otp_bar.setFixedHeight(6)
        self.otp_bar.setLayoutDirection(Qt.LeftToRight)
        otp_layout.addWidget(self.otp_bar)
        self._otp_sheet = ""

        self.otp_box.setVisible(self.otp is not None)
        layout.addWidget(self.otp_box)

        self.edit = QPlainTextEdit(self)
        self.edit.setReadOnly(True)
        self.edit.setPlainText(text)
        layout.addWidget(self.edit, 1)

        self.buttons = QDialogButtonBox(self)
        self.copy_button = QPushButton(i18n.tr("viewer.copy"), self)
        self.copy_button.clicked.connect(self.copy_all)
        self.buttons.addButton(self.copy_button, QDialogButtonBox.ActionRole)
        self.buttons.addButton(QDialogButtonBox.Close)
        self.buttons.rejected.connect(self.close)
        self.buttons.clicked.connect(self._on_clicked)
        layout.addWidget(self.buttons)

        # One tick a second keeps a live code honest without a busy loop; the dialog stops the
        # timer whenever it is not on screen.
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.refresh_otp)
        if self.otp is not None and self.otp.live:
            self._timer.start()

        self.retranslate()
        self._render_otp()
        i18n.bind(self, self.retranslate)

    # --------------------------------------------------------------------- otp
    def refresh_otp(self, at: float | None = None) -> None:
        """Regenerate the code (the timer's slot; ``at`` is for the tests) and re-render."""
        if not self._otp_value:
            return
        fresh = totp.value_to_code(self._otp_value, at)
        if fresh is None:
            return
        self.otp = fresh
        self._render_otp()

    def _render_otp(self) -> None:
        """Paint the current code, countdown and progress bar."""
        if self.otp is None:
            self.otp_box.setVisible(False)
            return
        self.otp_box.setVisible(True)
        self._style_otp()
        self.otp_code.setText(self.otp.display)
        self.otp_bar.setVisible(self.otp.live)
        if self.otp.live and self.otp.remaining is not None:
            self.otp_bar.setRange(0, self.otp.period)
            self.otp_bar.setValue(self.otp.remaining)
            self.otp_remaining.setText(
                i18n.tr("viewer.otp_remaining", seconds=self.otp.remaining)
            )
        else:
            self.otp_remaining.setText(i18n.tr("viewer.otp_static"))

    def _style_otp(self) -> None:
        """Paint the countdown bar with the theme's colours.

        Fusion's default progress bar is a dark track with a dark chunk — invisible on the dark
        theme. The stylesheet is rebuilt only when the colour table changes (a theme switch), not
        on every tick.
        """
        palette = theme.colors()
        sheet = (
            "QProgressBar { background: %(code_bg)s; border: 1px solid %(border)s;"
            " border-radius: 3px; }"
            "QProgressBar::chunk { background: %(accent)s; border-radius: 2px; }"
        ) % {"code_bg": palette["code_bg"], "border": palette["border"],
             "accent": palette["accent"]}
        if sheet != self._otp_sheet:
            self._otp_sheet = sheet
            self.otp_bar.setStyleSheet(sheet)

    def copy_otp(self) -> None:
        """Copy only the code to the clipboard and notify."""
        if self.otp is None:
            return
        self._copy_field(self.otp.code, "viewer.copied_otp")

    def copy_username(self) -> None:
        """Copy the parsed user name to the clipboard and notify."""
        self._copy_field(self.username, "viewer.copied_username")

    def copy_password(self) -> None:
        """Copy the parsed password to the clipboard and notify."""
        self._copy_field(self.password, "viewer.copied_password")

    def _copy_field(self, value: str, key: str) -> None:
        """Put one field on the clipboard.

        The value is used once and never stored, logged or put into the notification: the notice
        names the file and the field only, so a tray bubble can never carry a secret.
        """
        if not value:
            return
        QApplication.clipboard().setText(value)
        notifications.notify(
            i18n.tr("notification.copied"),
            i18n.tr(key, path=self.path),
            tray=self._tray,
        )

    # ------------------------------------------------------------------- events
    def showEvent(self, event: Any) -> None:
        """Restart the countdown whenever the viewer comes back on screen."""
        super().showEvent(event)
        if self.otp is not None and self.otp.live:
            self._timer.start()

    def hideEvent(self, event: Any) -> None:
        """Stop the countdown while the viewer is off screen."""
        self._timer.stop()
        super().hideEvent(event)

    def closeEvent(self, event: Any) -> None:
        """Stop the countdown when the viewer closes."""
        self._timer.stop()
        super().closeEvent(event)

    # ------------------------------------------------------------------ buttons
    def _on_clicked(self, button: Any) -> None:
        """Close the dialog when the Close button is pressed."""
        if self.buttons.standardButton(button) == QDialogButtonBox.Close:
            self.close()

    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.setWindowTitle(i18n.tr("viewer.title"))
        self.copy_button.setText(i18n.tr("viewer.copy"))
        self.copy_username_button.setText(i18n.tr("viewer.copy_username"))
        self.copy_password_button.setText(i18n.tr("viewer.copy_password"))
        self.otp_title.setText(i18n.tr("viewer.otp_title"))
        self.otp_copy_button.setText(i18n.tr("viewer.copy_otp"))
        self._render_otp()

    def copy_all(self) -> None:
        """Copy the whole content to the clipboard and notify."""
        QApplication.clipboard().setText(self.text)
        notifications.notify(
            i18n.tr("notification.copied"),
            i18n.tr("viewer.copied_body", path=self.path),
            tray=self._tray,
        )


def open_viewer(parent: Any, path: str, text: str, *, tray: Any = None) -> SecretViewer:
    """Open (non-modally) the native viewer and remember the last content/OTP/actions."""
    global last_text, last_path, last_otp, last_actions
    last_text = text
    last_path = path
    dialog = SecretViewer(parent, path, text, tray=tray)
    last_otp = dialog.otp.to_dict() if dialog.otp is not None else None
    # Booleans only — never the values, so a self-test can assert the buttons without a secret.
    last_actions = {
        "username": bool(dialog.username),
        "password": bool(dialog.password),
        "otp": dialog.otp is not None,
    }
    dialog.show()
    return dialog


__all__ = [
    "SecretViewer",
    "open_viewer",
    "last_text",
    "last_path",
    "last_otp",
    "last_actions",
    "uses_web_engine",
    "web_views_created",
]
