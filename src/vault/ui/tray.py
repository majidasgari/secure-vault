"""System tray icon with graceful degradation (SPEC/03 §2.6, §6).

When no system tray is available (offscreen, minimal desktops) the icon is skipped
silently and :attr:`available` stays False; everything else keeps working.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QObject
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from . import i18n


class TrayIcon(QObject):
    """A thin wrapper over :class:`QSystemTrayIcon` that never raises."""

    def __init__(
        self,
        *,
        icon_path: Path | str | None = None,
        on_show: Callable[[], None] | None = None,
        on_lock: Callable[[], None] | None = None,
        on_search: Callable[[], None] | None = None,
        on_settings: Callable[[], None] | None = None,
        on_quit: Callable[[], None] | None = None,
        parent: Any = None,
    ) -> None:
        """Try to install a tray icon; degrade silently when unavailable."""
        super().__init__(parent)
        self.available = False
        self.tray: QSystemTrayIcon | None = None
        self.actions: dict[str, QAction] = {}
        self._locked = False

        try:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            icon = QIcon(str(icon_path)) if icon_path else QIcon()
            self.tray = QSystemTrayIcon(icon, parent)
            menu = QMenu()
            for name, callback in (
                ("show", on_show),
                ("lock", on_lock),
                ("search", on_search),
                ("settings", on_settings),
                ("quit", on_quit),
            ):
                action = QAction(menu)
                if callback is not None:
                    action.triggered.connect(callback)
                menu.addAction(action)
                self.actions[name] = action
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self._on_activated)
            self.tray.show()
            self.available = True
            self.retranslate()
        except Exception:  # noqa: BLE001 - a tray must never stop the app
            self.available = False
            self.tray = None

    def _on_activated(self, reason: Any) -> None:
        """Show the window when the icon is activated."""
        if self.tray is None:
            return
        if reason == QSystemTrayIcon.Trigger:
            callback = self.actions.get("show")
            if callback is not None:
                callback.trigger()

    def notify(self, title: str, body: str) -> None:
        """Show a balloon message when a tray is available."""
        if self.tray is not None:
            self.tray.showMessage(title, body)

    def set_locked(self, locked: bool) -> None:
        """Update the tooltip to reflect the lock state."""
        self._locked = bool(locked)
        if self.tray is not None:
            key = "tray.tooltip_locked" if locked else "tray.tooltip_unlocked"
            self.tray.setToolTip(i18n.tr(key))

    def hide(self) -> None:
        """Hide the tray icon (used on quit)."""
        if self.tray is not None:
            self.tray.hide()

    def retranslate(self) -> None:
        """Re-apply translated menu labels and tooltip."""
        labels = {
            "show": "tray.show",
            "lock": "tray.lock",
            "search": "tray.search",
            "settings": "tray.settings",
            "quit": "tray.quit",
        }
        for name, action in self.actions.items():
            action.setText(i18n.tr(labels[name]))
        self.set_locked(self._locked)


__all__ = ["TrayIcon"]
