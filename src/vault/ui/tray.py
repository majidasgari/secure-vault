"""System tray icon: the always-on shell (SPEC/03 §2.6, SPEC/09 §A–C).

The tray is the secret gate and the live "which file is being read right now" surface.
It degrades silently when no system tray is available (offscreen, minimal desktops):
:attr:`available` stays False and everything else keeps working.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QObject
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from ..util import now_ms
from . import i18n

#: A secret/secretfile read within this window marks the tray badge (SPEC/09 §8).
SECRET_RECENT_MS = 60_000

#: How many events the "last reads" submenu shows (SPEC/09 §8).
RECENT_LIMIT = 10

_LEVEL_KEYS = {
    "normal": "level.normal",
    "secret": "level.secret",
    "secretfile": "level.secretfile",
}

#: Activity kind -> label ("read", "write", …) for the tray menu and the tooltip.
_ACTION_KEYS = {
    "read": "tray.action_read",
    "write": "tray.action_write",
    "delete": "tray.action_delete",
    "move": "tray.action_move",
    "mkdir": "tray.action_mkdir",
    "list": "tray.action_list",
    "search": "tray.action_search",
}


class TrayIcon(QObject):
    """A thin wrapper over :class:`QSystemTrayIcon` that never raises."""

    def __init__(
        self,
        *,
        icon_path: Path | str | None = None,
        on_show: Callable[[], None] | None = None,
        on_open_web: Callable[[], None] | None = None,
        on_copy_link: Callable[[], None] | None = None,
        on_lock: Callable[[], None] | None = None,
        on_settings: Callable[[], None] | None = None,
        on_quit: Callable[[], None] | None = None,
        on_recent: Callable[[str], None] | None = None,
        on_search: Callable[[], None] | None = None,
        parent: Any = None,
    ) -> None:
        """Try to install a tray icon; degrade silently when unavailable."""
        super().__init__(parent)
        self.available = False
        self.tray: QSystemTrayIcon | None = None
        self.actions: dict[str, QAction] = {}
        self.recent_menu: QMenu | None = None
        self._locked = False
        self._last_read: dict[str, Any] | None = None
        self._events: list[dict[str, Any]] = []
        self.secret_recent = False
        self._on_recent = on_recent

        try:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            icon = QIcon(str(icon_path)) if icon_path else QIcon()
            self.tray = QSystemTrayIcon(icon, parent)
            menu = QMenu()
            for name, callback in (
                ("show", on_show),
                ("open_web", on_open_web),
                ("copy_link", on_copy_link),
            ):
                action = QAction(menu)
                if callback is not None:
                    action.triggered.connect(callback)
                menu.addAction(action)
                self.actions[name] = action
            self.recent_menu = menu.addMenu("")
            menu.addSeparator()
            for name, callback in (
                ("lock", on_lock),
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

    # ------------------------------------------------------------------ activity
    def set_activity(self, events: list[dict[str, Any]]) -> None:
        """Replace the feed and refresh the tooltip, badge and recent submenu."""
        self._events = list(events)[-RECENT_LIMIT * 4 :]
        reads = [event for event in self._events if event.get("kind") == "read"]
        self._last_read = reads[-1] if reads else None
        threshold = now_ms() - SECRET_RECENT_MS
        self.secret_recent = any(
            event.get("sensitivity") in ("secret", "secretfile")
            and int(event.get("ts", 0)) >= threshold
            for event in reads
        )
        self._rebuild_recent()
        self._apply_tooltip()

    def last_read(self) -> dict[str, Any] | None:
        """Return the most recent read event (or None)."""
        return self._last_read

    def _rebuild_recent(self) -> None:
        """Fill the "last reads" submenu with up to ten newest-first entries."""
        if self.recent_menu is None:
            return
        self.recent_menu.clear()
        events = list(reversed(self._events))[:RECENT_LIMIT]
        if not events:
            self.recent_menu.setEnabled(False)
            return
        self.recent_menu.setEnabled(True)
        for event in events:
            label = i18n.tr(
                "tray.recent_entry",
                time=_format_time(event.get("ts")),
                action=i18n.tr(
                    _ACTION_KEYS.get(str(event.get("kind") or "read"), "tray.action_read")
                ),
                source=str(event.get("source", "")),
                path="/" + str(event.get("path", "")).lstrip("/") if event.get("path") else "-",
                level=i18n.tr(
                    _LEVEL_KEYS.get(str(event.get("sensitivity") or "normal"), "level.normal")
                ),
            )
            action = self.recent_menu.addAction(label)
            path = event.get("path")
            if self._on_recent is not None and path:
                action.triggered.connect(
                    lambda _checked=False, value=path: self._on_recent(value)
                )

    def _apply_tooltip(self) -> None:
        """Compose the tooltip from the lock state and the last agent activity."""
        if self.tray is None:
            return
        if self._locked:
            text = i18n.tr("tray.tooltip_locked")
        else:
            text = i18n.tr("tray.tooltip_unlocked")
            last = self._events[-1] if self._events else None
            if last is not None and last.get("path"):
                age = max(0, int((now_ms() - int(last.get("ts", 0))) / 1000))
                text = i18n.tr(
                    "tray.tooltip_last_action",
                    state=text,
                    action=i18n.tr(
                        _ACTION_KEYS.get(str(last.get("kind") or "read"), "tray.action_read")
                    ),
                    path="/" + str(last.get("path", "")).lstrip("/"),
                    seconds=age,
                )
            elif self._last_read is not None:
                age = max(0, int((now_ms() - int(self._last_read.get("ts", 0))) / 1000))
                text = i18n.tr(
                    "tray.tooltip_last_read",
                    state=text,
                    path="/" + str(self._last_read.get("path", "")).lstrip("/"),
                    seconds=age,
                )
        if self.secret_recent:
            text = "🔑 " + text
        self.tray.setToolTip(text)

    def set_locked(self, locked: bool) -> None:
        """Update the tooltip to reflect the lock state."""
        self._locked = bool(locked)
        self._apply_tooltip()

    def hide(self) -> None:
        """Hide the tray icon (used on quit)."""
        if self.tray is not None:
            self.tray.hide()

    def retranslate(self) -> None:
        """Re-apply translated menu labels and tooltip."""
        labels = {
            "show": "tray.show",
            "open_web": "tray.open_web",
            "copy_link": "tray.copy_link",
            "lock": "tray.lock",
            "settings": "tray.settings",
            "quit": "tray.quit",
        }
        for name, action in self.actions.items():
            action.setText(i18n.tr(labels[name]))
        if self.recent_menu is not None:
            self.recent_menu.setTitle(i18n.tr("tray.recent"))
        self._rebuild_recent()
        self._apply_tooltip()


def _format_time(ts: Any) -> str:
    """Render an epoch-millisecond timestamp as ``HH:MM:SS`` (best effort)."""
    try:
        from datetime import datetime

        return datetime.fromtimestamp(int(ts) / 1000.0).strftime("%H:%M:%S")
    except (TypeError, ValueError, OSError):
        return ""


__all__ = ["TrayIcon", "SECRET_RECENT_MS", "RECENT_LIMIT"]
