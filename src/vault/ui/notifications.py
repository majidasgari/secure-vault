"""Desktop notifications with a headless fallback (SPEC/03 §6).

``notify`` tries ``QSystemTrayIcon.showMessage`` when a tray is available and always
records the message in a module-level list so tests can assert on it without a
notification daemon.
"""

from __future__ import annotations

from typing import Any

_recent: list[dict[str, Any]] = []


def notify(title: str, body: str, *, tray: Any = None) -> dict[str, Any]:
    """Show a notification (best effort) and record it for the tests.

    Returns the recorded entry. Never raises when no tray/daemon exists.
    """
    entry: dict[str, Any] = {"title": title, "body": body, "shown": False}
    if tray is not None:
        try:
            tray.notify(title, body)
            entry["shown"] = True
        except Exception:  # noqa: BLE001 - notifications are best effort
            entry["shown"] = False
    _recent.append(entry)
    return entry


def recent() -> list[dict[str, Any]]:
    """Return a copy of the recorded notifications, oldest first."""
    return [dict(item) for item in _recent]


def clear() -> None:
    """Forget every recorded notification (used by tests)."""
    _recent.clear()


__all__ = ["notify", "recent", "clear"]
