"""Fonts, layout direction and the small password-strength estimate (SPEC/03 §1, §2.2).

The Vazirmatn fonts bundled under ``assets/`` are loaded here; no new dependency (no
zxcvbn) is used for the strength hint.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QFontDatabase

from ..config import app_paths

FONT_REGULAR = "Vazirmatn-Regular.ttf"
FONT_BOLD = "Vazirmatn-Bold.ttf"

COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password",
        "password1",
        "passw0rd",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "abc123",
        "111111",
        "letmein",
        "welcome",
        "admin",
        "iloveyou",
        "monkey",
        "dragon",
        "master",
        "sunshine",
        "princess",
        "football",
        "baseball",
        "superman",
        "trustno1",
    }
)
"""A deliberately tiny list; only used to warn, never to block."""

_STRENGTH_KEYS = ("newvault.strength.weak", "newvault.strength.fair",
                  "newvault.strength.good", "newvault.strength.strong")


def load_fonts() -> str | None:
    """Load the bundled Vazirmatn faces and return the family name, if available."""
    family: str | None = None
    for filename in (FONT_REGULAR, FONT_BOLD):
        path = app_paths().assets_dir / filename
        if not path.is_file():
            continue
        font_id = QFontDatabase.addApplicationFont(str(path))
        if font_id < 0 or family is not None:
            continue
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            family = families[0]
    return family


#: The appearance choices offered in Settings → Appearance.
THEMES: tuple[str, ...] = ("system", "dark", "light")

_preference = "system"


def set_preference(value: Any) -> str:
    """Remember the theme preference for this process and return the effective value."""
    global _preference
    text = str(value or "system").strip().lower()
    _preference = text if text in THEMES else "system"
    return _preference


def preference() -> str:
    """Return the stored preference (``system`` / ``dark`` / ``light``)."""
    return _preference


def detect_system_theme(app: Any = None) -> str:
    """Return ``"dark"`` or ``"light"`` for the desktop.

    Qt's colour-scheme hint comes first — it reads the platform theme, which is what actually
    works on Wayland/KDE. The luminance of the ``Window`` colour is the fallback, and a
    headless run (no application) reports ``"light"``.
    """
    try:
        from PySide6.QtCore import Qt as _Qt
        from PySide6.QtGui import QGuiApplication, QPalette
        from PySide6.QtWidgets import QApplication

        application: Any = app or QApplication.instance()
        if application is None:
            return "light"
        hints = QGuiApplication.styleHints() if QGuiApplication.instance() else None
        scheme = getattr(hints, "colorScheme", None)
        if scheme is not None and hints is not None:
            if hints.colorScheme() == _Qt.ColorScheme.Dark:
                return "dark"
            if hints.colorScheme() == _Qt.ColorScheme.Light:
                return "light"
        color = application.palette().color(QPalette.ColorRole.Window)
        # Perceived luminance (ITU-R BT.601) — under 40 % means a dark theme.
        if (0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue()) < 102:
            return "dark"
    except Exception:  # noqa: BLE001 - no Qt, no palette: keep the light default
        return "light"
    return "light"


def is_dark(app: Any = None) -> bool:
    """True when the effective theme is dark — the preference wins over the desktop."""
    choice = preference()
    if choice == "dark":
        return True
    if choice == "light":
        return False
    return detect_system_theme(app) == "dark"


def colors(app: Any = None) -> dict[str, str]:
    """Return the colour table of the effective theme (``bg``, ``text``, ``code_bg``, …)."""
    from .highlight import pick_palette

    return pick_palette(app)


def apply(app: Any, language: str, *, dark: bool | None = None) -> str | None:
    """Apply the theme, the layout direction and the bundled UI font for ``language``.

    A dark theme sets Qt's Fusion style plus an explicit palette: the desktop's own scheme is
    not always reported to the process, and without this the plain widgets (text areas, table
    cells, the web preview behind its HTML) keep their white base — a white slab in the middle
    of a dark window.
    """
    if dark is None:
        dark = is_dark(app)
    _apply_palette(app, dark)
    app.setLayoutDirection(Qt.RightToLeft if language == "fa" else Qt.LeftToRight)
    family = load_fonts()
    if language == "fa" and family:
        app.setFont(QFont(family, 10))
    return family


def _apply_palette(app: Any, dark: bool) -> None:
    """Give ``app`` the Fusion style and the palette matching ``dark``."""
    try:
        from PySide6.QtGui import QColor, QPalette

        from .highlight import pick_palette

        colors = pick_palette(app, dark=dark)
        if hasattr(app, "setStyle"):
            app.setStyle("Fusion")
        palette = QPalette()
        base = QColor(colors["bg"])
        surface = QColor(colors["code_bg"])
        text = QColor(colors["text"])
        palette.setColor(QPalette.ColorRole.Window, base)
        palette.setColor(QPalette.ColorRole.WindowText, text)
        palette.setColor(QPalette.ColorRole.Base, surface if dark else base)
        palette.setColor(QPalette.ColorRole.AlternateBase, base if dark else surface)
        palette.setColor(QPalette.ColorRole.Text, text)
        palette.setColor(QPalette.ColorRole.Button, surface)
        palette.setColor(QPalette.ColorRole.ButtonText, text)
        palette.setColor(QPalette.ColorRole.ToolTipBase, surface)
        palette.setColor(QPalette.ColorRole.ToolTipText, text)
        palette.setColor(QPalette.ColorRole.Highlight, QColor(colors["accent"]))
        palette.setColor(
            QPalette.ColorRole.HighlightedText, base if dark else QColor(colors["bg"])
        )
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(colors["muted"]))
        palette.setColor(QPalette.ColorRole.Link, QColor(colors["link"]))
        try:
            disabled = QColor(colors["muted"])
            for role in (QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText,
                         QPalette.ColorRole.WindowText):
                palette.setColor(QPalette.ColorGroup.Disabled, role, disabled)
        except Exception:  # noqa: BLE001 - cosmetic only
            pass
        app.setPalette(palette)
    except Exception:  # noqa: BLE001 - headless tests have no real application
        pass


def refresh(app: Any = None) -> None:
    """Re-apply the palette after the preference changed (Settings → Appearance)."""
    target = app
    if target is None:
        try:
            from PySide6.QtWidgets import QApplication

            target = QApplication.instance()
        except Exception:  # noqa: BLE001 - no Qt at all
            target = None
    if target is None:
        return
    _apply_palette(target, is_dark(target))


def estimate_strength(password: str) -> int:
    """Return a coarse 0..3 strength score for ``password``."""
    if not password:
        return 0
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(set(password)) >= 8:
        score += 1
    if any(ch.isdigit() for ch in password) and any(ch.isalpha() for ch in password):
        score += 1
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 1)
    return min(score, 3)


def strength_key(password: str) -> str:
    """Return the i18n key describing the strength of ``password``."""
    return _STRENGTH_KEYS[estimate_strength(password)]


def is_weak(password: str) -> bool:
    """Return True when the password should carry a warning (< 10 chars or common)."""
    return len(password) < 10 or password.lower() in COMMON_PASSWORDS


__all__ = [
    "FONT_REGULAR",
    "FONT_BOLD",
    "COMMON_PASSWORDS",
    "load_fonts",
    "apply",
    "estimate_strength",
    "strength_key",
    "is_weak",
]
