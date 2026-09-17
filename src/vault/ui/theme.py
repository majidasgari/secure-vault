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


def apply(app: Any, language: str) -> str | None:
    """Apply the layout direction and the bundled UI font for ``language``."""
    app.setLayoutDirection(Qt.RightToLeft if language == "fa" else Qt.LeftToRight)
    family = load_fonts()
    if language == "fa" and family:
        app.setFont(QFont(family, 10))
    return family


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
