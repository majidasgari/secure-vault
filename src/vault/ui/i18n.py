"""Bilingual (fa/en) translation layer for the Qt UI (SPEC/03 §3).

Catalogues are flat JSON objects (``{"unlock.title": "…"}``) loaded from the repo's
``i18n/`` directory. Every user-visible string in ``vault/ui/**`` goes through
:func:`tr`; a missing key renders the visible marker ``⟦key⟧`` instead of raising.
"""

from __future__ import annotations

import json
import weakref
from pathlib import Path
from typing import Callable

from ..config import app_paths

MISSING_TEMPLATE = "\u27e6{key}\u27e7"
"""Visible marker rendered for a missing key (never a crash)."""

ChangeCallback = Callable[[str], None]
RefreshCallback = Callable[[], None]


class Translator:
    """Loads one language catalogue and notifies listeners when it changes."""

    def __init__(self, lang: str = "fa", i18n_dir: Path | None = None) -> None:
        """Create a translator for ``lang`` reading catalogues from ``i18n_dir``."""
        self._i18n_dir = Path(i18n_dir) if i18n_dir is not None else app_paths().i18n_dir
        self._lang = "fa"
        self._strings: dict[str, str] = {}
        self._callbacks: list[ChangeCallback] = []
        self._bindings: list[tuple[weakref.ref, RefreshCallback]] = []
        self.set_language(lang if self._catalogue_exists(lang) else "fa")

    # ------------------------------------------------------------------ catalogue
    def _catalogue_exists(self, lang: str) -> bool:
        """Return True when ``<lang>.json`` exists in the catalogue directory."""
        return (self._i18n_dir / f"{lang}.json").is_file()

    def _load(self, lang: str) -> dict[str, str]:
        """Read and validate ``<lang>.json``; malformed files yield an empty mapping."""
        path = self._i18n_dir / f"{lang}.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        return {str(key): str(value) for key, value in raw.items()}

    # ------------------------------------------------------------------ language
    def set_language(self, lang: str) -> None:
        """Switch the active language and notify every registered listener."""
        self._lang = lang
        self._strings = self._load(lang)
        for callback in list(self._callbacks):
            try:
                callback(lang)
            except Exception:  # noqa: BLE001 - a bad listener must not break i18n
                pass
        self.reload()

    @property
    def lang(self) -> str:
        """The active language code."""
        return self._lang

    def available(self) -> list[str]:
        """Return the language codes that have a catalogue, sorted."""
        return sorted(path.stem for path in self._i18n_dir.glob("*.json"))

    # ------------------------------------------------------------------ lookup
    def t(self, key: str, **fmt: object) -> str:
        """Translate ``key``; missing keys render ``⟦key⟧`` and never raise."""
        template = self._strings.get(key)
        if template is None:
            return MISSING_TEMPLATE.format(key=key)
        if not fmt:
            return template
        try:
            return template.format(**fmt)
        except (KeyError, IndexError, ValueError):
            return template

    # ------------------------------------------------------------------ listeners
    def on_change(self, callback: ChangeCallback) -> None:
        """Register ``callback(lang)`` invoked after every language switch."""
        self._callbacks.append(callback)

    def bind(self, widget: object, refresh: RefreshCallback) -> None:
        """Register ``refresh`` to be re-applied to ``widget`` on language changes."""
        self._bindings.append((weakref.ref(widget), refresh))

    def reload(self) -> None:
        """Re-apply strings to every live registered widget."""
        alive: list[tuple[weakref.ref, RefreshCallback]] = []
        for ref, refresh in self._bindings:
            widget = ref()
            if widget is None:
                continue
            try:
                refresh()
            except Exception:  # noqa: BLE001 - one broken widget must not stop the rest
                pass
            alive.append((ref, refresh))
        self._bindings = alive


_translator = Translator()


def tr(key: str, **fmt: object) -> str:
    """Translate ``key`` with the current translator (module-level convenience)."""
    return _translator.t(key, **fmt)


def set_language(lang: str) -> None:
    """Switch the current language and refresh registered widgets."""
    _translator.set_language(lang)


def on_language_changed(callback: ChangeCallback) -> None:
    """Register a callback invoked after every language switch."""
    _translator.on_change(callback)


def bind(widget: object, refresh: RefreshCallback) -> None:
    """Register a widget refresh callback for live retranslation."""
    _translator.bind(widget, refresh)


def reload_widgets() -> None:
    """Re-apply strings to every registered widget."""
    _translator.reload()


def translator() -> Translator:
    """Return the process-wide translator instance (used by the app/tests)."""
    return _translator


def __getattr__(name: str) -> object:
    """Expose ``i18n.lang`` as a read-only view of the current language."""
    if name == "lang":
        return _translator.lang
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Translator",
    "tr",
    "set_language",
    "on_language_changed",
    "bind",
    "reload_widgets",
    "translator",
    "MISSING_TEMPLATE",
]
