"""Markdown syntax highlighting for the editor (Kate-like colours).

A small :class:`QSyntaxHighlighter` that gives the editor the thing the user liked about
Kate's markdown view: real colours per element plus monospace fenced code — while
:mod:`vault.ui.editor` keeps owning the per-block **direction** (RTL/LTR), so the two passes
never fight (the highlighter owns character formats, the editor owns block formats).

Palettes follow the application palette: the dark set is chosen automatically when the
window colour is dark, so it tracks the system theme.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import (
    QColor,
    QFont,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextDocument,
)

# Kate-ish palettes: (dark, light)
_DARK = {
    "text": "#d6d8de",
    "muted": "#8a8f9a",
    "heading": "#7c9cff",
    "accent": "#5b9dff",
    "code": "#e6c07b",
    "code_bg": "#23252c",
    "quote": "#9aa7b8",
    "link": "#5b9dff",
    "url": "#7f8a99",
    "marker": "#c792ea",
    "bg": "#1b1d23",
    "border": "#33363f",
}
_LIGHT = {
    "text": "#202124",
    "muted": "#6b7280",
    "heading": "#1a3fa8",
    "accent": "#0b57d0",
    "code": "#9c3d00",
    "code_bg": "#f1f3f5",
    "quote": "#5f6672",
    "link": "#0b57d0",
    "url": "#7a8290",
    "marker": "#7b1fa2",
    "bg": "#ffffff",
    "border": "#dfe3e8",
}

_FENCE = QRegularExpression(r"^\s*(```|~~~)")
_HEADING = QRegularExpression(r"^\s{0,3}(#{1,6})\s+.*$")
_HR = QRegularExpression(r"^\s{0,3}([-*_])(\s*\1){2,}\s*$")
_QUOTE = QRegularExpression(r"^\s{0,3}>.*$")
_LIST = QRegularExpression(r"^(\s*)([-*+]|\d+[.)])(\s+)")
_TASK = QRegularExpression(r"^\s*([-*+]|\d+[.)])\s+\[[ xX]\]")
_BOLD = QRegularExpression(r"(\*\*|__)(?=\S)(.+?)(?<=\S)\1")
_ITALIC = QRegularExpression(r"(?<![*\w])(\*|_)(?=\S)(.+?)(?<=\S)\1(?![*\w])")
_STRIKE = QRegularExpression(r"~~(?=\S)(.+?)(?<=\S)~~")
_INLINE_CODE = QRegularExpression(r"(`+)([^`]+?)\1")
_LINK = QRegularExpression(r"(\!?\[)([^\]]*)(\]\()([^)\s]*)(\))")
_KEYWORDS = QRegularExpression(r"\b(TODO|FIXME|NOTE|XXX)\b")


def _fmt(*, color: str | None = None, bold: bool = False, italic: bool = False,
         mono: bool = False, background: str | None = None, underline: bool = False,
         strike: bool = False) -> QTextCharFormat:
    """Build a :class:`QTextCharFormat` from the small set of options used here."""
    fmt = QTextCharFormat()
    if color:
        fmt.setForeground(QColor(color))
    if bold:
        fmt.setFontWeight(QFont.Weight.Bold)
    if italic:
        fmt.setFontItalic(True)
    if underline:
        fmt.setFontUnderline(True)
    if strike:
        fmt.setFontStrikeOut(True)
    if mono:
        fmt.setFontFamilies(["ui-monospace", "DejaVu Sans Mono", "Consolas", "monospace"])
    if background:
        fmt.setBackground(QColor(background))
    return fmt


def pick_palette(app: Any = None) -> dict[str, str]:
    """Return the palette that matches the current application theme."""
    dark = False
    try:
        from PySide6.QtGui import QPalette
        from PySide6.QtWidgets import QApplication

        application: Any = app or QApplication.instance()
        if application is not None:
            color = application.palette().color(QPalette.ColorRole.Window)
            # Perceived luminance (ITU-R BT.601) — under 40 % means a dark theme.
            dark = (0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue()) < 102
    except Exception:  # noqa: BLE001 - headless / no palette: keep the light default
        dark = False
    return dict(_DARK if dark else _LIGHT)


def _matches(pattern: QRegularExpression, text: str) -> list[Any]:
    """Return every match of ``pattern`` in ``text`` (PySide iterators are explicit)."""
    found: list[Any] = []
    iterator = pattern.globalMatch(text)
    while iterator.hasNext():
        found.append(iterator.next())
    return found


class MarkdownHighlighter(QSyntaxHighlighter):
    """Kate-like markdown colouring, including multi-line fenced code."""

    def __init__(self, document: QTextDocument, *, app: Any = None) -> None:
        """Attach the highlighter to ``document`` and pick the matching palette."""
        super().__init__(document)
        self._app = app
        self.palette = pick_palette(app)
        self._build_formats()
        self._fence_state = 1  # arbitrary non-zero state for "inside a fence"

    # ------------------------------------------------------------------ internal
    def _build_formats(self) -> None:
        """Create the character formats from the active palette."""
        p = self.palette
        self.fmt_text = _fmt(color=p["text"])
        self.fmt_heading = [_fmt(color=p["heading"], bold=True) for _ in range(6)]
        self.fmt_bold = _fmt(color=p["text"], bold=True)
        self.fmt_italic = _fmt(color=p["text"], italic=True)
        self.fmt_strike = _fmt(color=p["muted"], strike=True)
        self.fmt_code = _fmt(color=p["code"], mono=True, background=p["code_bg"])
        self.fmt_fence = _fmt(color=p["code"], mono=True, background=p["code_bg"])
        self.fmt_quote = _fmt(color=p["quote"], italic=True)
        self.fmt_marker = _fmt(color=p["marker"], bold=True)
        self.fmt_link_text = _fmt(color=p["link"], underline=True)
        self.fmt_url = _fmt(color=p["url"], underline=True)
        self.fmt_keyword = _fmt(color=p["accent"], bold=True)

    def refresh(self) -> None:
        """Re-pick the palette (theme change) and re-highlight the document."""
        self.palette = pick_palette(self._app)
        self._build_formats()
        self.rehighlight()

    # ------------------------------------------------------------------- pass
    def highlightBlock(self, text: str) -> None:  # noqa: N802 - Qt naming
        """Colour one block; fenced code keeps its formatting across lines."""
        base = self.fmt_text
        inside_fence = self.previousBlockState() == self._fence_state
        if _FENCE.match(text).hasMatch():
            self.setCurrentBlockState(self._fence_state if not inside_fence else 0)
            self.setFormat(0, len(text), self.fmt_fence)
            return
        if inside_fence:
            self.setCurrentBlockState(self._fence_state)
            self.setFormat(0, len(text), self.fmt_fence)
            return
        self.setCurrentBlockState(0)

        heading = _HEADING.match(text)
        if heading.hasMatch():
            level = min(len(heading.captured(1)), 6)
            self.setFormat(0, len(text), self.fmt_heading[level - 1])
        elif _HR.match(text).hasMatch():
            self.setFormat(0, len(text), _fmt(color=self.palette["muted"]))
        elif _QUOTE.match(text).hasMatch():
            self.setFormat(0, len(text), self.fmt_quote)
        else:
            self.setFormat(0, len(text), base)

        task = _TASK.match(text)
        if task.hasMatch():
            self.setFormat(task.capturedStart(0), task.capturedLength(0), self.fmt_marker)
        else:
            marker = _LIST.match(text)
            if marker.hasMatch():
                self.setFormat(
                    marker.capturedStart(2), marker.capturedLength(2), self.fmt_marker
                )

        for match in _matches(_BOLD, text):
            self.setFormat(match.capturedStart(0), match.capturedLength(0), self.fmt_bold)
        for match in _matches(_ITALIC, text):
            self.setFormat(match.capturedStart(0), match.capturedLength(0), self.fmt_italic)
        for match in _matches(_STRIKE, text):
            self.setFormat(match.capturedStart(0), match.capturedLength(0), self.fmt_strike)
        for match in _matches(_INLINE_CODE, text):
            self.setFormat(match.capturedStart(0), match.capturedLength(0), self.fmt_code)
        for match in _matches(_LINK, text):
            self.setFormat(match.capturedStart(2), match.capturedLength(2), self.fmt_link_text)
            self.setFormat(match.capturedStart(4), match.capturedLength(4), self.fmt_url)
        for match in _matches(_KEYWORDS, text):
            self.setFormat(match.capturedStart(0), match.capturedLength(0), self.fmt_keyword)


__all__ = ["MarkdownHighlighter", "pick_palette"]
