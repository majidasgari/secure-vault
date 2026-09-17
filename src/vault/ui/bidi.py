"""Bidirectional text helpers for the markdown editor (SPEC/08 §A.1).

Pure Python (no Qt) so the direction rules are unit-testable in isolation. The rule is the
user's: **any** line that contains at least one Persian/Arabic letter or digit is RTL, every
other line is LTR (the same rule the farsi-helper addon applies in the browser). Fenced code is
always LTR so code never flips, and a blank line inherits the previous line's direction.
"""

from __future__ import annotations

#: Arabic/Persian letters live in these Unicode blocks (Script=Arabic).
_ARABIC_RANGES: tuple[tuple[int, int], ...] = (
    (0x0600, 0x06FF),
    (0x0750, 0x077F),
    (0x08A0, 0x08FF),
    (0xFB50, 0xFDFF),
    (0xFE70, 0xFEFF),
)

#: Persian/Arabic-Indic digits (they are strong RTL characters for direction purposes).
_ARABIC_DIGITS: tuple[tuple[int, int], ...] = (
    (0x0660, 0x0669),
    (0x06F0, 0x06F9),
)

_ASCII_LETTERS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ASCII_DIGITS = set("0123456789")


def _in_ranges(code: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    """Return True when ``code`` falls inside any inclusive ``(lo, hi)`` range."""
    return any(lo <= code <= hi for lo, hi in ranges)


def is_arabic_letter(char: str) -> bool:
    """Return True for a Persian/Arabic letter (Script=Arabic, excluding digits)."""
    if not char:
        return False
    code = ord(char)
    if _in_ranges(code, _ARABIC_DIGITS):
        return False
    if not _in_ranges(code, _ARABIC_RANGES):
        return False
    return char.isalpha()


def is_arabic_strong(char: str) -> bool:
    """Return True for a strong RTL character (Persian/Arabic letter or digit)."""
    return is_arabic_letter(char) or _in_ranges(ord(char), _ARABIC_DIGITS)


def is_latin_strong(char: str) -> bool:
    """Return True for a strong LTR character (ASCII letter or digit)."""
    return char in _ASCII_LETTERS or char in _ASCII_DIGITS


def _first_strong(text: str) -> str | None:
    """Return the first strong directional character of ``text`` (or None)."""
    for char in text:
        if is_arabic_strong(char) or is_latin_strong(char):
            return char
    return None


def has_persian(text: str) -> bool:
    """Return True when ``text`` contains at least one Persian/Arabic letter or digit."""
    return any(is_arabic_strong(char) for char in text)


def needs_rtl(text: str) -> bool:
    """Return True when ``text`` contains ANY Persian/Arabic letter or digit.

    This is the user's rule (the same one the farsi-helper addon follows): *any* line that has
    even one Persian/Arabic character is right-to-left, everything else is left-to-right. There
    is no first-strong-character test — a line that begins with a Latin word but contains
    Persian is still Persian and must be right-aligned.
    """
    return has_persian(text)


def block_direction(text: str, *, in_fence: bool, previous: str | None = None) -> str:
    """Return ``"rtl"`` or ``"ltr"`` for one markdown block.

    Fenced code is always LTR. A blank line has nothing to align, so it inherits the direction
    of the previous block (``previous``) to keep the caret on the side the user expects.
    Everything else follows :func:`needs_rtl`.
    """
    if in_fence:
        return "ltr"
    if not text.strip() or _first_strong(text) is None:
        return previous or "ltr"
    return "rtl" if needs_rtl(text) else "ltr"


def _is_fence_line(line: str) -> bool:
    """Return True for a ``` or ~~~ fence delimiter line."""
    stripped = line.strip()
    return stripped.startswith("```") or stripped.startswith("~~~")


def split_blocks(markdown: str) -> list[tuple[str, bool]]:
    """Split ``markdown`` into blank-line separated blocks.

    Returns ``(block_text, in_fence)`` pairs. A fenced region is a single block whose
    flag is True; blank lines inside a fence do not split it. Blank lines outside a
    fence separate blocks and are not returned.
    """
    blocks: list[tuple[str, bool]] = []
    buffer: list[str] = []
    fence = False

    def flush() -> None:
        """Emit the pending buffer as a block (when non-empty)."""
        if buffer:
            blocks.append(("\n".join(buffer), fence))
            buffer.clear()

    for line in markdown.splitlines():
        if _is_fence_line(line):
            if not fence:
                # A fence starts: any preceding text is its own (non-fence) block.
                if buffer:
                    blocks.append(("\n".join(buffer), False))
                    buffer.clear()
                fence = True
                buffer.append(line)
                continue
            # Closing fence: the whole fenced region is one block.
            buffer.append(line)
            blocks.append(("\n".join(buffer), True))
            buffer.clear()
            fence = False
            continue
        if fence:
            buffer.append(line)
            continue
        if line.strip() == "":
            if buffer:
                blocks.append(("\n".join(buffer), False))
                buffer.clear()
        else:
            buffer.append(line)
    if buffer:
        blocks.append(("\n".join(buffer), fence))
    return blocks


__all__ = [
    "needs_rtl",
    "block_direction",
    "split_blocks",
    "has_persian",
    "is_arabic_letter",
    "is_arabic_strong",
    "is_latin_strong",
]
