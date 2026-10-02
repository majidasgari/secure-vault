"""Emoji labels for folders and files (SPEC/01 §6, SPEC/03 §2.3).

An emoji here is *metadata on a path*, exactly like a name: it lives in the plaintext
``meta.sqlite`` row of that path, it syncs with the metadata, and it is visible while the
vault is locked. That is deliberate — it labels a name the locked UI already shows, and it
never carries content. One optional emoji per path; empty means "no label".

The palette is the single source for both UIs (served by ``vault.emoji_palette``): a picker
that is consistent between the desktop app and the browser is what keeps a vault's folder
map readable. Free text is still allowed for anything the palette does not cover.
"""

from __future__ import annotations

import unicodedata
from typing import Any

from ..errors import BadRequest

#: Longest accepted label, in code points. A ZWJ sequence or a flag is several code points
#: (``👨‍👩‍👧‍👦`` = 11, ``🇮🇷`` = 2 + the tag chars), so the cap is generous — it only
#: refuses a paragraph pasted by mistake.
MAX_CODEPOINTS = 16

#: Characters that are always stripped: they are invisible and only mangle the layout.
_INVISIBLE = "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff"

#: ``(i18n key, emoji)`` groups of the built-in palette, in display order.
PALETTE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("emoji.group.general", ("📁", "📂", "🗂️", "⭐", "📌", "🔖", "🏷️", "✅")),
    ("emoji.group.work", ("💼", "🧑‍💻", "🛠️", "📊", "📈", "🎯", "🗓️", "🧪")),
    ("emoji.group.writing", ("📝", "📄", "📚", "📖", "🖊️", "🗒️", "📰", "🖼️")),
    ("emoji.group.money", ("💰", "🏦", "💳", "🧾", "🪙", "💵", "📉", "📑")),
    ("emoji.group.security", ("🔐", "🔑", "🛡️", "🧿", "🕵️", "🚨", "🪪", "🔒")),
    ("emoji.group.network", ("🌐", "🖥️", "☁️", "📡", "🔌", "🗄️", "🐳", "🧰")),
    ("emoji.group.people", ("🧑", "👥", "🎓", "🧑‍🏫", "🤝", "🏫", "👨‍👩‍👧‍👦", "💬")),
    ("emoji.group.places", ("🏠", "🏢", "🧭", "🗺️", "✈️", "🚗", "🏥", "🥗")),
    ("emoji.group.ideas", ("💡", "🧠", "🔬", "🧩", "🎨", "🎵", "🎮", "📷")),
    ("emoji.group.marks", ("🔥", "⚡", "❗", "❓", "⏳", "🧹", "🆕", "🏁")),
)


def palette() -> list[dict[str, Any]]:
    """Return the palette as ``[{"group": <i18n key>, "items": [...]}]``."""
    return [{"group": key, "items": list(items)} for key, items in PALETTE]


def normalize(value: Any) -> str | None:
    """Validate ``value`` as a label and return it, or ``None`` to clear the label.

    Raises:
        BadRequest: when the value is not a usable label (too long, or a control character,
            or plain ASCII text — a label is a glyph, the name beside it is the text).
    """
    if value is None:
        return None
    text = "".join(ch for ch in str(value) if ch not in _INVISIBLE).strip()
    if not text:
        return None
    if len(text) > MAX_CODEPOINTS:
        raise BadRequest("emoji_too_long", details={"max": MAX_CODEPOINTS})
    for ch in text:
        if unicodedata.category(ch) in ("Cc", "Zl", "Zp"):
            raise BadRequest("emoji_invalid")
        # ``Cf`` is mostly invisible junk, but two of its members are load-bearing: the ZWJ
        # that glues a sequence together and the tag characters of a subdivision flag.
        if unicodedata.category(ch) == "Cf" and ch != "\u200d" and not (
            "\U000e0020" <= ch <= "\U000e007f"
        ):
            raise BadRequest("emoji_invalid")
    # ASCII-only means someone typed a word: the name already carries the text, and an
    # "emoji" of letters would silently shadow it in every listing.
    if all(ord(ch) < 0xA0 for ch in text):
        raise BadRequest("emoji_invalid")
    return text


#: Shown in the preview box when what was typed is not a usable emoji label.
WARNING = "\u26a0"


def first_glyph(value: str | None) -> str | None:
    """Return the first user-perceived character of ``value`` (a cheap sanity check)."""
    if not value:
        return None
    return value[0]


__all__ = ["MAX_CODEPOINTS", "PALETTE", "WARNING", "first_glyph", "normalize", "palette"]
