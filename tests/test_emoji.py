"""Tests for vault.core.emoji (SPEC/01 §6, SPEC/03 §2.3)."""

from __future__ import annotations

import unittest

from vault.core import emoji as emoji_module
from vault.errors import BadRequest


class EmojiNormalizeTest(unittest.TestCase):
    """A label is one glyph (or a short sequence), never text."""

    def test_accepts_a_plain_emoji(self) -> None:
        """A single pictograph round-trips."""
        self.assertEqual(emoji_module.normalize("📁"), "📁")

    def test_accepts_a_zwj_sequence(self) -> None:
        """A family emoji is one user-perceived character made of several code points."""
        family = "👨‍👩‍👧‍👦"
        self.assertEqual(emoji_module.normalize(family), family)

    def test_accepts_a_subdivision_flag(self) -> None:
        """The Iran flag is a base letter plus tag characters (category Cf)."""
        self.assertEqual(emoji_module.normalize("🇮🇷"), "🇮🇷")

    def test_strips_surrounding_space_and_invisible_marks(self) -> None:
        """Whitespace and bidi marks are dropped, not stored."""
        self.assertEqual(emoji_module.normalize("  🗂️\u200e "), "🗂️")

    def test_empty_and_none_clear_the_label(self) -> None:
        """``None`` and an all-invisible string both mean "no label"."""
        self.assertIsNone(emoji_module.normalize(None))
        self.assertIsNone(emoji_module.normalize(""))
        self.assertIsNone(emoji_module.normalize("   "))
        self.assertIsNone(emoji_module.normalize("\u200f"))

    def test_refuses_ascii_text(self) -> None:
        """A word is not a label — the name beside it already carries the text."""
        with self.assertRaises(BadRequest) as ctx:
            emoji_module.normalize("docs")
        self.assertEqual(ctx.exception.message, "emoji_invalid")

    def test_refuses_too_long(self) -> None:
        """A paragraph pasted by mistake is refused with the cap in the details."""
        with self.assertRaises(BadRequest) as ctx:
            emoji_module.normalize("📁" * (emoji_module.MAX_CODEPOINTS + 1))
        self.assertEqual(ctx.exception.message, "emoji_too_long")
        self.assertEqual(ctx.exception.details.get("max"), emoji_module.MAX_CODEPOINTS)

    def test_refuses_embedded_control_characters(self) -> None:
        """A newline or a tab *inside* the label would break every listing row."""
        for bad in ("📁\n📁", "📁\t📁", "📁\u2028📁"):
            with self.assertRaises(BadRequest):
                emoji_module.normalize(bad)

    def test_a_trailing_newline_from_a_paste_is_stripped(self) -> None:
        """Copying a glyph usually brings a newline; that is trimmed, not refused."""
        self.assertEqual(emoji_module.normalize("📁\n"), "📁")
        self.assertEqual(emoji_module.normalize("\n📁\t"), "📁")
        for only_space in ("\n", "\t", "\u2028"):
            self.assertIsNone(emoji_module.normalize(only_space))

    def test_refuses_a_lone_bidi_control(self) -> None:
        """An embedded override mark is stripped first; only it left means "no label"."""
        self.assertIsNone(emoji_module.normalize("\u202e"))
        with self.assertRaises(BadRequest):
            emoji_module.normalize("a\u202eb")


class EmojiPaletteTest(unittest.TestCase):
    """The palette is one shared source for both UIs."""

    def test_palette_groups_are_i18n_keys_with_items(self) -> None:
        """Every group names an i18n key and carries a non-empty list of glyphs."""
        groups = emoji_module.palette()
        self.assertTrue(groups)
        for group in groups:
            self.assertTrue(str(group["group"]).startswith("emoji.group."))
            self.assertTrue(group["items"])

    def test_palette_items_are_all_valid_labels(self) -> None:
        """Nothing shipped in the palette can be refused by the validator."""
        for group in emoji_module.palette():
            for glyph in group["items"]:
                self.assertEqual(emoji_module.normalize(glyph), glyph)

    def test_palette_is_copied_not_shared(self) -> None:
        """A caller mutating the returned lists cannot corrupt the module constant."""
        groups = emoji_module.palette()
        groups[0]["items"].append("💥")
        self.assertNotIn("💥", emoji_module.palette()[0]["items"])

    def test_first_glyph(self) -> None:
        """The helper returns the first character and handles the empty cases."""
        self.assertEqual(emoji_module.first_glyph("📁x"), "📁")
        self.assertIsNone(emoji_module.first_glyph(""))
        self.assertIsNone(emoji_module.first_glyph(None))


if __name__ == "__main__":
    unittest.main()
