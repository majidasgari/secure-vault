"""Tests for the pure bidi helpers (SPEC/08 §A.1)."""

from __future__ import annotations

import unittest

from vault.ui import bidi


class NeedsRtlTest(unittest.TestCase):
    """``needs_rtl`` follows the first-strong-character rule."""

    def test_persian_paragraph_is_rtl(self) -> None:
        """A Persian paragraph is RTL."""
        self.assertTrue(bidi.needs_rtl("سلام دنیا"))

    def test_english_only_is_ltr(self) -> None:
        """English-only text is LTR."""
        self.assertFalse(bidi.needs_rtl("English only"))

    def test_persian_starting_with_latin_is_ltr(self) -> None:
        """A Persian paragraph that starts with a Latin word stays LTR."""
        self.assertFalse(bidi.needs_rtl("Hello سلام دنیا"))

    def test_persian_starting_with_persian_digit_is_rtl(self) -> None:
        """A Persian paragraph starting with a Persian digit is RTL."""
        self.assertTrue(bidi.needs_rtl("۱۲ سلام"))

    def test_empty_is_ltr(self) -> None:
        """Whitespace has no strong character and is LTR."""
        self.assertFalse(bidi.needs_rtl("   "))


class BlockDirectionTest(unittest.TestCase):
    """``block_direction`` handles fences and plain blocks."""

    def test_fence_is_always_ltr(self) -> None:
        """A fenced block with Persian comments is LTR."""
        code = '```\n# یادداشت\nprint("x")\n```'
        self.assertEqual(bidi.block_direction(code, in_fence=True), "ltr")

    def test_persian_block(self) -> None:
        """A Persian block is RTL."""
        self.assertEqual(bidi.block_direction("متن فارسی", in_fence=False), "rtl")

    def test_english_block(self) -> None:
        """An English block is LTR."""
        self.assertEqual(bidi.block_direction("plain text", in_fence=False), "ltr")


class SplitBlocksTest(unittest.TestCase):
    """``split_blocks`` groups paragraphs and keeps fences whole."""

    def test_splits_on_blank_lines(self) -> None:
        """Blank lines separate blocks."""
        blocks = bidi.split_blocks("one\n\ntwo\n\nthree")
        self.assertEqual([text for text, _ in blocks], ["one", "two", "three"])
        self.assertTrue(all(not fence for _, fence in blocks))

    def test_fence_is_one_block(self) -> None:
        """A fence (including blank lines inside) is a single LTR block."""
        blocks = bidi.split_blocks("intro\n\n```\n\ncode\n```\n\noutro")
        self.assertEqual(blocks[0][0], "intro")
        self.assertFalse(blocks[0][1])
        self.assertIn("code", blocks[1][0])
        self.assertTrue(blocks[1][1])
        self.assertEqual(blocks[2][0], "outro")


if __name__ == "__main__":  # pragma: no cover - manual run
    unittest.main()
