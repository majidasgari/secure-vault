"""Tests for vault.core.security (SPEC/06 §2 test_security)."""

from __future__ import annotations

import unittest

from vault.core import security
from vault.core.security import (
    LEVELS,
    SOURCE_IMPORTER,
    SOURCE_MCP,
    SOURCE_UI,
    Policy,
)
from vault.errors import BadRequest

# Expected policy matrix from SPEC/01 §9.
_CAN_READ = {
    "normal": {SOURCE_UI: True, SOURCE_MCP: True, SOURCE_IMPORTER: True},
    "secret": {SOURCE_UI: True, SOURCE_MCP: False, SOURCE_IMPORTER: True},
    "secretfile": {SOURCE_UI: True, SOURCE_MCP: False, SOURCE_IMPORTER: True},
}

_CAN_REQUEST = {
    "normal": {SOURCE_UI: False, SOURCE_MCP: True, SOURCE_IMPORTER: False},
    "secret": {SOURCE_UI: False, SOURCE_MCP: False, SOURCE_IMPORTER: False},
    "secretfile": {SOURCE_UI: False, SOURCE_MCP: True, SOURCE_IMPORTER: False},
}

_ALL_SOURCES = (SOURCE_UI, SOURCE_MCP, SOURCE_IMPORTER)


class PolicyMatrixTest(unittest.TestCase):
    """The full (level, source) matrix."""

    def test_can_see_name_always(self) -> None:
        """Names are visible for every level and source."""
        for level in LEVELS:
            for source in _ALL_SOURCES:
                self.assertTrue(Policy.can_see_name(level, source))

    def test_can_read_content_matrix(self) -> None:
        """Content read permissions match the table."""
        for level in LEVELS:
            for source in _ALL_SOURCES:
                self.assertEqual(
                    Policy.can_read_content(level, source),
                    _CAN_READ[level][source],
                    msg=f"{level}/{source}",
                )

    def test_can_search_content_only_normal(self) -> None:
        """Only normal content is searchable, for every source."""
        for level in LEVELS:
            for source in _ALL_SOURCES:
                self.assertEqual(
                    Policy.can_search_content(level, source),
                    level == "normal",
                    msg=f"{level}/{source}",
                )

    def test_can_request_open_secret_matrix(self) -> None:
        """MCP may request normal/secretfile; other sources never."""
        for level in LEVELS:
            for source in _ALL_SOURCES:
                self.assertEqual(
                    Policy.can_request_open_secret(level, source),
                    _CAN_REQUEST[level][source],
                    msg=f"{level}/{source}",
                )

    def test_rank_and_ordering(self) -> None:
        """Ranks and the ordering helper agree with the level order."""
        self.assertEqual(security.rank("normal"), 0)
        self.assertEqual(security.rank("secret"), 1)
        self.assertEqual(security.rank("secretfile"), 2)
        self.assertTrue(security.is_higher_or_equal("secretfile", "normal"))
        self.assertFalse(security.is_higher_or_equal("normal", "secret"))
        with self.assertRaises(BadRequest):
            security.rank("unknown")


class RaiseLowerTest(unittest.TestCase):
    """can_raise / can_lower rules."""

    def test_can_raise(self) -> None:
        """Any strictly higher level may be raised to by UI/MCP/importer."""
        self.assertTrue(Policy.can_raise("normal", "secret", SOURCE_UI))
        self.assertTrue(Policy.can_raise("normal", "secretfile", SOURCE_MCP))
        self.assertTrue(Policy.can_raise("secret", "secretfile", SOURCE_MCP))
        self.assertFalse(Policy.can_raise("secret", "secret", SOURCE_UI))
        self.assertFalse(Policy.can_raise("secretfile", "normal", SOURCE_UI))
        self.assertFalse(Policy.can_raise("secret", "normal", SOURCE_MCP))

    def test_can_lower_only_ui_to_different_level(self) -> None:
        """Only the UI may lower, and only to a different level."""
        self.assertTrue(Policy.can_lower("secret", "normal", SOURCE_UI))
        self.assertTrue(Policy.can_lower("secretfile", "secret", SOURCE_UI))
        self.assertFalse(Policy.can_lower("secret", "normal", SOURCE_MCP))
        self.assertFalse(Policy.can_lower("secret", "normal", SOURCE_IMPORTER))
        self.assertFalse(Policy.can_lower("secret", "secret", SOURCE_UI))
        self.assertFalse(Policy.can_lower("normal", "secret", SOURCE_UI))

    def test_ui_view_helpers(self) -> None:
        """The UI confirmation and native-viewer helpers follow the table."""
        self.assertFalse(Policy.ui_requires_confirmation("normal"))
        self.assertTrue(Policy.ui_requires_confirmation("secret"))
        self.assertTrue(Policy.ui_requires_confirmation("secretfile"))
        self.assertFalse(Policy.ui_uses_native_viewer("normal"))
        self.assertTrue(Policy.ui_uses_native_viewer("secret"))
        self.assertTrue(Policy.ui_uses_native_viewer("secretfile"))

    def test_unknown_source_rejected(self) -> None:
        """Unknown sources are a BadRequest, not a silent allow."""
        with self.assertRaises(BadRequest):
            Policy.can_read_content("normal", "bogus")
        with self.assertRaises(BadRequest):
            Policy.can_raise("normal", "secret", "bogus")


if __name__ == "__main__":
    unittest.main()
