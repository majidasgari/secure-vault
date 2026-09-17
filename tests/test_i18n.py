"""Tests for vault.ui.i18n and the fa/en catalogues (SPEC/06 §2 test_i18n)."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from vault import errors
from vault.config import app_paths
from vault.ui import i18n

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_DIR = REPO_ROOT / "src" / "vault" / "ui"
API_DIR = REPO_ROOT / "src" / "vault" / "api"

_TR_CALL = re.compile(r"""\btr\(\s*["']([^"']+)["']""")


def _catalogue(lang: str) -> dict:
    """Load one catalogue from the repo's i18n directory."""
    path = app_paths().i18n_dir / f"{lang}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _used_keys() -> set[str]:
    """Return every literal key passed to ``tr(...)`` under ui/ and api/."""
    keys: set[str] = set()
    for directory in (UI_DIR, API_DIR):
        for path in directory.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            keys.update(_TR_CALL.findall(text))
    return keys


class CatalogueTest(unittest.TestCase):
    """The two catalogues must be complete and identical in shape."""

    def test_identical_key_sets(self) -> None:
        """fa.json and en.json have exactly the same keys."""
        en = set(_catalogue("en"))
        fa = set(_catalogue("fa"))
        self.assertEqual(en, fa, f"key diff: only-en={en - fa} only-fa={fa - en}")

    def test_no_empty_values(self) -> None:
        """Neither catalogue has empty strings."""
        for lang in ("en", "fa"):
            for key, value in _catalogue(lang).items():
                self.assertTrue(value, f"{lang}:{key} is empty")

    def test_every_used_key_exists(self) -> None:
        """Every literal tr(...) key exists in both catalogues."""
        used = _used_keys()
        self.assertTrue(used)
        for lang in ("en", "fa"):
            catalogue = _catalogue(lang)
            missing = sorted(key for key in used if key not in catalogue)
            self.assertEqual(missing, [], f"{lang} is missing keys: {missing}")

    def test_every_error_code_has_a_key(self) -> None:
        """Every VaultError.code has an error.<CODE> entry."""
        codes = set()
        for name in errors.__all__:
            obj = getattr(errors, name)
            if isinstance(obj, type) and issubclass(obj, errors.VaultError):
                codes.add(obj.code)
        self.assertIn("ERROR", codes)
        for lang in ("en", "fa"):
            catalogue = _catalogue(lang)
            for code in sorted(codes):
                self.assertIn(f"error.{code}", catalogue, f"{lang} missing error.{code}")


class TranslatorTest(unittest.TestCase):
    """Runtime behaviour of the translator."""

    def tearDown(self) -> None:
        i18n.set_language("fa")

    def test_missing_key_renders_marker(self) -> None:
        """A missing key renders the visible marker and never raises."""
        self.assertEqual(i18n.tr("no.such.key"), "\u27e6no.such.key\u27e7")

    def test_set_language_flips_and_notifies(self) -> None:
        """set_language updates the active language and calls listeners."""
        seen: list[str] = []
        i18n.on_language_changed(seen.append)
        i18n.set_language("en")
        self.assertEqual(i18n.lang, "en")
        self.assertIn("en", seen)
        i18n.set_language("fa")
        self.assertEqual(i18n.lang, "fa")
        self.assertEqual(seen[-1], "fa")

    def test_formatting(self) -> None:
        """Keyword formatting is applied."""
        i18n.set_language("en")
        self.assertIn("3", i18n.tr("status.files", count=3))

    def test_translator_available(self) -> None:
        """available() lists both bundled languages."""
        langs = i18n.Translator("fa").available()
        self.assertIn("fa", langs)
        self.assertIn("en", langs)


try:
    from PySide6.QtWidgets import QApplication, QLabel

    HAVE_QT = True
except ImportError:  # pragma: no cover - environment without PySide6
    HAVE_QT = False


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class WidgetRetranslateTest(unittest.TestCase):
    """A representative widget retranslates live (offscreen)."""

    def setUp(self) -> None:
        import os

        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        self.app = QApplication.instance() or QApplication([])

    def tearDown(self) -> None:
        i18n.set_language("fa")

    def test_label_retranslates(self) -> None:
        """A bound label changes text when the language switches."""
        label = QLabel()
        i18n.on_language_changed(lambda lang: label.setText(i18n.tr("app.title")))
        i18n.set_language("fa")
        self.assertEqual(label.text(), i18n.tr("app.title"))
        i18n.set_language("en")
        self.assertEqual(label.text(), "Secure Vault")


if __name__ == "__main__":
    unittest.main()
