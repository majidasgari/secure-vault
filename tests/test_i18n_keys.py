"""Translation catalogue completeness (regression guard).

Removing the web log panel once removed ``log.*`` from the catalogue, but the *desktop* app reads
the same files, so its log panel started printing raw keys such as ``[log.export]``. This test
fails whenever a key used in the source is missing from a catalogue (or the two catalogues drift).
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
I18N = REPO / "i18n"
SRC = REPO / "src"

#: ``i18n.tr("a.b")`` / ``tr('a.b')`` / ``data-i18n="a.b"`` and friends.
CALL_PATTERN = re.compile(
    r"""(?:i18n\.tr|_tr|\btr|data-i18n(?:-title|-placeholder|-aria)?)\s*[=(]\s*["']([^"']+)["']"""
)
#: any dotted literal, so tuple/list style tables are covered too
LITERAL_PATTERN = re.compile(r"""["']([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)["']""")


def _catalogue(lang: str) -> dict[str, str]:
    """Load one catalogue."""
    return json.loads((I18N / f"{lang}.json").read_text(encoding="utf-8"))


def _source_text() -> str:
    """Concatenate every source file that can reference a translation key."""
    text = []
    for pattern in ("*.py", "*.js", "*.html"):
        for path in SRC.rglob(pattern):
            text.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(text)


class I18nKeysTest(unittest.TestCase):
    """Every referenced key exists in both languages and the catalogues stay identical."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load the catalogues and the source once."""
        cls.fa = _catalogue("fa")
        cls.en = _catalogue("en")
        cls.source = _source_text()
        cls.namespaces = {key.split(".")[0] for key in cls.fa}

    def test_catalogues_have_identical_keys(self) -> None:
        """fa and en must stay in lockstep."""
        self.assertEqual(set(self.fa), set(self.en))
        self.assertTrue(self.fa)

    def test_called_keys_are_translated(self) -> None:
        """No ``i18n.tr("…")`` may point at a key the catalogue does not define."""
        used = {
            match.group(1)
            for match in CALL_PATTERN.finditer(self.source)
            if "." in match.group(1) and not match.group(1).endswith("_")
        }
        missing_fa = sorted(key for key in used if key not in self.fa)
        missing_en = sorted(key for key in used if key not in self.en)
        self.assertEqual(missing_fa, [], f"missing from fa.json: {missing_fa}")
        self.assertEqual(missing_en, [], f"missing from en.json: {missing_en}")

    def test_dynamic_prefixes_have_entries(self) -> None:
        """A key built at runtime (``"web.action_" + name``) must have at least one entry."""
        prefixes = {
            match.group(1)
            for match in re.finditer(r"""["']([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*\.)["']""", self.source)
            if match.group(1).split(".")[0] in self.namespaces
        }
        problems = []
        for prefix in sorted(prefixes):
            if not any(key.startswith(prefix) for key in self.fa):
                problems.append(prefix)
        self.assertEqual(problems, [], f"no catalogue entry for these prefixes: {problems}")

    def test_ui_module_literals_are_translated(self) -> None:
        """Dotted keys written straight into a UI call (``self._label("settings.web_port")``)."""
        ui = REPO / "src/vault/ui"
        literal = re.compile(r"""["']([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)["']""")
        skip = re.compile(r"\.(py|js|html|json|md|txt|sh|svg|png|jpg|toml|cfg|ini)$")
        missing: dict[str, str] = {}
        for path in sorted(ui.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            for match in literal.finditer(path.read_text(encoding="utf-8", errors="replace")):
                key = match.group(1)
                if skip.search(key) or key.split(".")[0] not in self.namespaces:
                    continue
                if key.endswith("_") or key in self.fa:
                    continue
                # `web.host` / `web.port` are settings paths in a docstring, not labels
                if key.startswith(("web.", "vault.")):
                    continue
                missing[key] = path.name
        self.assertEqual(missing, {}, f"referenced but undefined: {missing}")

    def test_no_placeholder_leaks_into_persian(self) -> None:
        """Persian values keep the same placeholders as English (no dropped/renamed slots)."""
        slots = re.compile(r"\{([a-z_]+)\}")
        problems = []
        for key, fa_value in self.fa.items():
            en_value = self.en.get(key, "")
            if not isinstance(fa_value, str) or not isinstance(en_value, str):
                continue
            if set(slots.findall(fa_value)) != set(slots.findall(en_value)):
                problems.append(f"{key}: fa={sorted(slots.findall(fa_value))} en={sorted(slots.findall(en_value))}")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
