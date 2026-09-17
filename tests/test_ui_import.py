"""The Settings/menu "Run import" path (SPEC/03 §4 Importer, SPEC/04).

The import used to report "arrives in a later phase"; these tests pin the real behaviour:
the button runs the Joplin importer against the configured mirror, the report reaches the
user (and ``controller.last_import_report``), running it while locked refuses, a wrong
mirror path explains itself, and a second run is a no-op.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    HAVE_QT = True
except ImportError:  # pragma: no cover - environment without PySide6
    HAVE_QT = False

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "mirror_small"
PASSWORD = "ui-import-passphrase"


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class UiImportTest(unittest.TestCase):
    """Drive the UI import path headlessly against a copy of the fixture mirror."""

    def setUp(self) -> None:
        """Create a scratch vault, a copy of the fixture mirror and the controller."""
        from vault.core.session import VaultSession
        from vault.ui.app import VaultApplication

        self.tmp = Path(tempfile.mkdtemp(prefix="sv-ui-import-"))
        self.home = self.tmp / "vault"
        self.mirror = self.tmp / "mirror"
        shutil.copytree(FIXTURE, self.mirror)
        VaultSession.create(self.home, PASSWORD).close()
        self.qapp = QApplication.instance() or QApplication([])
        self.controller = VaultApplication(
            self.qapp, home=self.home, language="fa", no_tray=True, self_test=True
        )
        self.session = VaultSession(self.home)
        self.session.unlock(PASSWORD)
        self.controller.attach_session(self.session)
        self.controller.set_settings({"import_joplin": {"mirror_root": str(self.mirror)}})

    def tearDown(self) -> None:
        """Close the session and drop the scratch tree."""
        try:
            self.session.close()
        except Exception:  # noqa: BLE001 - best effort
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_settings_round_trip_the_importer_path(self) -> None:
        """The importer settings must survive a save: a typo must never silently fall back."""
        stored = self.controller.get_settings()["import_joplin"]
        self.assertEqual(stored["mirror_root"], str(self.mirror))
        self.assertEqual(self.controller.import_joplin(wait=True) is not None, True)
        self.assertEqual(self.controller.last_import_mirror, str(self.mirror))

    def test_import_creates_and_is_idempotent(self) -> None:
        """The button imports the mirror, and a second click changes nothing."""
        first = self.controller.import_joplin(wait=True)
        self.assertIsNotNone(first)
        assert first is not None
        self.assertEqual(first["notes_created"], 3)
        self.assertEqual(first["errors"], [])
        self.assertEqual(self.controller.last_import_report["notes_created"], 3)
        self.assertIsNotNone(self.session.index.get_file("Work/first.md"))
        second = self.controller.import_joplin(wait=True)
        assert second is not None
        self.assertEqual(second["notes_created"], 0)
        self.assertEqual(second["notes_skipped"], 3)

    def test_import_marks_secret_globs(self) -> None:
        """Sensitive globs configured in the settings are applied by the UI run."""
        self.controller.set_settings(
            {"import_joplin": {"mirror_root": str(self.mirror), "sensitive_globs": ["*idea*"]}}
        )
        self.controller.import_joplin(wait=True)
        row = self.session.index.get_file("idea.md")
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["sensitivity"], "secret")

    def test_import_refuses_while_locked(self) -> None:
        """A locked vault refuses the import with an explanation and writes nothing."""
        self.session.lock()
        self.assertIsNone(self.controller.import_joplin(wait=True))
        self.assertIn("قفل", self.controller.last_import_error or "")
        self.session.unlock(PASSWORD)
        self.assertIsNone(self.session.index.get_file("Work/first.md"))

    def test_import_missing_mirror_explains(self) -> None:
        """A wrong mirror path produces a message naming the path, not a crash."""
        result = self.controller.import_joplin(wait=True, mirror_root=str(self.tmp / "nope"))
        self.assertIsNone(result)
        self.assertIn("nope", self.controller.last_import_error or "")

    def test_result_dialog_shows_the_counts(self) -> None:
        """The user-visible report carries the numbers from the run."""
        report = self.controller.import_joplin(wait=True)
        assert report is not None
        self.controller.self_test = False
        with mock.patch("vault.ui.app.QMessageBox.information") as info:
            self.controller._on_import_finished(report)
        self.controller.self_test = True
        self.assertTrue(info.called, "no report dialog was shown")
        text = str(info.call_args[0][2])
        self.assertIn("3", text)
        self.assertIn("یادداشت", text)  # the Persian catalogue's wording for "notes"
        self.assertIn("پیوست", text)

    def test_settings_button_runs_the_controller(self) -> None:
        """The Settings button saves first, then starts the configured import."""
        from vault.ui.settings_dialog import SettingsDialog

        dialog = SettingsDialog(self.controller, self.controller.window)
        with mock.patch.object(SettingsDialog, "_on_accept") as accept, mock.patch.object(
            self.controller, "import_joplin"
        ) as run:
            dialog._run_import()
        self.assertTrue(accept.called, "the settings were not persisted before importing")
        self.assertTrue(run.called, "the import was not started")

    def test_catalogues_describe_the_real_feature(self) -> None:
        """The 'later phase' placeholder is gone and both catalogues carry the new keys."""
        required = {
            "import.running",
            "import.done_title",
            "import.done_text",
            "import.mirror_missing",
        }
        catalogues = {
            lang: json.loads((ROOT / "i18n" / f"{lang}.json").read_text(encoding="utf-8"))
            for lang in ("fa", "en")
        }
        self.assertEqual(set(catalogues["fa"]), set(catalogues["en"]))
        for lang, data in catalogues.items():
            self.assertNotIn("settings.import_unavailable", data, lang)
            self.assertTrue(required <= set(data), f"{lang} is missing {sorted(required - set(data))}")
            for key in ("import.done_text", "import.mirror_missing"):
                self.assertIn("{", data[key], f"{lang}:{key} lost its placeholders")
        for path in (ROOT / "src").rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            self.assertNotIn(
                "settings.import_unavailable",
                path.read_text(encoding="utf-8"),
                f"{path} still references the removed placeholder key",
            )


if __name__ == "__main__":  # pragma: no cover - manual run
    unittest.main()
