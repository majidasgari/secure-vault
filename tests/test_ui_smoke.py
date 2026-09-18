"""UI smoke test (SPEC/06 §2 test_ui_smoke), run headless under offscreen Qt."""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QtMsgType, qInstallMessageHandler

    HAVE_QT = True
except ImportError:  # pragma: no cover - environment without PySide6
    HAVE_QT = False

# Messages emitted by Qt itself in the offscreen platform that are not our concern.
_BENIGN = (
    "Vulkan",
    "createPlatformVulkanInstance",
    "propagateSizeHints",
    "QStandardPaths",
    "WebEngine",
)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class UiSmokeTest(unittest.TestCase):
    """Build the whole UI against a scratch vault and assert the flows."""

    @classmethod
    def setUpClass(cls) -> None:
        """Install a Qt message recorder and run the self-test once."""
        cls.messages: list[tuple[object, str]] = []

        def handler(mode: object, context: object, message: str) -> None:
            cls.messages.append((mode, message))

        cls._old_handler = qInstallMessageHandler(handler)
        from vault.gui import run_self_test

        cls.result = run_self_test(language="fa", no_tray=True)
        cls.checks = cls.result.checks

    @classmethod
    def tearDownClass(cls) -> None:
        """Shut the app down and restore the environment/handler."""
        try:
            cls.result.controller.shutdown()
        finally:
            qInstallMessageHandler(cls._old_handler)
            if cls.result.previous_xdg is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = cls.result.previous_xdg
            if cls.result.previous_config is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = cls.result.previous_config

    def test_package_importable(self) -> None:
        """The package and the GUI entry point import."""
        import vault
        import vault.gui

        self.assertTrue(hasattr(vault, "__version__"))
        self.assertTrue(callable(vault.gui.main))

    def test_tree_has_expected_folders(self) -> None:
        """The browser tree shows the scratch vault's folders."""
        self.assertGreaterEqual(self.result.window.tree_model.rowCount(), 2)
        self.assertGreater(self.checks["tree_rows"], 0)

    def test_normal_file_preview_enabled(self) -> None:
        """A normal file opens in the editor with the preview enabled."""
        self.assertTrue(self.checks["open_normal"])
        self.assertTrue(self.checks["preview_enabled_normal"])
        self.assertTrue(self.checks["normal_content"])

    def test_secret_file_preview_disabled(self) -> None:
        """A secret file opens after confirmation with the preview disabled."""
        self.assertTrue(self.checks["open_secret"])
        self.assertTrue(self.checks["preview_disabled_secret"])
        self.assertTrue(self.checks["secret_content"])

    def test_secretfile_uses_native_viewer(self) -> None:
        """A secretfile uses the native viewer and never a web view."""
        self.assertTrue(self.checks["open_secretfile"])
        self.assertEqual(self.checks["viewer_text"], "token=alpha-secret")
        self.assertFalse(self.checks["viewer_uses_web"])
        self.assertEqual(self.checks["web_views_for_secretfile"], 0)
        self.assertTrue(self.checks["secretfile_logged"])

    def test_search_three_kinds(self) -> None:
        """All three search kinds return results (semantic via the stub)."""
        self.assertGreater(self.checks["search_filename"], 0)
        self.assertGreater(self.checks["search_text"], 0)
        self.assertGreater(self.checks["search_semantic"], 0)
        self.assertEqual(
            len(self.result.search_panel.last_results("filename")),
            self.checks["last_results_filename"],
        )

    def test_log_panel_grows(self) -> None:
        """The access-log panel grows after an action."""
        self.assertTrue(self.checks["log_grows"])
        self.assertGreater(self.checks["log_rows"], 0)

    def test_language_switch_and_rtl(self) -> None:
        """Switching to en retranslates a label; fa flips the layout RTL."""
        from vault.ui import i18n

        self.assertTrue(self.checks["label_changed"])
        self.assertEqual(self.checks["lang_en"], "en")
        self.assertEqual(self.checks["lang_fa"], "fa")
        self.assertTrue(self.checks["ltr"])
        self.assertTrue(self.checks["rtl"])
        self.assertEqual(i18n.lang, "fa")
        from PySide6.QtCore import Qt

        self.assertEqual(self.result.qapp.layoutDirection(), Qt.RightToLeft)

    def test_settings_dialog_opens(self) -> None:
        """The settings dialog opens and closes without touching a real vault."""
        self.assertTrue(self.checks["settings_ok"])

    def test_tray_and_notifications_degrade(self) -> None:
        """Tray/notification use degrades gracefully with no tray daemon."""
        from vault.ui import notifications
        from vault.ui.tray import TrayIcon

        tray = TrayIcon()
        tray.notify("title", "body")
        entry = notifications.notify("Title", "Body", tray=tray)
        self.assertEqual(entry["title"], "Title")
        self.assertTrue(notifications.recent())
        tray.hide()

    def test_lock_returns_to_unlock(self) -> None:
        """Locking returns the app to the unlock screen."""
        self.assertTrue(self.checks["locked_screen"])
        self.assertEqual(self.result.controller.current_screen, "unlock")
        self.assertTrue(self.checks["session_locked"])

    def test_no_exception_reaches_message_handler(self) -> None:
        """No critical/fatal or unexpected Qt message was recorded."""
        unexpected = []
        for mode, message in self.messages:
            if any(token in message for token in _BENIGN):
                continue
            if mode in (QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
                unexpected.append(message)
            elif "Traceback" in message or "Exception" in message:
                unexpected.append(message)
        self.assertEqual(unexpected, [], f"unexpected Qt messages: {unexpected}")


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class EditorBidiTest(unittest.TestCase):
    """The Qt markdown editor applies per-block directions (SPEC/08 §A)."""

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure a single offscreen QApplication exists."""
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication(["editor-bidi-test"])

    def test_per_block_directions_and_monospace(self) -> None:
        """Persian → RTL/right, English → LTR, fence → LTR + monospace."""
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QTextCursor

        from vault.ui.editor import EditorPanel

        editor = EditorPanel()
        editor.set_content(
            "/notes/x.md",
            "متن فارسی\n\nEnglish text\n\n```\n# یادداشت\n```",
            preview_enabled=True,
        )
        document = editor.source.document()
        first = document.begin()
        self.assertEqual(first.blockFormat().textDirection(), Qt.RightToLeft)
        self.assertEqual(first.blockFormat().alignment(), Qt.AlignRight)
        english = first.next()
        self.assertEqual(english.blockFormat().textDirection(), Qt.LeftToRight)
        fence = english.next()
        self.assertEqual(fence.blockFormat().textDirection(), Qt.LeftToRight)
        cursor = QTextCursor(document)
        cursor.setPosition(fence.position() + 1)
        self.assertTrue(cursor.charFormat().fontFixedPitch())
        self.assertFalse(editor.is_dirty())

    def test_cycle_direction_uniform(self) -> None:
        """Cycling the mode applies one direction to every block."""
        from PySide6.QtCore import Qt

        from vault.ui.editor import EditorPanel

        editor = EditorPanel()
        editor.set_content("/n.md", "متن فارسی\n\nEnglish", preview_enabled=False)
        self.assertEqual(editor.cycle_direction(), "rtl")
        block = editor.source.document().begin()
        while block.isValid():
            self.assertEqual(block.blockFormat().textDirection(), Qt.RightToLeft)
            block = block.next()
        self.assertEqual(editor.cycle_direction(), "ltr")
        block = editor.source.document().begin()
        while block.isValid():
            self.assertEqual(block.blockFormat().textDirection(), Qt.LeftToRight)
            block = block.next()

    def test_preview_dir_attributes(self) -> None:
        """The preview HTML marks blocks auto and code LTR."""
        from vault.ui.editor import render_markdown

        rendered = render_markdown("متن فارسی\n\n```\ncode\n```")
        self.assertIn('dir="auto"', rendered)
        self.assertIn('<pre dir="ltr">', rendered)
        self.assertIn('dir="ltr"', rendered)

    def test_browser_url(self) -> None:
        """``browser_url`` encodes the note path and is None while locked."""
        from vault.ui.editor import EditorPanel

        editor = EditorPanel()
        editor.set_content("/notes/hello.md", "x", preview_enabled=True)
        editor.locked = False
        editor.web_port = 8788
        self.assertEqual(
            editor.browser_url,
            "http://127.0.0.1:8788/#/note/%2Fnotes%2Fhello.md",
        )
        editor.locked = True
        self.assertIsNone(editor.browser_url)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class SemanticProgressUiTest(unittest.TestCase):
    """The semantic build shows a determinate, count-based progress bar."""

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure a single offscreen QApplication exists."""
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication(["sv-semantic-progress"])

    def test_progress_dialog_is_determinate_and_polled(self) -> None:
        """The bar has a 0..100 range and tracks the adapter's count/percentage."""
        import tempfile
        from pathlib import Path

        from vault.ui.app import SemanticProgress, VaultApplication

        controller = VaultApplication(
            self.app,
            home=Path(tempfile.mkdtemp(prefix="sv-semprog-")),
            no_tray=True,
            self_test=False,
        )
        try:
            adapter = SemanticProgress()
            controller._show_semantic_progress(adapter)
            dialog = controller._import_progress
            self.assertIsNotNone(dialog)
            self.assertEqual(dialog.minimum(), 0)
            self.assertEqual(dialog.maximum(), 100)
            self.assertEqual(dialog.value(), 0)

            adapter(3, 12)
            controller._poll_semantic_progress()
            self.assertEqual(dialog.value(), 25)
            self.assertIn("3", dialog.labelText())
            self.assertIn("12", dialog.labelText())

            controller._on_semantic_finished({"indexed": 12, "skipped": 0})
            self.assertIsNone(controller._import_progress)
            self.assertFalse(controller.import_running)
        finally:
            controller.shutdown()


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class SemanticSettingsUiTest(unittest.TestCase):
    """The Settings → Semantic folder tree and select/deselect-all buttons."""

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure a single offscreen QApplication exists."""
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication(["sv-semantic-settings"])

    @staticmethod
    def _items(tree):
        """Yield every item in ``tree`` depth-first."""

        def walk(parent):
            for index in range(parent.childCount()):
                child = parent.child(index)
                yield child
                yield from walk(child)

        return list(walk(tree.invisibleRootItem()))

    def test_folder_scope_checkboxes(self) -> None:
        """Stored folder states drive the tree; select/deselect all rewrite them."""
        import os
        import tempfile
        from pathlib import Path

        from PySide6.QtCore import Qt

        from support import tmp_vault
        from vault.ui.app import VaultApplication
        from vault.ui.settings_dialog import SettingsDialog

        previous_config = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="sv-semcfg-")
        session = tmp_vault(
            settings={
                "web": {"enabled": False},
                "semantic": {
                    "enabled": True,
                    "provider": "stub",
                    "model": "stub",
                    "folder_states": {"private": False},
                },
            }
        )
        session.write_file("notes/a.md", b"alpha")
        session.write_file("private/b.md", b"beta")
        controller = VaultApplication(
            self.app, home=session.home, no_tray=True, self_test=True
        )
        try:
            controller.attach_session(session)
            dialog = SettingsDialog(controller, controller.window)
            keys = {item.data(0, Qt.ItemDataRole.UserRole) for item in self._items(dialog.folder_tree)}
            self.assertIn("notes", keys)
            self.assertIn("private", keys)
            by_key = {
                item.data(0, Qt.ItemDataRole.UserRole): item
                for item in self._items(dialog.folder_tree)
            }
            self.assertEqual(by_key["private"].checkState(0), Qt.CheckState.Unchecked)
            self.assertEqual(by_key["notes"].checkState(0), Qt.CheckState.Checked)

            dialog._set_all_folders(False)
            self.assertEqual(dialog._folder_states, {"*": False})
            self.assertTrue(
                all(
                    item.checkState(0) == Qt.CheckState.Unchecked
                    for item in self._items(dialog.folder_tree)
                )
            )
            dialog._set_all_folders(True)
            self.assertEqual(dialog._folder_states, {})
            self.assertTrue(
                all(
                    item.checkState(0) == Qt.CheckState.Checked
                    for item in self._items(dialog.folder_tree)
                )
            )
            dialog.close()
        finally:
            controller.shutdown()
            session.close()
            if previous_config is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = previous_config


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class WebShellSmokeTest(unittest.TestCase):
    """The in-process web shell starts with the app (SPEC/09 §A, §D)."""

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure a single offscreen QApplication exists."""
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication(["web-shell-test"])

    def test_web_started_and_link(self) -> None:
        """The self-test controller exposes a running web server and a token URL."""
        import os

        from vault.gui import run_self_test

        result = run_self_test(language="fa", no_tray=True)
        try:
            controller = result.controller
            self.assertIsNotNone(controller.web)
            self.assertGreater(int(controller.web.port), 0)
            link = controller.web_link()
            self.assertIsNotNone(link)
            self.assertIn("token=", link)
            controller.copy_web_link()
            from PySide6.QtGui import QGuiApplication

            self.assertEqual(QGuiApplication.clipboard().text(), link)
        finally:
            result.controller.shutdown()
            if result.previous_xdg is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = result.previous_xdg
            if result.previous_config is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = result.previous_config

    def test_web_disabled_starts_nothing(self) -> None:
        """``web.enabled=false`` leaves ``VaultApplication.web`` as None."""
        import os
        import tempfile
        from pathlib import Path

        from support import tmp_vault
        from vault.ui.app import VaultApplication

        previous_config = os.environ.get("XDG_CONFIG_HOME")
        config_home = Path(tempfile.mkdtemp(prefix="sv-webcfg-"))
        os.environ["XDG_CONFIG_HOME"] = str(config_home)
        session = tmp_vault(settings={"web": {"enabled": False}})
        controller = VaultApplication(
            self.app, home=session.home, no_tray=True, self_test=True
        )
        try:
            controller.attach_session(session)
            self.assertIsNone(controller.web)
        finally:
            controller.shutdown()
            session.close()
            if previous_config is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = previous_config


if __name__ == "__main__":
    unittest.main()
