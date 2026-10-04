"""UI smoke test (SPEC/06 §2 test_ui_smoke), run headless under offscreen Qt."""

from __future__ import annotations

import os
import unittest
from unittest import mock

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
def _block_direction(fmt):
    """Return a block's direction, whichever name this PySide6 version uses.

    Qt 6 renamed ``QTextBlockFormat.textDirection`` to ``layoutDirection``; PySide6 6.11 only
    has the new name, older versions only the old one.
    """
    getter = getattr(fmt, "layoutDirection", None) or getattr(fmt, "textDirection")
    return getter()


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
            if cls.result.previous_data is None:
                os.environ.pop("XDG_DATA_HOME", None)
            else:
                os.environ["XDG_DATA_HOME"] = cls.result.previous_data

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

    def test_secretfile_otp_code_shown(self) -> None:
        """A credential body with an OTP field shows a live code and never a web view."""
        self.assertTrue(self.checks["open_secretfile_otp"])
        self.assertTrue(self.checks["viewer_otp_live"])
        self.assertEqual(self.checks["viewer_otp_digits"], 6)
        self.assertTrue(self.checks["viewer_otp_grouped"])
        self.assertTrue(self.checks["viewer_otp_countdown"])
        self.assertEqual(self.checks["web_views_for_otp"], 0)

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
        by_text = {}
        block = document.begin()
        while block.isValid():
            by_text.setdefault(block.text(), block)
            block = block.next()
        # Blocks are picked by their text: a blank separator block simply inherits the
        # direction of the block before it, so counting `next()` steps is not meaningful.
        first = by_text["متن فارسی"]
        self.assertEqual(_block_direction(first.blockFormat()), Qt.RightToLeft)
        # Qt keeps the absolute bit alongside the logical alignment (AlignRight|AlignAbsolute).
        self.assertTrue(first.blockFormat().alignment() & Qt.AlignRight)
        english = by_text["English text"]
        self.assertEqual(_block_direction(english.blockFormat()), Qt.LeftToRight)
        fence = by_text["```"]
        self.assertEqual(_block_direction(fence.blockFormat()), Qt.LeftToRight)
        # A highlighter writes its formats into the block *layout*, not into the character
        # format the cursor reports: read them where they are.
        self.app.processEvents()
        layout = fence.layout()
        ranges = list(layout.formats()) if layout is not None else []
        families = [str(name) for item in ranges for name in item.format.fontFamilies()]
        self.assertTrue(
            any("mono" in name.lower() for name in families),
            f"fenced code is not monospace: {families}",
        )
        colours = [item.format.background().color().name() for item in ranges]
        self.assertTrue(colours, "fenced code carries no background colour")
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
            self.assertEqual(_block_direction(block.blockFormat()), Qt.RightToLeft)
            block = block.next()
        self.assertEqual(editor.cycle_direction(), "ltr")
        block = editor.source.document().begin()
        while block.isValid():
            self.assertEqual(_block_direction(block.blockFormat()), Qt.LeftToRight)
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
class EditorPreviewTest(unittest.TestCase):
    """The preview refreshes on demand, never on every keystroke (large-file fix)."""

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure a single offscreen QApplication exists."""
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication(["editor-preview-test"])

    def test_typing_does_not_render_the_preview(self) -> None:
        """An edit schedules the bidi pass but must not re-render the preview."""
        from vault.ui.editor import EditorPanel

        editor = EditorPanel()
        editor.set_content("/notes/big.md", "سلام\n\nEnglish\n", preview_enabled=True)
        calls: list[int] = []
        editor._render_preview = lambda: calls.append(1)  # type: ignore[method-assign]
        editor.source.insertPlainText("more")
        editor._bidi_timer.timeout.emit()
        self.assertEqual(calls, [])

    def test_preview_button_renders_on_demand(self) -> None:
        """The toolbar button shows/refreshes the preview when the user asks."""
        from vault.ui.editor import EditorPanel

        editor = EditorPanel()
        editor.set_content("/notes/big.md", "hello", preview_enabled=True)
        editor.preview_enabled = False
        calls: list[int] = []
        editor._render_preview = lambda: calls.append(1)  # type: ignore[method-assign]
        editor._on_preview_clicked()
        self.assertTrue(editor.preview_enabled)
        self.assertEqual(calls, [1])
        editor._on_preview_clicked()
        self.assertEqual(calls, [1, 1])

    def test_editing_only_formats_the_current_block(self) -> None:
        """The per-keystroke bidi pass keeps the caret and leaves other blocks alone."""
        from PySide6.QtCore import Qt

        from vault.ui.editor import EditorPanel

        editor = EditorPanel()
        editor.set_content(
            "/notes/x.md",
            "متن فارسی\n\nEnglish text\n\nمتن دیگر",
            preview_enabled=False,
        )
        document = editor.source.document()
        untouched = document.begin().next().next()
        before = untouched.blockFormat().layoutDirection()
        cursor = editor.source.textCursor()
        cursor.setPosition(document.begin().next().position() + 2)
        editor.source.setTextCursor(cursor)
        editor._apply_current_block_bidi()
        self.assertEqual(editor.source.textCursor().position(), cursor.position())
        self.assertEqual(untouched.blockFormat().layoutDirection(), before)
        self.assertEqual(
            editor.source.textCursor().block().blockFormat().layoutDirection(),
            Qt.LeftToRight,
        )


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
            if result.previous_data is None:
                os.environ.pop("XDG_DATA_HOME", None)
            else:
                os.environ["XDG_DATA_HOME"] = result.previous_data

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


class QuickUnlockAutoScanTest(unittest.TestCase):
    """With quick unlock enabled the unlock screen offers the sensor by itself."""

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure a single offscreen QApplication exists."""
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication(["sv-quick-unlock"])

    def setUp(self) -> None:
        """Build a scratch vault with quick unlock enabled and a fake sensor."""
        from support import tmp_vault
        from vault.core import fingerprint
        from vault.ui.app import VaultApplication

        self.session = tmp_vault()
        self.addCleanup(self.session.close)
        self.session.quick_unlock_enable(
            fingerprint.VerifyResult(True, "match", "0.0s", ("test-finger",))
        )
        device = mock.patch.object(
            fingerprint,
            "device_info",
            return_value={
                "available": True,
                "device": "Test Sensor",
                "fingers": ["right-index-finger"],
                "username": "tester",
                "reason": "ok",
            },
        )
        device.start()
        self.addCleanup(device.stop)
        self.controller = VaultApplication(
            self.app, home=self.session.home, no_tray=True, self_test=True
        )
        self.addCleanup(self.controller.shutdown)

    def test_enabled_quick_unlock_arms_the_scan(self) -> None:
        """Showing the unlock screen schedules a scan and keeps the button reachable."""
        screen = self.controller.show_unlock()
        self.assertTrue(self.controller.auto_scan_armed())
        self.assertFalse(screen.fingerprint_button.isHidden())

    def test_armed_scan_starts_by_itself(self) -> None:
        """The scheduled scan calls the unlock path with ``auto`` set."""
        self.controller.show_unlock()
        with mock.patch.object(
            self.controller, "unlock_with_fingerprint", return_value=True
        ) as scan:
            self.controller._auto_scan_fire()
        scan.assert_called_once_with(auto=True)
        self.assertFalse(self.controller.auto_scan_armed())

    def test_typing_the_password_cancels_the_scan(self) -> None:
        """A typed password takes over: the sensor is not offered any more."""
        screen = self.controller.show_unlock()
        screen.password.setText("master-phrase")
        screen.password.textEdited.emit("master-phrase")
        self.assertFalse(self.controller.auto_scan_armed())
        with mock.patch.object(
            self.controller, "unlock_with_fingerprint", return_value=True
        ) as scan:
            self.controller._auto_scan_fire()
        scan.assert_not_called()

    def test_unanswered_scan_keeps_waiting(self) -> None:
        """A scan nobody answered re-arms instead of reporting a failure."""
        from vault.ui import i18n

        screen = self.controller.show_unlock()
        self.controller._on_fingerprint_finished(
            {"action": "unlock", "ok": False, "reason": "timeout", "auto": True}
        )
        self.assertTrue(self.controller.auto_scan_armed())
        self.assertIn(i18n.tr("unlock.fingerprint_scanning"), screen.fingerprint_status.text())

    def test_manual_failure_is_reported(self) -> None:
        """A scan the user asked for reports its reason and does not re-arm."""
        from vault.ui import i18n

        screen = self.controller.show_unlock()
        self.controller._on_fingerprint_finished(
            {"action": "unlock", "ok": False, "reason": "no_match", "auto": False}
        )
        self.assertFalse(self.controller.auto_scan_armed())
        self.assertIn(i18n.tr("fingerprint.reason.no_match"), screen.fingerprint_status.text())

    def test_disabled_quick_unlock_does_not_arm(self) -> None:
        """Without a record the screen waits for the password only."""
        self.session.quick_unlock_disable()
        screen = self.controller.show_unlock()
        self.assertFalse(self.controller.auto_scan_armed())
        self.assertTrue(screen.fingerprint_button.isHidden())


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class SecretViewerOtpTest(unittest.TestCase):
    """The native viewer renders a live code for a credential body (desktop-only surface)."""

    BODY = (
        "# GitHub\n\nسایت: github.com | دسته: برنامه‌نویسی\n\n"
        "نام کاربری: demo\nگذرواژه: demo-pass\n"
        "کد یکبارمصرف (otp): otpauth://totp/github.com:demo"
        "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub\n"
    )
    PLAIN_BODY = "# بانک نمونه\n\nسایت: bank.ir\n\nشماره کارت: 6037991234567890\n"

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure a single offscreen QApplication exists and the fa catalogue is active."""
        from PySide6.QtWidgets import QApplication

        from vault.ui import i18n

        cls.app = QApplication.instance() or QApplication(["sv-viewer-otp"])
        i18n.set_language("fa")

    def test_live_code_countdown_and_copy(self) -> None:
        """The code comes from the RFC algorithm, the countdown tracks the step, copy is code-only."""
        from PySide6.QtGui import QGuiApplication

        from vault.ui import notifications, viewer

        dialog = viewer.SecretViewer(None, "/رمزها/گیت‌هاب/github.com.md", self.BODY)
        try:
            dialog.refresh_otp(at=59)          # 8-digit vector 94287082 → 6 digits 287082
            self.assertEqual(dialog.otp_code.text(), "287 082")
            assert dialog.otp is not None
            self.assertEqual(dialog.otp.code, "287082")      # what the copy button puts out
            self.assertTrue(dialog.otp_box.isVisibleTo(dialog))
            self.assertEqual(dialog.otp_remaining.text(), "1 ثانیه مانده")
            self.assertEqual(dialog.otp_bar.maximum(), 30)
            self.assertEqual(dialog.otp_bar.value(), 1)
            self.assertTrue(dialog.otp_code.layoutDirection().name == "LeftToRight")

            dialog.refresh_otp(at=60)          # next step: a different code, full countdown
            self.assertNotEqual(dialog.otp_code.text(), "287 082")
            self.assertEqual(dialog.otp_bar.value(), 30)

            dialog.copy_otp()
            self.assertEqual(QGuiApplication.clipboard().text(), dialog.otp_code.text().replace(" ", ""))
            self.assertIn(dialog.path, notifications.recent()[-1]["body"])
            self.assertNotIn(dialog.otp_code.text(), notifications.recent()[-1]["body"])
            self.assertFalse(viewer.uses_web_engine)
        finally:
            dialog.close()

    def test_body_without_otp_shows_no_row(self) -> None:
        """A card entry has nothing to count down: the row stays hidden."""
        from vault.ui import viewer

        dialog = viewer.SecretViewer(None, "/رمزها/بانک/bank.md", self.PLAIN_BODY)
        try:
            self.assertIsNone(dialog.otp)
            self.assertFalse(dialog.otp_box.isVisibleTo(dialog))
            # A card number is neither a user name nor a password: no copy button for it.
            self.assertFalse(dialog.field_actions.isVisibleTo(dialog))
            self.assertFalse(dialog.copy_username_button.isVisibleTo(dialog))
            self.assertFalse(dialog.copy_password_button.isVisibleTo(dialog))
        finally:
            dialog.close()

    def test_username_and_password_copy_buttons(self) -> None:
        """Each field gets its own copy button and copies only that value."""
        from PySide6.QtGui import QGuiApplication

        from vault.ui import notifications, viewer

        dialog = viewer.SecretViewer(None, "/رمزها/گیت‌هاب/github.com.md", self.BODY)
        try:
            self.assertTrue(dialog.field_actions.isVisibleTo(dialog))
            self.assertTrue(dialog.copy_username_button.isVisibleTo(dialog))
            self.assertTrue(dialog.copy_password_button.isVisibleTo(dialog))
            self.assertEqual(dialog.copy_username_button.text(), "رونوشت نام کاربری")
            self.assertEqual(dialog.copy_password_button.text(), "رونوشت رمز عبور")

            dialog.copy_username()
            self.assertEqual(QGuiApplication.clipboard().text(), "demo")
            dialog.copy_password()
            self.assertEqual(QGuiApplication.clipboard().text(), "demo-pass")

            # The notice names the file and the field, never the value.
            body = notifications.recent()[-1]["body"]
            self.assertIn(dialog.path, body)
            self.assertNotIn("demo-pass", body)

            recorded = viewer.open_viewer(None, dialog.path, self.BODY)
            try:
                self.assertEqual(
                    viewer.last_actions, {"username": True, "password": True, "otp": True}
                )
            finally:
                recorded.close()
        finally:
            dialog.close()

    def test_field_buttons_absent_for_a_plain_note(self) -> None:
        """A note with no credential fields offers no copy button at all."""
        from vault.ui import viewer

        dialog = viewer.open_viewer(None, "/memory/dream.md", "# رویا\n\nمتن ساده\n")
        try:
            self.assertFalse(dialog.field_actions.isVisibleTo(dialog))
            self.assertEqual(viewer.last_actions, {"username": False, "password": False, "otp": False})
        finally:
            dialog.close()

    def test_backup_code_is_shown_without_a_countdown(self) -> None:
        """A pasted code is displayed as-is, with the static hint and no progress bar."""
        from vault.ui import viewer

        body = self.BODY.replace(
            "otpauth://totp/github.com:demo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub",
            "987654",
        )
        dialog = viewer.SecretViewer(None, "/x/backup.md", body)
        try:
            self.assertIsNotNone(dialog.otp)
            self.assertFalse(dialog.otp.live)
            self.assertEqual(dialog.otp_code.text(), "987654")
            self.assertFalse(dialog.otp_bar.isVisibleTo(dialog))
            self.assertEqual(dialog.otp_remaining.text(), "کد پشتیبان (بدون شمارش)")
        finally:
            dialog.close()

    def test_open_viewer_records_the_code_for_the_self_test(self) -> None:
        """``open_viewer`` records a seed-free descriptor (the code, never the secret)."""
        from vault.ui import viewer

        dialog = viewer.open_viewer(None, "/x/demo.md", self.BODY)
        try:
            recorded = viewer.last_otp
            self.assertIsNotNone(recorded)
            assert recorded is not None
            self.assertEqual(len(recorded["code"]), 6)
            self.assertTrue(recorded["live"])
            self.assertNotIn("secret", recorded)
            self.assertNotIn("GEZDGNBVGY3TQOJQ", str(recorded))
        finally:
            dialog.close()


if __name__ == "__main__":
    unittest.main()
