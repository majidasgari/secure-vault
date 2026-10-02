"""Tests for the native image viewer and the appearance preference (SPEC/06 §2).

Run headless under offscreen Qt like the other UI tests.
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QBuffer, QByteArray
    from PySide6.QtGui import QColor, QPixmap
    from PySide6.QtWidgets import QApplication

    HAVE_QT = True
except ImportError:  # pragma: no cover - environment without PySide6
    HAVE_QT = False

from vault.ui import i18n, image_view, theme
from vault.ui.highlight import palette_colors

if HAVE_QT:
    # Qt needs an application object before any QPixmap exists, and the decode tests do not
    # build a widget first — keep one alive for the whole module.
    _APP = QApplication.instance() or QApplication(["secure-vault-tests"])


def ensure_app() -> object:
    """Return the module's QApplication (created on first use if needed)."""
    global _APP
    if QApplication.instance() is None:
        _APP = QApplication(["secure-vault-tests"])
    return QApplication.instance()


def png_bytes(width: int = 6, height: int = 4) -> bytes:
    """Return a small solid-colour PNG."""
    pixmap = QPixmap(width, height)
    pixmap.fill(QColor("#336699"))
    array = QByteArray()
    buffer = QBuffer(array)
    buffer.open(QBuffer.OpenModeFlag.WriteOnly)
    pixmap.save(buffer, "PNG")
    buffer.close()
    return bytes(array.data())


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class LooksLikeImageTest(unittest.TestCase):
    """Suffix classification decides whether the editor or the viewer opens a file."""

    def test_known_suffixes(self) -> None:
        for path in ("/a/b.png", "/a/b.JPG", "/a/b.jpeg", "/x.webp", "/x.gif", "/x.BMP"):
            with self.subTest(path=path):
                self.assertTrue(image_view.looks_like_image(path))

    def test_non_images(self) -> None:
        for path in ("/a/b.md", "/a/b.txt", "/a/b", "/a/b.png.txt", "/png"):
            with self.subTest(path=path):
                self.assertFalse(image_view.looks_like_image(path))


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class DecodeTest(unittest.TestCase):
    """Decoding real bytes and refusing everything else."""

    def test_decode_and_info(self) -> None:
        data = png_bytes(6, 4)
        pixmap = image_view.decode(data)
        self.assertIsNotNone(pixmap)
        self.assertEqual((pixmap.width(), pixmap.height()), (6, 4))
        self.assertEqual(image_view.image_info(data), (6, 4))

    def test_decode_refuses_garbage(self) -> None:
        self.assertIsNone(image_view.decode(b"not a picture at all"))
        self.assertIsNone(image_view.image_info(b"not a picture at all"))


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class ImageViewerTest(unittest.TestCase):
    """The viewer itself: zoom, theming and the honest message for non-pictures."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.qapp = ensure_app()

    def setUp(self) -> None:
        self._previous = theme.preference()
        theme.set_preference("system")

    def tearDown(self) -> None:
        theme.set_preference(self._previous)

    def test_fit_then_zoom_ladder(self) -> None:
        dialog = image_view.ImageViewer(None, "/notes/shot.png", png_bytes())
        self.addCleanup(dialog.close)
        dialog.fit_to_window()
        self.assertTrue(dialog._fit)
        dialog.actual_size()
        self.assertFalse(dialog._fit)
        self.assertEqual(dialog.zoom(), 1.0)
        dialog.step_zoom(1)
        self.assertEqual(dialog.zoom(), 1.25)
        dialog.step_zoom(-1)
        dialog.step_zoom(-1)
        self.assertEqual(dialog.zoom(), 0.75)
        dialog.step_zoom(99)
        self.assertEqual(dialog.zoom(), image_view.ZOOM_STEPS[-1])
        dialog.step_zoom(-99)
        self.assertEqual(dialog.zoom(), image_view.ZOOM_STEPS[0])

    def test_canvas_follows_the_theme(self) -> None:
        """No white slab: the canvas is painted with the theme's surface colour."""
        theme.set_preference("dark")
        dark = image_view.ImageViewer(None, "/notes/shot.png", png_bytes())
        self.addCleanup(dark.close)
        self.assertIn(theme.colors()["code_bg"], dark.canvas.styleSheet())
        theme.set_preference("light")
        dark.apply_theme()
        self.assertIn(theme.colors()["code_bg"], dark.canvas.styleSheet())
        self.assertNotEqual(theme.colors()["code_bg"], palette_colors(True)["code_bg"])

    def test_info_line_reports_the_size(self) -> None:
        dialog = image_view.ImageViewer(None, "/notes/shot.png", png_bytes(6, 4))
        self.addCleanup(dialog.close)
        self.assertIn("6", dialog.info_label.text())
        self.assertIn("4", dialog.info_label.text())
        dialog.actual_size()
        self.assertIn("100", dialog.info_label.text())

    def test_unreadable_picture_disables_the_controls(self) -> None:
        dialog = image_view.ImageViewer(None, "/notes/broken.png", b"definitely not a picture")
        self.addCleanup(dialog.close)
        self.assertEqual(dialog.canvas.text(), i18n.tr("image.unsupported"))
        for button in (dialog.fit_button, dialog.actual_button, dialog.zoom_in_button,
                       dialog.zoom_out_button):
            self.assertFalse(button.isEnabled())

    def test_fit_follows_the_viewport(self) -> None:
        """A fitted picture fills the canvas instead of staying at a stamp size.

        Regression: the fit was computed in ``__init__``, before the layout ran, so the first
        picture opened came out ~20 px wide.
        """
        dialog = image_view.ImageViewer(None, "/notes/shot.png", png_bytes(400, 300))
        self.addCleanup(dialog.close)
        dialog.resize(700, 500)
        dialog.show()
        ensure_app().processEvents()
        fitted = dialog.canvas.pixmap().size()
        self.assertGreater(fitted.width(), 300, "fitted picture is a stamp")
        self.assertLessEqual(fitted.width(), 700)
        # Scaling rounds to whole pixels, so the ratio only has to hold within one pixel.
        expected_height = round(fitted.width() * 300 / 400)
        self.assertLessEqual(abs(fitted.height() - expected_height), 1, "aspect ratio changed")

    def test_fit_before_a_layout_keeps_the_source_size(self) -> None:
        """Without a usable viewport the picture is shown as it is, not scaled down."""
        dialog = image_view.ImageViewer(None, "/notes/shot.png", png_bytes(6, 4))
        self.addCleanup(dialog.close)
        self.assertEqual(dialog.canvas.pixmap().size(), dialog._source.size())
        self.assertEqual(dialog._fit_size(), dialog._source.size())

    def test_open_image_remembers_and_stays_native(self) -> None:
        before = image_view.web_views_created
        data = png_bytes(6, 4)
        dialog = image_view.open_image(None, "/notes/shot.png", data)
        self.addCleanup(dialog.close)
        self.assertEqual(image_view.last_path, "/notes/shot.png")
        self.assertEqual(image_view.last_size, (6, 4))
        self.assertEqual(image_view.web_views_created, before)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class ThemePreferenceTest(unittest.TestCase):
    """The appearance preference and the palettes behind it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.qapp = ensure_app()

    def setUp(self) -> None:
        self._previous = theme.preference()
        theme.set_preference("system")

    def tearDown(self) -> None:
        theme.set_preference(self._previous)

    def test_preference_normalisation(self) -> None:
        self.assertEqual(theme.set_preference("DARK"), "dark")
        self.assertEqual(theme.set_preference(" light "), "light")
        self.assertEqual(theme.set_preference("nonsense"), "system")
        self.assertEqual(theme.set_preference(None), "system")

    def test_forced_theme_wins_over_the_desktop(self) -> None:
        theme.set_preference("dark")
        self.assertTrue(theme.is_dark())
        self.assertEqual(theme.colors()["bg"], palette_colors(True)["bg"])
        self.assertNotEqual(palette_colors(True)["bg"], palette_colors(False)["bg"])
        theme.set_preference("light")
        self.assertFalse(theme.is_dark())
        self.assertEqual(theme.colors()["bg"], palette_colors(False)["bg"])

    def test_system_theme_is_answered(self) -> None:
        self.assertIn(theme.detect_system_theme(), ("dark", "light"))
        self.assertIn(theme.preference(), theme.THEMES)