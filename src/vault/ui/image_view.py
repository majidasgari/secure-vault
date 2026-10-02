"""Native image viewer for pictures stored in the vault (SPEC/03 §2.4, §10).

Pictures live in the vault like any other file, but the markdown editor would only show them
as bytes. This viewer is the native path for them: it renders a ``QPixmap`` in a plain widget,
so a ``secret``/``secretfile`` picture is displayed without a web engine ever seeing it — the
same rule the secret text viewer follows.

The look follows the application theme: the canvas is the theme's surface colour (never the
default white slab in a dark window) and the picture is centred on it.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QEvent, QSize, Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from . import i18n, theme

#: File suffixes the viewer opens. Everything here is decoded by Qt itself.
IMAGE_SUFFIXES: frozenset[str] = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".pbm",
     ".pgm", ".ppm", ".xpm", ".avif"}
)

#: Zoom steps used by the +/- buttons.
ZOOM_STEPS: tuple[float, ...] = (0.25, 0.33, 0.5, 0.67, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0, 4.0)

#: Where the viewer starts on the zoom ladder.
DEFAULT_ZOOM_INDEX = ZOOM_STEPS.index(1.0)

last_path: str | None = None
"""Path of the most recently opened picture (module-level so the smoke test can assert)."""

last_size: tuple[int, int] | None = None
"""Pixel size of the most recently opened picture, or ``None`` when it could not be decoded."""

web_views_created = 0
"""Number of web views ever created by this module (always 0 — the viewer is native)."""


def looks_like_image(path: str) -> bool:
    """True when ``path``'s suffix is one this viewer can render."""
    name = str(path).rsplit("/", 1)[-1]
    if "." not in name:
        return False
    return ("." + name.rsplit(".", 1)[-1].lower()) in IMAGE_SUFFIXES


def decode(data: bytes) -> QPixmap | None:
    """Decode ``data`` into a pixmap, or return ``None`` when Qt cannot read it."""
    pixmap = QPixmap()
    if not pixmap.loadFromData(data):
        return None
    return pixmap


def image_info(data: bytes) -> tuple[int, int] | None:
    """Return the pixel size of ``data`` without decoding it into a pixmap."""
    from PySide6.QtGui import QImage

    image = QImage.fromData(data)
    if image.isNull():
        return None
    return (image.width(), image.height())


class ImageViewer(QDialog):
    """Show one picture with fit-to-window and a small zoom ladder."""

    def __init__(
        self,
        parent: Any,
        path: str,
        data: bytes,
        *,
        sensitivity: str = "normal",
        tray: Any = None,
    ) -> None:
        """Build the viewer for ``path``; ``data`` is the decrypted picture bytes."""
        super().__init__(parent)
        self.path = path
        self.data = data
        self.sensitivity = sensitivity
        self._tray = tray
        self._zoom_index = DEFAULT_ZOOM_INDEX
        self._fit = True
        self._pixmap = decode(data)
        self._source = self._pixmap
        self.setModal(False)
        self.resize(860, 620)

        layout = QVBoxLayout(self)
        self.path_label = QLabel(path, self)
        self.path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.info_label = QLabel(self)
        self.info_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.path_label)
        layout.addWidget(self.info_label)

        self.area = QScrollArea(self)
        self.area.setWidgetResizable(True)
        self.area.setAlignment(Qt.AlignCenter)
        self.canvas = QLabel(self.area)
        self.canvas.setAlignment(Qt.AlignCenter)
        self.canvas.setFrameShape(QFrame.Shape.NoFrame)
        self.canvas.setMinimumSize(1, 1)
        self.area.setWidget(self.canvas)
        # Fit-to-window has to follow the viewport, not just this dialog: the first layout pass
        # happens after __init__, and a scroll area whose viewport is not laid out yet would
        # otherwise leave the picture at a stamp size.
        self.area.viewport().installEventFilter(self)
        layout.addWidget(self.area, 1)

        buttons = QHBoxLayout()
        self.fit_button = QPushButton(self)
        self.actual_button = QPushButton(self)
        self.zoom_in_button = QPushButton(self)
        self.zoom_out_button = QPushButton(self)
        self.fit_button.clicked.connect(self.fit_to_window)
        self.actual_button.clicked.connect(self.actual_size)
        self.zoom_in_button.clicked.connect(lambda: self.step_zoom(1))
        self.zoom_out_button.clicked.connect(lambda: self.step_zoom(-1))
        for button in (self.fit_button, self.actual_button, self.zoom_out_button,
                       self.zoom_in_button):
            buttons.addWidget(button)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.buttons = QDialogButtonBox(self)
        self.buttons.addButton(QDialogButtonBox.Close)
        self.buttons.rejected.connect(self.close)
        self.buttons.clicked.connect(self._on_clicked)
        layout.addWidget(self.buttons)

        self.apply_theme()
        self.retranslate()
        self._redraw()
        i18n.bind(self, self.retranslate)

    # ------------------------------------------------------------------ theme
    def apply_theme(self) -> None:
        """Paint the canvas with the theme's surface colour (no white slab in dark mode)."""
        colors = theme.colors()
        self.canvas.setStyleSheet(
            f"QLabel {{ background: {colors['code_bg']}; color: {colors['muted']}; }}"
        )
        self.area.setStyleSheet(f"QScrollArea {{ background: {colors['code_bg']}; }}")

    # ------------------------------------------------------------------ zoom
    def fit_to_window(self) -> None:
        """Scale the picture so it fits the canvas."""
        self._fit = True
        self._redraw()

    def actual_size(self) -> None:
        """Show the picture at 100 %."""
        self._fit = False
        self._zoom_index = DEFAULT_ZOOM_INDEX
        self._redraw()

    def step_zoom(self, direction: int) -> None:
        """Move one step up or down the zoom ladder."""
        self._fit = False
        self._zoom_index = max(0, min(len(ZOOM_STEPS) - 1, self._zoom_index + direction))
        self._redraw()

    def zoom(self) -> float:
        """Return the current zoom factor (1.0 when fitting is handled by the layout)."""
        return ZOOM_STEPS[self._zoom_index]

    #: Smallest viewport that is worth fitting to; below this the layout has not run yet.
    MIN_VIEWPORT = 32

    def _fit_size(self) -> QSize:
        """Return the size the picture should have when fitted, or its own size."""
        available = self.area.viewport().size()
        if available.width() < self.MIN_VIEWPORT or available.height() < self.MIN_VIEWPORT:
            # No usable viewport yet (first layout pass): show the picture as it is rather
            # than scaling it down to a stamp.
            return self._source.size() if self._source is not None else QSize(0, 0)
        return QSize(max(1, available.width() - 12), max(1, available.height() - 12))

    def _redraw(self) -> None:
        """Push the current zoom/fit state into the canvas label."""
        if self._source is None or self._pixmap is None:
            self.canvas.setText(i18n.tr("image.unsupported"))
            self.fit_button.setEnabled(False)
            self.actual_button.setEnabled(False)
            self.zoom_in_button.setEnabled(False)
            self.zoom_out_button.setEnabled(False)
            return
        if self._fit:
            scaled = self._source.scaled(
                self._fit_size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
            )
        else:
            factor = self.zoom()
            scaled = self._source.scaled(
                self._source.size() * factor, Qt.KeepAspectRatio, Qt.SmoothTransformation
            )
        self.canvas.setPixmap(scaled)
        self.canvas.setText("")
        self.info_label.setText(self._info_text(scaled))

    def eventFilter(self, watched: Any, event: Any) -> bool:  # noqa: N802 - Qt naming
        """Re-fit when the viewport itself changes size (window resize, splitter drag)."""
        try:
            if (
                watched is self.area.viewport()
                and event.type() == QEvent.Type.Resize
                and self._fit
            ):
                self._redraw()
        except Exception:  # noqa: BLE001 - cosmetic only
            pass
        return super().eventFilter(watched, event)

    def _info_text(self, scaled: QPixmap | None = None) -> str:
        """Return the size/zoom line under the title."""
        if self._source is None:
            return i18n.tr("image.unsupported")
        source = self._source
        if self._fit:
            return i18n.tr(
                "image.info_fit",
                width=source.width(),
                height=source.height(),
                percent=100,
            )
        return i18n.tr(
            "image.info_zoom",
            width=source.width(),
            height=source.height(),
            percent=int(round(self.zoom() * 100)),
        )

    def resizeEvent(self, event: Any) -> None:
        """Keep the picture fitted while the window is resized."""
        super().resizeEvent(event)
        if self._fit:
            self._redraw()

    def _on_clicked(self, button: Any) -> None:
        """Close on the standard Close button."""
        if self.buttons.standardButton(button) == QDialogButtonBox.Close:
            self.close()

    def retranslate(self) -> None:
        """Re-apply translated strings."""
        self.setWindowTitle(i18n.tr("image.title"))
        self.fit_button.setText(i18n.tr("image.fit"))
        self.actual_button.setText(i18n.tr("image.actual"))
        self.zoom_in_button.setText(i18n.tr("image.zoom_in"))
        self.zoom_out_button.setText(i18n.tr("image.zoom_out"))
        self.info_label.setText(self._info_text())


def open_image(
    parent: Any,
    path: str,
    data: bytes,
    *,
    sensitivity: str = "normal",
    tray: Any = None,
) -> ImageViewer:
    """Open (non-modally) the image viewer and remember what was shown."""
    global last_path, last_size
    last_path = path
    pixmap = decode(data)
    last_size = (pixmap.width(), pixmap.height()) if pixmap is not None else None
    dialog = ImageViewer(parent, path, data, sensitivity=sensitivity, tray=tray)
    dialog.show()
    return dialog


__all__ = [
    "DEFAULT_ZOOM_INDEX",
    "IMAGE_SUFFIXES",
    "ZOOM_STEPS",
    "ImageViewer",
    "decode",
    "image_info",
    "last_path",
    "last_size",
    "looks_like_image",
    "open_image",
    "web_views_created",
]
