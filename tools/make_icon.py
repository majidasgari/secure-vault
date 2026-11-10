"""Re-render ``assets/icon.svg`` into the multi-size ``assets/secure-vault.ico`` Windows uses.

Windows shortcuts cannot use an SVG, so the icon the Start menu and the Startup entry show is a
generated ``.ico``. Re-run this after changing ``assets/icon.svg``:

    QT_QPA_PLATFORM=offscreen ./.venv/bin/python tools/make_icon.py

(On Windows: ``portable\\win\\python.exe tools\\make_icon.py``.) Each size is stored as a PNG
payload, which is what Windows Vista and later expect inside an ``.ico`` container.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice
from PySide6.QtGui import QColor, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QApplication

REPO_ROOT = Path(__file__).resolve().parent.parent
SIZES = (16, 24, 32, 48, 64, 128, 256)


def render(svg: Path, sizes: tuple[int, ...] = SIZES) -> list[tuple[int, bytes]]:
    """Render ``svg`` at every size in ``sizes`` and return ``[(size, png_bytes)]``."""
    renderer = QSvgRenderer(QByteArray(svg.read_bytes()))
    if not renderer.isValid():
        raise SystemExit(f"not a renderable SVG: {svg}")
    out: list[tuple[int, bytes]] = []
    for size in sizes:
        image = QImage(size, size, QImage.Format_ARGB32)
        image.fill(QColor(0, 0, 0, 0))
        painter = QPainter(image)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
        renderer.render(painter)
        painter.end()
        buffer = QBuffer()
        buffer.open(QIODevice.WriteOnly)
        if not image.save(buffer, "PNG"):
            raise SystemExit(f"PNG encoding failed at {size}px")
        out.append((size, bytes(buffer.data())))
    return out


def pack_ico(images: list[tuple[int, bytes]]) -> bytes:
    """Pack PNG payloads into an ICO container (each entry may be a whole PNG file)."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = bytearray()
    blobs = bytearray()
    for size, blob in images:
        dimension = 0 if size >= 256 else size  # 0 means 256 in the ICO directory
        entries += struct.pack(
            "<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(blob), offset
        )
        offset += len(blob)
        blobs += blob
    return header + bytes(entries) + bytes(blobs)


def main(argv: list[str] | None = None) -> int:
    """Render the SVG and write the ICO."""
    parser = argparse.ArgumentParser(description="Build assets/secure-vault.ico from icon.svg.")
    parser.add_argument("--svg", default=str(REPO_ROOT / "assets" / "icon.svg"))
    parser.add_argument("--out", default=str(REPO_ROOT / "assets" / "secure-vault.ico"))
    args = parser.parse_args(argv)

    QApplication.instance() or QApplication([])
    svg = Path(args.svg)
    out = Path(args.out)
    images = render(svg)
    out.write_bytes(pack_ico(images))
    print(f"wrote {out} ({len(images)} sizes: {', '.join(str(s) for s, _ in images)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
