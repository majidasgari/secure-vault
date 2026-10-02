"""Add the appearance + image-viewer keys to both catalogues.

Run with the vault venv python. Idempotent: re-running rewrites the same values.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
I18N = ROOT / "i18n"

NEW: dict[str, dict[str, str]] = {
    "fa": {
        "settings.theme": "ظاهر",
        "theme.system": "هماهنگ با سیستم",
        "theme.dark": "تیره",
        "theme.light": "روشن",
        "menu.view_image": "نمایش تصویر",
        "image.title": "تصویر",
        "image.fit": "جا شدن در پنجره",
        "image.actual": "اندازهٔ واقعی",
        "image.zoom_in": "بزرگ‌نمایی",
        "image.zoom_out": "کوچک‌نمایی",
        "image.unsupported": "این فایل یک تصویر قابل نمایش نیست.",
        "image.info_fit": "{width}×{height} پیکسل — جا شده در پنجره",
        "image.info_zoom": "{width}×{height} پیکسل — {percent}٪",
    },
    "en": {
        "settings.theme": "Appearance",
        "theme.system": "Match the system",
        "theme.dark": "Dark",
        "theme.light": "Light",
        "menu.view_image": "View image",
        "image.title": "Image",
        "image.fit": "Fit to window",
        "image.actual": "Actual size",
        "image.zoom_in": "Zoom in",
        "image.zoom_out": "Zoom out",
        "image.unsupported": "This file is not a picture that can be shown.",
        "image.info_fit": "{width}×{height} pixels — fitted to the window",
        "image.info_zoom": "{width}×{height} pixels — {percent}%",
    },
}


def main() -> int:
    """Add the keys and assert the two catalogues keep the same key set."""
    payloads: dict[str, dict[str, str]] = {}
    for lang, additions in NEW.items():
        path = I18N / f"{lang}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        before = len(data)
        data.update(additions)
        ordered = {key: data[key] for key in sorted(data)}
        path.write_text(
            json.dumps(ordered, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        payloads[lang] = ordered
        print(f"{lang}: {before} -> {len(ordered)} keys (+{len(ordered) - before})")

    fa, en = set(payloads["fa"]), set(payloads["en"])
    if fa != en:
        print("KEY MISMATCH:", sorted(fa ^ en))
        return 1
    print(f"key sets identical: {len(fa)} keys each")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
