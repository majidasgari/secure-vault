"""Add the emoji-label keys to both catalogues and assert the key sets stay identical.

Run with the vault venv python. Idempotent: re-running rewrites the same values.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
I18N = ROOT / "i18n"

NEW: dict[str, dict[str, str]] = {
    "fa": {
        "menu.emoji": "اموجی…",
        "dialog.emoji": "اموجی این مورد",
        "emoji.hint": "یک اموجی برای «{name}» انتخاب کن؛ کنار نامش در همهٔ فهرست‌ها نشان داده می‌شود.",
        "emoji.custom": "یا اموجی دلخواه را بچسبان",
        "emoji.clear": "بدون اموجی",
        "emoji.saved": "اموجی ذخیره شد.",
        "emoji.too_long": "اموجی حداکثر {max} نویسه می‌تواند باشد.",
        "emoji.group.general": "عمومی",
        "emoji.group.work": "کار",
        "emoji.group.writing": "نوشتار",
        "emoji.group.money": "مالی",
        "emoji.group.security": "رمز و امنیت",
        "emoji.group.network": "شبکه و سرور",
        "emoji.group.people": "افراد و آموزش",
        "emoji.group.places": "جاها",
        "emoji.group.ideas": "ایده و پژوهش",
        "emoji.group.marks": "نشانه‌ها",
    },
    "en": {
        "menu.emoji": "Emoji…",
        "dialog.emoji": "Emoji for this item",
        "emoji.hint": "Pick an emoji for “{name}” — it is shown beside its name in every listing.",
        "emoji.custom": "or paste your own emoji",
        "emoji.clear": "No emoji",
        "emoji.saved": "Emoji saved.",
        "emoji.too_long": "An emoji label can be at most {max} characters.",
        "emoji.group.general": "General",
        "emoji.group.work": "Work",
        "emoji.group.writing": "Writing",
        "emoji.group.money": "Money",
        "emoji.group.security": "Secrets & security",
        "emoji.group.network": "Network & servers",
        "emoji.group.people": "People & teaching",
        "emoji.group.places": "Places",
        "emoji.group.ideas": "Ideas & research",
        "emoji.group.marks": "Marks",
    },
}


def main() -> int:
    """Merge the keys into each catalogue, then compare the key sets."""
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
