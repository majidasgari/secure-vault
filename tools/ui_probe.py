#!/usr/bin/env python3
"""Drive the real web UI in headless Chrome: breadcrumbs, dialogs, search, tags, mobile.

    ./.venv/bin/python tools/ui_probe.py [screenshot.png] [extra-test.js]
    PROBE_W=390 PROBE_H=844 ./.venv/bin/python tools/ui_probe.py /tmp/phone.png

Builds a throwaway vault in /tmp, starts the web server on a free port, and runs
``tools/ui_probe_driver.py`` (which needs the *system* python3 with ``websockets`` plus
``google-chrome-stable``) over the Chrome DevTools protocol. Not part of the unit suite: Max
tests the UI by hand, this is for agent verification and regression checks.
"""
from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vault.api.service import Service  # noqa: E402
from vault.core.session import VaultSession  # noqa: E402
from vault.web.server import WebServer  # noqa: E402

PASSWORD = "ui-probe-pass-123"
DRIVER = Path(__file__).with_name("ui_probe_driver.py")


_EDITOR_NOTE = (
    "# ادیتور بصری\n"
    "\n"
    "متن فارسی برای بررسی راست‌چین بودن، با **پررنگ** و `کد` درون‌خطی.\n"
    "\n"
    "An English paragraph that has to stay left to right.\n"
    "\n"
    "## فهرست\n"
    "\n"
    "- مورد نخست\n"
    "- مورد دوم\n"
    "\n"
    "### english list\n"
    "\n"
    "- english first item\n"
    "- english second item\n"
    "\n"
    "### کارها\n"
    "\n"
    "- [x] کار انجام‌شده\n"
    "- [ ] کار باقی‌مانده\n"
    "\n"
    "> نقل قول فارسی برای آزمایش بلوک نقل قول.\n"
    "\n"
    "| ستون اول | ستون دوم |\n"
    "| --- | --- |\n"
    "| خانه یک | خانه دو |\n"
    "\n"
    "| first | second |\n"
    "| --- | --- |\n"
    "| alpha | beta |\n"
    "\n"
    "```js\n"
    "const x = 1;\n"
    "console.log(x);\n"
    "```\n"
    "\n"
    "![نقطه](vault:/attachments/dot.png)\n"
)

#: 1×1 transparent PNG — enough to prove a `vault:` image becomes an object URL in the editor.
_DOT_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg=="
)


#: Mirrors the shape of Max's real notes (a Persian note with English table cells, numbering and a
#: lone English paragraph) — the display probe measures this note's rendering (see ui_probe_display.js).
_DISPLAY_NOTE = (
    "# مقایسه نهایی\n"
    "\n"
    "متن فارسی با English در میان آن.\n"
    "\n"
    "Quality over quantity: 3 نتیجه یا یکی ضعیف\n"
    "\n"
    "plain english line only\n"
    "\n"
    "| گزینه | مدل‌ها | مزایا |\n"
    "| --- | --- | --- |\n"
    "| فعلی | RotatE + ComplEx | قوی‌ترین نتایج |\n"
    "| alternative | TransE + RotatE | پوشش بیشتر |\n"
    "\n"
    "1. با 132% بهبود یک الماس است\n"
    "2. English only numbered item\n"
    "3. دو معماری متفاوت کافی است\n"
    "\n"
    "- مورد فارسی\n"
    "- english bullet only\n"
    "\n"
    "> نقل قول فارسی برای آزمایش\n"
    "\n"
    "```js\n"
    "const x = 1;\n"
    "```\n"
)


def build_vault() -> VaultSession:
    """A small nested vault that mirrors the structure the UI has to handle."""
    home = Path(tempfile.mkdtemp()) / "vault"
    home.mkdir(parents=True)
    session = VaultSession.create(home, PASSWORD)
    for folder in ("/الف", "/الف/ب", "/الف/ب/ج", "/الف/ب/ج/د", "/شخصی", "/attachments"):
        session.mkdir(folder)
    session.write_file("/الف/ب/ج/یادداشت.md", "# یادداشت\n\nمتن نمونه با **پررنگ**.\n".encode())
    session.write_file("/الف/ب/ج/ادیتور.md", _EDITOR_NOTE.encode())
    session.write_file("/الف/ب/ج/نمایش.md", _DISPLAY_NOTE.encode())
    session.write_file("/attachments/dot.png", _DOT_PNG)
    session.write_file("/الف/ب/ج/د/عمیق.md", "deep\n".encode())
    session.set_tags("/الف/ب/ج/یادداشت.md", ["تست", "نمونه"])
    # enough tags that the sidebar preview has to defer to the tag browser
    for index in range(12):
        path = f"/شخصی/یادداشت {index}.md"
        session.write_file(path, f"# یادداشت {index}\n".encode())
        session.set_tags(path, [f"بتا{index}", "تست"])
    return session


def main() -> None:
    """Start the server and run the browser probe against it."""
    session = build_vault()
    server = WebServer(Service(session), host="127.0.0.1", port=0)
    server.start()
    url = f"http://127.0.0.1:{server.port}/"
    print(f"server: {url}")
    shot = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ui_probe.png"
    try:
        subprocess.run(  # noqa: S603
            ["python3", str(DRIVER), url, PASSWORD, shot] + sys.argv[2:],
            check=False, timeout=300,
        )
    finally:
        server.stop()
        session.close()


if __name__ == "__main__":
    main()
