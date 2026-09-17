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


def build_vault() -> VaultSession:
    """A small nested vault that mirrors the structure the UI has to handle."""
    home = Path(tempfile.mkdtemp()) / "vault"
    home.mkdir(parents=True)
    session = VaultSession.create(home, PASSWORD)
    for folder in ("/الف", "/الف/ب", "/الف/ب/ج", "/الف/ب/ج/د", "/شخصی"):
        session.mkdir(folder)
    session.write_file("/الف/ب/ج/یادداشت.md", "# یادداشت\n\nمتن نمونه با **پررنگ**.\n".encode())
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
