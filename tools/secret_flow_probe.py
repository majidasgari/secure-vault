#!/usr/bin/env python3
"""Prove the web↔desktop secret flow end to end, in a real browser against the real app.

    ./.venv/bin/python tools/secret_flow_probe.py [screenshot.png]

Builds a throwaway vault and starts the **real application** in offscreen mode, whose in-process
web server serves the real SPA. ``tools/secret_flow_probe.js`` then drives that server in
headless Chrome: clicking a secret row has to ask the desktop app, and the text it approves has
to appear *in the browser* — never in the native viewer. A watcher presses the dialog's own
button, exactly the way the user does.

Also checks the row actions in the same page (rename + delete, both through their real dialogs)
and, back in Python, that the access log tells the same story.

Needs the system ``python3`` with ``websockets`` plus ``google-chrome-stable`` (the same
requirement as ``tools/ui_probe.py``).
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DRIVER = Path(__file__).with_name("ui_probe_driver.py")
TEST_JS = Path(__file__).with_name("secret_flow_probe.js")

#: Kept in the scratch dir: the probe must not fight the user's live vault for the token file,
#: the ui.json arrangement, or the web port.
_SCRATCH = Path(tempfile.mkdtemp(prefix="sv-secret-flow-"))
os.environ["XDG_RUNTIME_DIR"] = str(_SCRATCH / "run")
os.environ["XDG_CONFIG_HOME"] = str(_SCRATCH / "config")
os.environ["QT_QPA_PLATFORM"] = "offscreen"

sys.path.insert(0, str(REPO / "src"))

from PySide6.QtCore import QObject, QTimer                      # noqa: E402
from PySide6.QtWidgets import QApplication                      # noqa: E402

from vault.core.session import VaultSession                     # noqa: E402
from vault.ui import viewer as viewer_mod                       # noqa: E402
from vault.ui.app import VaultApplication                       # noqa: E402

PASSWORD = "secret-flow-probe"
SECRET_PATH = "/رمزها/نمونه/card.md"
SECRET_BODY = "# نمونه\n\nنام کاربری: demo\nگذرواژه: SECRET-BODY-MARKER\n"


def build_vault() -> Path:
    """Create a scratch vault holding one secretfile and one normal note."""
    home = _SCRATCH / "vault"
    session = VaultSession.create(home, PASSWORD)
    session.write_file(SECRET_PATH, SECRET_BODY.encode("utf-8"))
    session.set_sensitivity(SECRET_PATH, "secretfile")
    session.write_file("/notes/plain.md", b"# plain\n")
    session.close()
    return home


class ApprovalWatcher(QObject):
    """Press the permission dialog's own button, the way the user would."""

    def __init__(self, app: VaultApplication) -> None:
        """Remember the app and the dialogs already answered."""
        super().__init__()
        self.app = app
        self.answered: list[dict] = []
        self.unexpected: list[dict] = []
        self._seen: set[int] = set()

    def tick(self) -> None:
        """Answer every new web-origin request as approved (and note anything else)."""
        for dialog in list(self.app._secret_dialogs):
            if id(dialog) in self._seen:
                continue
            self._seen.add(id(dialog))
            request = dict(getattr(dialog, "request", {}) or {})
            if not getattr(dialog, "from_web", False):
                self.unexpected.append(request)
                continue
            self.answered.append(request)
            dialog.show_button.click()          # the real `_resolve_request` path


def main() -> int:
    """Run the probe and print the verdicts from both sides."""
    home = build_vault()
    qapp = QApplication.instance() or QApplication(["sv-secret-flow"])
    app = VaultApplication(qapp, home=home, language="fa", no_tray=True, self_test=True)
    session = VaultSession(home)                 # starts locked; the SPA unlocks it
    app.attach_session(session)
    if app.web is None:
        print("FAIL | the in-process web server did not start")
        return 1
    url = f"http://127.0.0.1:{app.web.port}/"
    print(f"server: {url}")

    watcher = ApprovalWatcher(app)
    timer = QTimer()
    timer.timeout.connect(watcher.tick)
    timer.start(150)

    shot = sys.argv[1] if len(sys.argv) > 1 else str(_SCRATCH / "secret-flow.png")
    captured: dict[str, object] = {}

    def run_driver() -> None:
        """Drive the real SPA in headless Chrome (its own process needs the system python3)."""
        captured["proc"] = subprocess.run(  # noqa: S603
            ["python3", str(DRIVER), url, PASSWORD, shot, str(TEST_JS)],
            capture_output=True, text=True, timeout=300, check=False,
        )

    thread = threading.Thread(target=run_driver, daemon=True)
    thread.start()
    deadline = time.time() + 320
    while thread.is_alive() and time.time() < deadline:
        qapp.processEvents()
        time.sleep(0.05)
    timer.stop()
    qapp.processEvents()

    proc = captured.get("proc")
    print((getattr(proc, "stdout", "") or "").strip())
    if getattr(proc, "stderr", ""):
        print("driver stderr:", getattr(proc, "stderr", "").strip()[:800])
    if thread.is_alive():
        print("FAIL | the browser driver did not finish in time")
    if shot:
        print(f"screenshot: {shot}")

    # ------------------------------------------------------------------ Python side
    def verdict(ok: bool, name: str, extra: str = "") -> None:
        print(f"{'PASS' if ok else 'FAIL'} | {name}" + (f" | {extra}" if extra else ""))

    verdict(len(watcher.answered) >= 1, "the web click raised a request in the desktop app",
            f"{len(watcher.answered)} dialog(s)")
    verdict(not watcher.unexpected, "every request came from the web UI")
    first = watcher.answered[0] if watcher.answered else {}
    verdict(str(first.get("path", "")).lstrip("/") == SECRET_PATH.lstrip("/"),
            "the request named the file that was clicked", str(first.get("path")))
    verdict(first.get("origin") == "web", "the request is marked as a browser request")
    verdict(viewer_mod.last_path != SECRET_PATH,
            "the native viewer never opened for a web click",
            f"viewer last path = {viewer_mod.last_path!r}")

    rows = session.access_log(limit=400)
    pairs = {(row["tool"], row["outcome"]) for row in rows}
    for method in ("vault.request_open_secret", "vault.resolve_open_secret",
                   "vault.read_secret", "vault.file_ops"):
        verdict((method, "allow") in pairs, f"the access log records {method}")
    verdict(not any(tool.endswith("secret_status") for tool, _outcome in pairs),
            "the status poll wrote no access-log row of its own")
    verdict(not any(tool == "ui.read_secretfile" for tool, _outcome in pairs),
            "no ui.read_secretfile row (nothing was shown natively)")

    listing = session.list_folder("/رمزها/نمونه")
    verdict(len(listing.get("entries", [])) == 0,
            "the rename + delete left the folder empty",
            str([e.get("name") for e in listing.get("entries", [])]))

    session.close()
    app.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
