#!/usr/bin/env python3
"""End-to-end: an MCP call must notify the tray (offscreen app, real socket, real bridge)."""
from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

REPO = Path("/data/Codes/secure-vault")
sys.path.insert(0, str(REPO / "src"))

from PySide6.QtWidgets import QApplication  # noqa: E402

from vault.gui import run_self_test  # noqa: E402
from vault.ui import i18n, notifications  # noqa: E402


def pump(app: QApplication, seconds: float) -> None:
    """Let the Qt event loop deliver queued signals for ``seconds``."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)


class Bridge:
    """A live MCP stdio bridge pointed at the given socket/token."""

    def __init__(self, socket_path: Path, token: str) -> None:
        """Spawn the bridge with the repo's src on the path."""
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src")
        self.proc = subprocess.Popen(  # noqa: S603
            [str(REPO / ".venv/bin/python"), "-m", "vault.mcp",
             "--socket", str(socket_path), "--token", token],
            cwd=str(REPO), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env,
        )
        self.counter = 0

    def request(self, method: str, params: dict | None = None, timeout: float = 20.0) -> dict:
        """Send one request and read its reply (never blocks past ``timeout``)."""
        self.counter += 1
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params or {}}
        ) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([self.proc.stdout], [], [], 0.3)
            if not ready:
                if self.proc.poll() is not None:
                    err = (self.proc.stderr.read() if self.proc.stderr else "")[:300]
                    return {"error": f"bridge exited: {err}"}
                continue
            line = self.proc.stdout.readline()
            if not line:
                break
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            if payload.get("id") == self.counter:
                return payload
        return {"error": "timeout"}

    def notify(self, method: str) -> None:
        """Send a notification frame."""
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": {}}) + "\n")
        self.proc.stdin.flush()

    def close(self) -> None:
        """Terminate the bridge."""
        self.proc.terminate()


def main() -> None:
    """Run the whole check and print a verdict."""
    result = run_self_test(language="fa", no_tray=True)
    app = QApplication.instance()
    assert app is not None
    controller = result.controller
    if controller.server is None:
        print("FAIL: the app could not start its daemon socket")
        return
    print("daemon socket:", controller.server.socket_path)

    # the self-test leaves the vault locked; unlock so the MCP reads really succeed
    from vault.gui import SELFTEST_PASSWORD

    unlocked = controller.unlock(SELFTEST_PASSWORD)
    pump(app, 0.5)
    print("unlocked     :", unlocked, "| locked now:", controller.session.is_locked)
    notifications.clear()
    controller.activity._items.clear()  # noqa: SLF001 - fresh feed for the assertion
    bridge = Bridge(controller.server.socket_path, controller.server.mcp_token)
    try:
        init = bridge.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                             "clientInfo": {"name": "e2e", "version": "1"}})
        print("initialize   :", (init.get("result") or {}).get("serverInfo", init.get("error")))
        bridge.notify("notifications/initialized")

        listing = bridge.request("tools/call", {"name": "list_folder", "arguments": {"path": "/notes"}})
        text = ((listing.get("result") or {}).get("content") or [{}])[0].get("text", str(listing.get("error")))
        print("list_folder  :", text[:110].replace("\n", " "))
        pump(app, 1.2)
        after_list = len(notifications.recent())

        read = bridge.request("tools/call", {"name": "read_file", "arguments": {"path": "notes/hello.md"}})
        print("read_file    :", json.dumps(read.get("result", read), ensure_ascii=False)[:110])
        pump(app, 1.2)

        recent = notifications.recent()
        print(f"\nnotifications: {len(recent)} (after list_folder: {after_list})")
        for entry in recent:
            print("   ", entry["title"], "::", entry["body"], "| shown:", entry["shown"])

        events = controller.activity.events()
        mcp_events = [e for e in events if e.get("source") == "mcp"]
        print("tray feed    :", len(events), "events |", len(mcp_events), "from mcp")
        for event in mcp_events[:4]:
            print("   ", event.get("kind"), event.get("tool"), event.get("path"))

        before = len(notifications.recent())
        bridge.request("tools/call", {"name": "read_file", "arguments": {"path": "notes/hello.md"}})
        pump(app, 0.6)
        after = len(notifications.recent())
        print(f"throttle     : {before} -> {after}")

        expected_title = i18n.tr("notification.agent_title", source="mcp")
        verdict = (
            bool(mcp_events)
            and any(entry["title"] == expected_title for entry in recent)
            and after == before
        )
        print("\nexpected title:", expected_title)
        print("VERDICT:", "PASS — MCP access notifies the tray" if verdict else "FAIL — see above")
    finally:
        bridge.close()
        controller.shutdown()


if __name__ == "__main__":
    main()
