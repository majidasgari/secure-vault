#!/usr/bin/env python3
"""Acceptance smoke test for the agent-facing MCP contract (SPEC/06 §3).

Starts the real headless daemon (``python -m vault.daemon``) on a scratch vault, then
drives the real MCP stdio bridge (``python -m vault.mcp``) through the documented
handshake and tool/resource calls, and finally proves the daemon-down behaviour.
Prints ``PASS``/``FAIL`` per step and exits non-zero on any failure.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
PYTHON = sys.executable
PASSWORD = "smoke-mcp-password"

PASS = "PASS"
FAIL = "FAIL"
_failures = 0


def step(name: str, fn) -> None:
    """Run one named step, print its result and remember failures."""
    global _failures
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - smoke reporting
        _failures += 1
        print(f"{FAIL}  {name}: {type(exc).__name__}: {exc}")
    else:
        print(f"{PASS}  {name}")


class MCP:
    """Minimal MCP stdio client for the smoke test."""

    def __init__(self, env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            [PYTHON, "-m", "vault.mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(REPO_ROOT),
        )
        self._buffer = b""
        self._counter = 0

    def send(self, message: dict) -> None:
        """Write one JSON message line."""
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        self.proc.stdin.flush()

    def read_line(self, timeout: float = 10.0) -> bytes:
        """Read one stdout line."""
        deadline = time.time() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for the MCP bridge")
            assert self.proc.stdout is not None
            ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if not ready:
                raise TimeoutError("timed out waiting for the MCP bridge")
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if not chunk:
                raise EOFError("the MCP bridge exited")
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return line

    def request(self, method: str, params: dict | None = None) -> dict:
        """Send a request and return the decoded response."""
        self._counter += 1
        self.send(
            {
                "jsonrpc": "2.0",
                "id": self._counter,
                "method": method,
                "params": params or {},
            }
        )
        return json.loads(self.read_line().decode("utf-8"))

    def tool(self, name: str, arguments: dict | None = None) -> dict:
        """Call one MCP tool."""
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self) -> None:
        """Terminate the bridge."""
        try:
            if self.proc.stdin is not None:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5.0)


def read_daemon_ready(proc: subprocess.Popen, timeout: float = 15.0) -> dict:
    """Wait for the daemon's ``{"event":"ready"}`` JSON line."""
    assert proc.stdout is not None
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], deadline - time.time())
        if not ready:
            break
        line = proc.stdout.readline()
        if not line:
            break
        text = line.decode("utf-8", "replace").strip()
        if not text:
            continue
        try:
            event = json.loads(text)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("event") == "ready":
            return event
    raise TimeoutError("the daemon never reported ready")


def main() -> int:
    """Run every smoke step and return the exit code."""
    scratch = Path(tempfile.mkdtemp(prefix="sv-smoke-mcp-"))
    home = scratch / "vault"
    runtime = scratch
    unlock_file = scratch / "unlock.pw"
    unlock_file.write_text(PASSWORD, encoding="utf-8")
    os.chmod(unlock_file, 0o600)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    env["XDG_RUNTIME_DIR"] = str(runtime)

    daemon = subprocess.Popen(
        [
            PYTHON,
            "-m",
            "vault.daemon",
            "--home",
            str(home),
            "--unlock-file",
            str(unlock_file),
            "--json-events",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(REPO_ROOT),
    )
    bridge: MCP | None = None
    try:
        ready = read_daemon_ready(daemon)
        print(f"daemon ready: {ready}")

        bridge = MCP(env)
        state: dict[str, Any] = {}

        def handshake() -> None:
            response = bridge.request(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "smoke", "version": "1"},
                },
            )
            result = response["result"]
            assert result["protocolVersion"] == "2025-03-26", result
            assert set(result["capabilities"]) == {"tools", "resources", "prompts"}
            assert result["serverInfo"]["name"] == "secure-vault"

        step("initialize handshake", handshake)

        def tools_list() -> None:
            tools = bridge.request("tools/list")["result"]["tools"]
            names = {tool["name"] for tool in tools}
            assert "list_folder" in names and "read_file" in names, names
            state["tools"] = names

        step("tools/list", tools_list)

        def list_folder() -> None:
            result = bridge.tool("list_folder", {"path": "/"})["result"]
            assert result["isError"] is False, result
            assert isinstance(result["structuredContent"]["entries"], list)

        step("tools/call list_folder", list_folder)

        def write_read() -> None:
            written = bridge.tool(
                "write_file", {"path": "/notes/hello.md", "content": "hello from smoke"}
            )["result"]
            assert written["isError"] is False, written
            read = bridge.tool("read_file", {"path": "/notes/hello.md"})["result"]
            assert read["structuredContent"]["content"] == "hello from smoke", read

        step("tools/call write_file + read-back", write_read)

        def make_secret() -> None:
            raised = bridge.tool(
                "set_sensitivity", {"path": "/notes/hello.md", "level": "secret"}
            )["result"]
            assert raised["isError"] is False, raised
            assert raised["structuredContent"]["to"] == "secret", raised

        step("tools/call set_sensitivity secret", make_secret)

        def denied_read() -> None:
            denied = bridge.tool("read_file", {"path": "/notes/hello.md"})["result"]
            assert denied["isError"] is True, denied
            assert denied["structuredContent"]["code"] == "PERMISSION_DENIED", denied

        step("denied read_file of a secret file", denied_read)

        def search_filenames() -> None:
            found = bridge.tool("search_filenames", {"query": "hello"})["result"]
            assert found["isError"] is False, found
            assert found["structuredContent"]["results"], found

        step("tools/call search_filenames", search_filenames)

        def resource_status() -> None:
            resource = bridge.request(
                "resources/read", {"uri": "vault://status"}
            )["result"]["contents"][0]
            assert resource["mimeType"] == "application/json", resource
            payload = json.loads(resource["text"])
            assert payload["daemon"]["running"] is True, payload

        step("resources/read vault://status", resource_status)

        def request_open_secret() -> None:
            raised = bridge.tool(
                "set_sensitivity", {"path": "/notes/hello.md", "level": "secretfile"}
            )["result"]
            assert raised["isError"] is False, raised
            requested = bridge.tool(
                "request_open_secret", {"path": "/notes/hello.md"}
            )["result"]
            payload = requested["structuredContent"]
            assert payload["status"] == "pending", payload
            assert "hello from smoke" not in json.dumps(requested), requested

        step("tools/call request_open_secret", request_open_secret)

        def daemon_down() -> None:
            daemon.send_signal(signal.SIGTERM)
            daemon.wait(timeout=10.0)
            response = bridge.tool("list_folder", {"path": "/"})
            assert response.get("error", {}).get("code") == -32000, response
            assert response["error"]["data"]["code"] == "VAULT_NOT_RUNNING", response

        step("daemon down -> VAULT_NOT_RUNNING", daemon_down)
    finally:
        if bridge is not None:
            bridge.close()
        if daemon.poll() is None:
            daemon.send_signal(signal.SIGTERM)
            try:
                daemon.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                daemon.kill()
        shutil.rmtree(scratch, ignore_errors=True)

    if _failures:
        print(f"\n{FAIL}: {_failures} step(s) failed")
        return 1
    print("\nPASS: all smoke_mcp steps succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
