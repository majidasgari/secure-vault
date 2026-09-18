"""The MCP bridge must survive an app restart (token rotation) — regression test.

``runtime_dir()/tokens.json`` carries a fresh ``mcp`` token every time the app starts, so a
bridge spawned by a long-lived agent runtime holds a dead token after the user restarts the
app. :class:`~vault.api.client.RefreshingClient` re-reads the file and retries once; before
it existed the bridge answered ``UNAUTHORIZED: invalid_token`` until the agent itself
restarted (observed with a Hermes session holding a bridge from a previous app run).
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from support import fake_daemon, mcp_stdio, tmp_vault

CURRENT = "token-current-000000000000000000"
STALE = "token-from-the-previous-app-run-0000"


def _write_token(runtime: Path, token: str) -> None:
    """Publish ``token`` as the daemon's ``mcp`` role token (as the app does on start)."""
    runtime.mkdir(parents=True, exist_ok=True)
    (runtime / "tokens.json").write_text(
        json.dumps({"mcp": token, "created_at": 0}), encoding="utf-8"
    )


class MCPTokenRefreshTest(unittest.TestCase):
    """Drives the real stdio bridge with the no-explicit-credentials code path."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.session.write_file("notes/hello.md", b"hello body")
        self.base = Path(tempfile.mkdtemp(prefix="sv-token-refresh-"))
        self.runtime = self.base / "secure-vault"
        self.daemon = fake_daemon(self.session, runtime=self.runtime, token=CURRENT)
        self.proc = None

    def tearDown(self) -> None:
        if self.proc is not None:
            self.proc.__exit__(None, None, None)
        self.daemon.stop()
        self.session.close()
        shutil.rmtree(self.base, ignore_errors=True)

    def _start_bridge(self, env: dict[str, str]) -> None:
        """Spawn the bridge and complete the MCP handshake."""
        self.proc = mcp_stdio(env).__enter__()
        self.proc.request(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "token-refresh-test", "version": "1"},
            },
        )

    def _error_code(self, response: dict) -> str | None:
        """Return the structured error code of an ``isError`` tool result, if any."""
        result = response.get("result") or {}
        if not result.get("isError"):
            return None
        structured = result.get("structuredContent") or {}
        return structured.get("code")

    def test_runtime_token_is_reread_after_app_restart(self) -> None:
        """A bridge started before the restart works again on the next call."""
        _write_token(self.runtime, STALE)  # what the previous app run had published
        self._start_bridge({"XDG_RUNTIME_DIR": str(self.base)})

        # Nothing changed on disk yet: the stale token is retried once and then reported.
        first = self.proc.tool("list_folder", {"path": "/"}, id=1)
        self.assertEqual(self._error_code(first), "UNAUTHORIZED", first)

        # The app restarts and publishes a new token.
        _write_token(self.runtime, CURRENT)
        second = self.proc.tool("list_folder", {"path": "/"}, id=2)
        self.assertNotIn("error", second, second)
        self.assertFalse(second["result"].get("isError"), second)
        payload = json.loads(second["result"]["content"][0]["text"])
        self.assertEqual(payload["path"], "/")
        self.assertEqual(payload["note"], None)

        # Content tools work too, not just metadata.
        read = self.proc.tool("read_file", {"path": "/notes/hello.md"}, id=3)
        self.assertFalse(read["result"].get("isError"), read)
        self.assertEqual(json.loads(read["result"]["content"][0]["text"])["content"], "hello body")

    def test_explicit_credentials_are_never_refreshed(self) -> None:
        """A client pinned with ``--token``/env keeps its token (no silent swap)."""
        _write_token(self.runtime, CURRENT)
        self._start_bridge(
            {
                "XDG_RUNTIME_DIR": str(self.base),
                "SECURE_VAULT_SOCKET": str(self.daemon.socket_path),
                "SECURE_VAULT_TOKEN": STALE,
            }
        )
        _write_token(self.runtime, CURRENT)
        response = self.proc.tool("list_folder", {"path": "/"}, id=1)
        self.assertEqual(self._error_code(response), "UNAUTHORIZED", response)


if __name__ == "__main__":
    unittest.main()
