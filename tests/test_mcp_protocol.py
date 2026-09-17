"""Tests for vault.api.mcp_server via a real ``python -m vault.mcp`` (SPEC/06 §2)."""

from __future__ import annotations

import json
import unittest

from support import fake_daemon, mcp_stdio, tmp_vault

EXPECTED_TOOLS = {
    "vault_status",
    "list_folder",
    "read_file",
    "read_lines",
    "write_file",
    "write_lines",
    "mkdir",
    "file_ops",
    "set_sensitivity",
    "search_filenames",
    "search_text",
    "search_semantic",
    "read_folder_note",
    "write_folder_note",
    "request_open_secret",
    "get_access_log",
}

NORMAL_MARKER = "hello normal body"
SECRET_MARKER = "secret body marker"
SECRETFILE_MARKER = "secretfile body marker"


class MCPProtocolTest(unittest.TestCase):
    """Drives the real MCP stdio bridge against an in-process fake daemon."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.session.write_file("notes/hello.md", NORMAL_MARKER.encode())
        self.session.write_file("notes/secret.md", SECRET_MARKER.encode())
        self.session.set_sensitivity("notes/secret.md", "secret")
        self.session.write_file("notes/vault.md", SECRETFILE_MARKER.encode())
        self.session.set_sensitivity("notes/vault.md", "secretfile")
        self.daemon = fake_daemon(self.session)
        env = {
            "SECURE_VAULT_SOCKET": str(self.daemon.socket_path),
            "SECURE_VAULT_TOKEN": self.daemon.token,
        }
        self.proc = mcp_stdio(env).__enter__()
        self._initialize()

    def tearDown(self) -> None:
        self.proc.__exit__(None, None, None)
        self.daemon.stop()
        self.session.close()

    # ------------------------------------------------------------------- helpers
    def _initialize(self) -> dict:
        response = self.proc.request(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        )
        return response["result"]

    def _result(self, response: dict) -> dict:
        self.assertIn("result", response, response)
        return response["result"]

    def _tool(self, name: str, arguments: dict | None = None, *, id: int = 1) -> dict:
        return self.proc.tool(name, arguments, id=id)

    def _structured(self, name: str, arguments: dict | None = None) -> dict:
        response = self._tool(name, arguments)
        result = self._result(response)
        self.assertFalse(result["isError"], result)
        return result["structuredContent"]

    # --------------------------------------------------------------------- tests
    def test_initialize_handshake(self) -> None:
        """initialize echoes a supported version and advertises the capabilities."""
        result = self._initialize()
        self.assertEqual(result["protocolVersion"], "2025-03-26")
        self.assertEqual(
            set(result["capabilities"]), {"tools", "resources", "prompts"}
        )
        self.assertEqual(result["serverInfo"]["name"], "secure-vault")
        self.assertIn("request_open_secret", result["instructions"])

    def test_initialize_unknown_version_defaults(self) -> None:
        """An unknown protocol version falls back to the default."""
        result = self.proc.request(
            "initialize", {"protocolVersion": "1999-01-01"}
        )["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")

    def test_initialized_notification_has_no_response(self) -> None:
        """notifications/initialized is silent; the next response is the ping."""
        self.proc.notify("notifications/initialized", {})
        response = self.proc.request("ping", id=99)
        self.assertEqual(response["id"], 99)
        self.assertEqual(response["result"], {})

    def test_ping(self) -> None:
        """ping returns an empty result object."""
        self.assertEqual(self.proc.request("ping", id=7)["result"], {})

    def test_tools_list_exact(self) -> None:
        """tools/list returns exactly the tools from SPEC/02 §4.1 with schemas."""
        tools = self.proc.request("tools/list", id=1)["result"]["tools"]
        self.assertEqual({tool["name"] for tool in tools}, EXPECTED_TOOLS)
        self.assertEqual(len(tools), len(EXPECTED_TOOLS))
        by_name = {tool["name"]: tool for tool in tools}
        self.assertEqual(by_name["read_file"]["inputSchema"]["required"], ["path"])
        self.assertEqual(
            by_name["write_file"]["inputSchema"]["required"], ["path", "content"]
        )
        self.assertIn(
            "secret",
            by_name["set_sensitivity"]["inputSchema"]["properties"]["level"]["enum"],
        )

    def test_tools_call_success_shapes(self) -> None:
        """The documented tools return the documented payload shapes."""
        status = self._structured("vault_status")
        self.assertEqual(status["daemon"], {"running": True})
        for key in ("locked", "home", "files", "folders", "by_level"):
            self.assertIn(key, status)

        listing = self._structured("list_folder", {"path": "/"})
        self.assertIn("entries", listing)

        read = self._structured("read_file", {"path": "/notes/hello.md"})
        self.assertEqual(read["content"], NORMAL_MARKER)

        written = self._structured(
            "write_file", {"path": "/notes/written.md", "content": "written body"}
        )
        self.assertTrue(written["created"])
        read_back = self._structured("read_file", {"path": "/notes/written.md"})
        self.assertEqual(read_back["content"], "written body")

        found = self._structured("search_filenames", {"query": "hello"})
        self.assertIn("results", found)

        note = self._structured("write_folder_note", {"path": "/notes", "text": "hi"})
        self.assertTrue(note["updated"])
        note_read = self._structured("read_folder_note", {"path": "/notes"})
        self.assertEqual(note_read["note"], "hi")

        log = self._structured("get_access_log", {"limit": 10})
        self.assertIn("entries", log)

    def test_tool_result_content_is_json_text(self) -> None:
        """Successful results carry pretty JSON text and structuredContent."""
        response = self._tool("read_file", {"path": "/notes/hello.md"})
        result = self._result(response)
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["type"], "text")
        self.assertEqual(json.loads(result["content"][0]["text"]), result["structuredContent"])

    def test_read_secret_denied_iserror(self) -> None:
        """read_file on a secret file is an isError tool result, not a JSON-RPC error."""
        response = self._tool("read_file", {"path": "/notes/secret.md"})
        self.assertNotIn("error", response)
        result = self._result(response)
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["code"], "PERMISSION_DENIED")
        self.assertNotIn(SECRET_MARKER, json.dumps(result))

    def test_downgrade_forbidden(self) -> None:
        """Lowering a sensitivity over MCP returns SENSITIVITY_DOWNGRADE_FORBIDDEN."""
        self._structured(
            "set_sensitivity", {"path": "/notes/hello.md", "level": "secret"}
        )
        response = self._tool(
            "set_sensitivity", {"path": "/notes/hello.md", "level": "normal"}
        )
        result = self._result(response)
        self.assertTrue(result["isError"])
        self.assertEqual(
            result["structuredContent"]["code"], "SENSITIVITY_DOWNGRADE_FORBIDDEN"
        )

    def test_request_open_secret_never_leaks_content(self) -> None:
        """request_open_secret returns pending and no response contains the content."""
        response = self._tool("request_open_secret", {"path": "/notes/vault.md"})
        result = self._result(response)
        payload = result["structuredContent"]
        self.assertEqual(payload["status"], "pending")
        self.assertNotIn(SECRETFILE_MARKER, json.dumps(result))
        self.assertNotIn(SECRETFILE_MARKER, json.dumps(self._structured("get_access_log")))

    def test_unknown_tool_invalid_params(self) -> None:
        """An unknown tool is a JSON-RPC -32602 invalid-params error."""
        response = self._tool("does_not_exist", {})
        self.assertEqual(response["error"]["code"], -32602)

    def test_missing_required_param(self) -> None:
        """A missing required argument is -32602."""
        response = self._tool("read_file", {})
        self.assertEqual(response["error"]["code"], -32602)

    def test_unknown_method(self) -> None:
        """An unknown JSON-RPC method is -32601."""
        response = self.proc.request("no/such/method", id=3)
        self.assertEqual(response["error"]["code"], -32601)

    def test_invalid_json_line(self) -> None:
        """An unparseable line is a -32700 parse error."""
        self.proc.send_raw(b"{this is not json\n")
        response = self.proc.read_response()
        self.assertEqual(response["error"]["code"], -32700)

    def test_resources_templates(self) -> None:
        """resources/templates/list returns the four documented templates."""
        templates = self.proc.request("resources/templates/list", id=1)["result"][
            "resourceTemplates"
        ]
        self.assertEqual(
            {t["uriTemplate"] for t in templates},
            {
                "vault://folder/{path}",
                "vault://note/{path}",
                "vault://search?q={query}",
                "vault://log?limit={n}",
            },
        )

    def test_resources_list(self) -> None:
        """resources/list exposes the concrete status/root/recent entries."""
        resources = self.proc.request("resources/list", id=1)["result"]["resources"]
        self.assertIn("vault://status", {r["uri"] for r in resources})
        self.assertIn("vault://root", {r["uri"] for r in resources})
        self.assertIn("vault://recent", {r["uri"] for r in resources})

    def test_resources_read(self) -> None:
        """resources/read works for status and normal notes, denies secret notes."""
        status = self.proc.request("resources/read", {"uri": "vault://status"}, id=1)
        contents = status["result"]["contents"]
        self.assertEqual(contents[0]["mimeType"], "application/json")
        self.assertEqual(json.loads(contents[0]["text"])["daemon"]["running"], True)

        note = self.proc.request(
            "resources/read", {"uri": "vault://note/notes/hello.md"}, id=2
        )
        self.assertEqual(note["result"]["contents"][0]["mimeType"], "text/markdown")
        self.assertEqual(note["result"]["contents"][0]["text"], NORMAL_MARKER)

        denied = self.proc.request(
            "resources/read", {"uri": "vault://note/notes/secret.md"}, id=3
        )
        self.assertEqual(denied["error"]["code"], -32000)
        self.assertEqual(denied["error"]["data"]["code"], "PERMISSION_DENIED")

    def test_resources_subscribe_not_supported(self) -> None:
        """resources/subscribe is not supported (-32601)."""
        response = self.proc.request("resources/subscribe", {"uri": "vault://status"}, id=1)
        self.assertEqual(response["error"]["code"], -32601)

    def test_stdout_carries_only_json(self) -> None:
        """Every stdout line parses as JSON even with --debug diagnostics."""
        env = {
            "SECURE_VAULT_SOCKET": str(self.daemon.socket_path),
            "SECURE_VAULT_TOKEN": self.daemon.token,
        }
        with mcp_stdio(env, args=["--debug"]) as proc:
            proc.send(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                }
            )
            proc.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            proc.send(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": {"path": "/notes/hello.md"},
                    },
                }
            )
            for _ in range(3):
                line = proc.read_line()
                parsed = json.loads(line.decode("utf-8"))
                self.assertEqual(parsed["jsonrpc"], "2.0")

    def test_daemon_down_returns_not_running(self) -> None:
        """When the daemon is gone the bridge reports VAULT_NOT_RUNNING."""
        self.daemon.stop()
        response = self._tool("list_folder", {"path": "/"})
        self.assertEqual(response["error"]["code"], -32000)
        self.assertEqual(response["error"]["data"]["code"], "VAULT_NOT_RUNNING")


if __name__ == "__main__":
    unittest.main()
