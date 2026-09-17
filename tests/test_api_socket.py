"""Tests for vault.api.socket_server and vault.api.client (SPEC/06 §2 test_api_socket)."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path

from support import fake_daemon, tmp_vault
from vault.api.client import VaultClient
from vault.errors import (
    BadRequest,
    NotFound,
    PermissionDenied,
    Unauthorized,
    VaultNotRunning,
)


class SocketServerTest(unittest.TestCase):
    """End-to-end behaviour of the Unix-socket JSON-RPC server."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.session.write_file("notes/a.md", b"body")
        self.daemon = fake_daemon(self.session)

    def tearDown(self) -> None:
        self.daemon.stop()
        self.session.close()

    # ------------------------------------------------------------------- helpers
    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(str(self.daemon.socket_path))
        return sock

    @staticmethod
    def _read_response(sock: socket.socket) -> dict:
        buffer = b""
        while b"\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
        line, _, _ = buffer.partition(b"\n")
        return json.loads(line.decode("utf-8"))

    def _send_line(self, sock: socket.socket, payload: bytes) -> dict:
        sock.sendall(payload + b"\n")
        return self._read_response(sock)

    # --------------------------------------------------------------------- tests
    def test_ping_without_token_unauthorized(self) -> None:
        """A request with no token is rejected with UNAUTHORIZED."""
        sock = self._connect()
        try:
            response = self._send_line(
                sock, json.dumps({"id": 1, "method": "vault.ping", "params": {}}).encode()
            )
        finally:
            sock.close()
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "UNAUTHORIZED")

    def test_wrong_token_denied_and_logged(self) -> None:
        """A wrong token is rejected and recorded as a socket deny row."""
        client = VaultClient(socket_path=self.daemon.socket_path, token="deadbeef")
        with self.assertRaises(Unauthorized):
            client.call("vault.ping")
        rows = self.session.access_log(limit=10, source="socket")
        match = [r for r in rows if r["tool"] == "vault.ping"]
        self.assertTrue(match)
        self.assertEqual(match[0]["outcome"], "deny")
        self.assertEqual(match[0]["code"], "UNAUTHORIZED")

    def test_mcp_token_permissions(self) -> None:
        """The mcp token can list but not unlock or read secrets."""
        client = self.daemon.client()
        listing = client.call("vault.list_folder", {"path": "/"})
        self.assertEqual(listing["path"], "/")
        with self.assertRaises(PermissionDenied):
            client.call("vault.unlock", {"password": "x"})
        with self.assertRaises(PermissionDenied):
            client.call("vault.read_secret", {"path": "/notes/a.md"})

    def test_malformed_json_line(self) -> None:
        """A malformed line yields BAD_REQUEST with id null and keeps the connection."""
        sock = self._connect()
        try:
            response = self._send_line(sock, b"{not json")
            self.assertIsNone(response["id"])
            self.assertEqual(response["error"]["code"], "BAD_REQUEST")
            ok = self._send_line(
                sock,
                json.dumps(
                    {
                        "id": 2,
                        "token": self.daemon.token,
                        "method": "vault.ping",
                        "params": {},
                    }
                ).encode(),
            )
            self.assertTrue(ok["ok"])
        finally:
            sock.close()

    def test_pipelined_requests_in_order(self) -> None:
        """Two pipelined requests get two responses in order."""
        token = self.daemon.token
        first = json.dumps({"id": "a", "token": token, "method": "vault.ping", "params": {}})
        second = json.dumps(
            {"id": "b", "token": token, "method": "vault.list_folder", "params": {"path": "/"}}
        )
        sock = self._connect()
        try:
            sock.sendall((first + "\n" + second + "\n").encode())
            r1 = self._read_response(sock)
            r2 = self._read_response(sock)
        finally:
            sock.close()
        self.assertEqual(r1["id"], "a")
        self.assertTrue(r1["ok"])
        self.assertEqual(r2["id"], "b")
        self.assertTrue(r2["ok"])

    def test_disconnect_mid_line_does_not_kill_server(self) -> None:
        """A client that disconnects mid-line does not stop the server."""
        sock = self._connect()
        sock.sendall(b'{"id": 1, "method": "vault.pi')
        sock.close()
        client = self.daemon.client()
        self.assertTrue(client.ping()["pong"])

    def test_error_code_mapping(self) -> None:
        """Client errors map to the matching VaultError subclass."""
        client = self.daemon.client()
        with self.assertRaises(NotFound):
            client.call("vault.read_file", {"path": "/missing.md"})
        with self.assertRaises(BadRequest):
            client.call("vault.no_such_method", {})

    def test_from_runtime_reads_token(self) -> None:
        """VaultClient.from_runtime finds the token written by the daemon."""
        base = Path(tempfile.mkdtemp(prefix="sv-rt-"))
        runtime = base / "secure-vault"
        daemon = fake_daemon(self.session, runtime=runtime)
        previous = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = str(base)
        try:
            client = VaultClient.from_runtime(role="mcp")
            self.assertEqual(client.token, daemon.token)
            self.assertTrue(client.ping()["pong"])
        finally:
            if previous is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = previous
            daemon.stop()

    def test_connection_refused_maps_to_not_running(self) -> None:
        """A missing socket raises VaultNotRunning."""
        base = Path(tempfile.mkdtemp(prefix="sv-nosock-"))
        client = VaultClient(socket_path=base / "missing.sock", token="x")
        with self.assertRaises(VaultNotRunning):
            client.call("vault.ping")


if __name__ == "__main__":
    unittest.main()
