"""Tests for vault.core.session (SPEC/06 §2 test_session)."""

from __future__ import annotations

import unittest
from unittest import mock

from support import DEFAULT_PASSWORD, assert_no_plaintext, tmp_vault
from vault.core import session as session_module
from vault.errors import (
    DowngradeForbidden,
    NotFound,
    PermissionDenied,
    Unauthorized,
    VaultLocked,
)


class SessionLifecycleTest(unittest.TestCase):
    """Create/unlock/lock and lock-state enforcement."""

    def setUp(self) -> None:
        self.session = tmp_vault()

    def tearDown(self) -> None:
        self.session.close()

    def test_create_unlock_lock_unlock(self) -> None:
        """The create -> lock -> unlock cycle works."""
        self.assertFalse(self.session.is_locked)
        self.session.lock()
        self.assertTrue(self.session.is_locked)
        self.session.unlock(DEFAULT_PASSWORD)
        self.assertFalse(self.session.is_locked)

    def test_wrong_password(self) -> None:
        """A wrong password raises Unauthorized('bad_password')."""
        self.session.lock()
        with self.assertRaises(Unauthorized) as ctx:
            self.session.unlock("definitely wrong")
        self.assertEqual(ctx.exception.message, "bad_password")

    def test_locked_methods_raise(self) -> None:
        """Content methods raise VaultLocked while locked."""
        self.session.write_file("a.md", b"content")
        self.session.lock()
        calls = [
            lambda: self.session.read_text("a.md"),
            lambda: self.session.write_file("b.md", b"x"),
            lambda: self.session.mkdir("d"),
            lambda: self.session.delete("a.md"),
            lambda: self.session.set_tags("a.md", []),
            lambda: self.session.folder_note("a.md"),
            lambda: self.session.set_folder_note("a.md", "x"),
            lambda: self.session.search_text("content"),
            lambda: self.session.set_sensitivity("a.md", "secret"),
        ]
        for call in calls:
            with self.assertRaises(VaultLocked):
                call()

    def test_list_folder_works_while_locked(self) -> None:
        """Metadata listing works while locked; content does not."""
        self.session.write_file("a.md", b"content")
        self.session.lock()
        result = self.session.list_folder("/")
        self.assertIn("a.md", {e["logical_path"] for e in result["entries"]})
        with self.assertRaises(VaultLocked):
            self.session.read_text("a.md")


class SessionFileOpsTest(unittest.TestCase):
    """File, directory, tag and note operations."""

    def setUp(self) -> None:
        self.session = tmp_vault()

    def tearDown(self) -> None:
        self.session.close()

    def test_file_operations(self) -> None:
        """write/read/move/copy/delete/mkdir/tags/folder notes."""
        session = self.session
        session.mkdir("notes")
        session.write_file("notes/a.md", b"hello")
        self.assertEqual(session.read_text("notes/a.md"), "hello")
        session.write_file("notes/b.md", b"world")
        session.move("notes/b.md", "notes/c.md")
        self.assertEqual(session.read_text("notes/c.md"), "world")
        session.copy("notes/c.md", "notes/d.md")
        self.assertEqual(session.read_text("notes/d.md"), "world")
        session.set_tags("notes/a.md", ["x", "y"])
        self.assertEqual(session.index.get_tags("notes/a.md"), ["x", "y"])
        session.set_folder_note("notes", "یادداشت")
        self.assertEqual(session.folder_note("notes"), "یادداشت")
        session.delete("notes/d.md")
        with self.assertRaises(NotFound):
            session.read_text("notes/d.md")

    def test_write_lines(self) -> None:
        """write_lines appends and inserts."""
        session = self.session
        session.write_file("log.txt", b"one")
        session.write_lines("log.txt", "two", mode="append")
        self.assertEqual(session.read_text("log.txt"), "one\ntwo")
        session.write_lines("log.txt", "zero", mode="prepend")
        self.assertEqual(session.read_text("log.txt"), "zero\none\ntwo")
        session.write_lines("log.txt", "mid", mode="insert", at_line=1)
        self.assertEqual(session.read_text("log.txt"), "zero\nmid\none\ntwo")


class SessionPolicyTest(unittest.TestCase):
    """Policy enforcement for the MCP source and the access log."""

    def setUp(self) -> None:
        self.session = tmp_vault()

    def tearDown(self) -> None:
        self.session.close()

    def test_mcp_cannot_create_secret(self) -> None:
        """Creating a non-normal file from MCP is denied; normal is allowed."""
        with self.assertRaises(PermissionDenied):
            self.session.write_file(
                "mcp-secret.md", b"x", source="mcp", sensitivity="secret"
            )
        row = self.session.write_file("mcp-normal.md", b"x", source="mcp")
        self.assertEqual(row["sensitivity"], "normal")

    def test_mcp_may_raise_but_not_lower(self) -> None:
        """MCP may raise sensitivity, never lower it."""
        self.session.write_file("f.md", b"x", source="mcp")
        row = self.session.set_sensitivity("f.md", "secret", source="mcp")
        self.assertEqual(row["sensitivity"], "secret")
        with self.assertRaises(DowngradeForbidden):
            self.session.set_sensitivity("f.md", "normal", source="mcp")

    def test_mcp_read_secret_denied_and_logged(self) -> None:
        """Reading a secret file from MCP is denied and logged."""
        self.session.write_file("sec.md", b"top secret body")
        self.session.set_sensitivity("sec.md", "secret", source="ui")
        with self.assertRaises(PermissionDenied):
            self.session.read_file("sec.md", source="mcp")
        rows = self.session.index.access_log(limit=1)
        self.assertEqual(rows[0]["outcome"], "deny")
        self.assertEqual(rows[0]["code"], "PERMISSION_DENIED")
        self.assertEqual(rows[0]["target_path"], "sec.md")
        self.assertEqual(rows[0]["source"], "mcp")

    def test_mcp_can_maintain_existing_secret(self) -> None:
        """MCP may overwrite content of an existing secret file."""
        self.session.write_file("keep.md", b"v1")
        self.session.set_sensitivity("keep.md", "secret", source="ui")
        row = self.session.write_file("keep.md", b"v2", source="mcp")
        self.assertEqual(row["sensitivity"], "secret")


class SecretRequestTest(unittest.TestCase):
    """request_open_secret / resolve_open_secret handoff."""

    def setUp(self) -> None:
        self.session = tmp_vault()

    def tearDown(self) -> None:
        self.session.close()

    def test_request_open_secretfile(self) -> None:
        """A secretfile request is pending/shown and never returns content."""
        self.session.write_file("sf.md", b"native only content")
        self.session.set_sensitivity("sf.md", "secretfile", source="ui")
        calls: list[dict] = []

        def callback(request: dict) -> str:
            calls.append(request)
            return "shown"

        self.session.on_secret_request = callback
        result = self.session.request_open_secret("sf.md", source="mcp")
        self.assertEqual(result["status"], "shown")
        self.assertTrue(calls)
        self.assertEqual(calls[0]["path"], "sf.md")
        self.assertNotIn("native only content", str(result))

    def test_request_pending_and_resolve(self) -> None:
        """Without a callback the request stays pending and can be resolved."""
        self.session.write_file("sf.md", b"x")
        self.session.set_sensitivity("sf.md", "secretfile", source="ui")
        self.session.on_secret_request = None
        result = self.session.request_open_secret("sf.md", source="mcp")
        self.assertEqual(result["status"], "pending")
        self.assertTrue(self.session.pending_requests())
        resolved = self.session.resolve_open_secret(result["request_id"], approved=True)
        self.assertEqual(resolved["status"], "shown")
        self.assertEqual(self.session.pending_requests(), [])

    def test_request_secret_denied(self) -> None:
        """Requesting a merely secret file is denied."""
        self.session.write_file("s.md", b"x")
        self.session.set_sensitivity("s.md", "secret", source="ui")
        with self.assertRaises(PermissionDenied):
            self.session.request_open_secret("s.md", source="mcp")


class SessionMiscTest(unittest.TestCase):
    """Auto-lock, status, plain storage and plaintext leakage."""

    def test_auto_lock_due(self) -> None:
        """auto_lock_due follows the patched clock and honours 0 = disabled."""
        session = tmp_vault()
        try:
            with mock.patch.object(session_module, "now_ms", return_value=1000):
                session.touch()
            with mock.patch.object(session_module, "now_ms", return_value=1000 + 901_000):
                self.assertTrue(session.auto_lock_due())
            with mock.patch.object(session_module, "now_ms", return_value=1000):
                session.touch()
                self.assertFalse(session.auto_lock_due())
            session.meta.settings["auto_lock_seconds"] = 0
            with mock.patch.object(session_module, "now_ms", return_value=10_000_000):
                self.assertFalse(session.auto_lock_due())
        finally:
            session.close()

    def test_status(self) -> None:
        """status() carries the documented keys."""
        session = tmp_vault()
        try:
            session.write_file("a.md", b"hello")
            status = session.status()
            for key in (
                "locked",
                "home",
                "files",
                "folders",
                "by_level",
                "semantic",
                "auto_lock_seconds",
                "store",
            ):
                self.assertIn(key, status)
            self.assertEqual(status["home"], str(session.home))
            self.assertFalse(status["locked"])
        finally:
            session.close()

    def test_large_file_stored_plain(self) -> None:
        """An 11 MB file with a 1 MB threshold is stored plain."""
        session = tmp_vault(plain_threshold=1024 * 1024)
        try:
            row = session.write_file("big.bin", b"\x00" * (11 * 1024 * 1024))
            self.assertEqual(row["encrypted"], 0)
            self.assertEqual(session.read_file("big.bin")[:4], b"\x00\x00\x00\x00")
        finally:
            session.close()

    def test_no_plaintext_leakage(self) -> None:
        """A marker in a normal note never appears in the vault home."""
        session = tmp_vault()
        try:
            marker = b"TOP-SECRET-MARKER"
            session.write_file("note.md", b"body " + marker)
            assert_no_plaintext(session.home, [marker])
        finally:
            session.close()

    def test_encrypted_content_not_in_store(self) -> None:
        """An encrypted file's content never appears in the encrypted store."""
        session = tmp_vault(plain_threshold=1024 * 1024)
        try:
            marker = b"ENCRYPTED-MARKER-7c1"
            session.write_file("enc.txt", b"hello " + marker)
            assert_no_plaintext(session.home, [marker])
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
