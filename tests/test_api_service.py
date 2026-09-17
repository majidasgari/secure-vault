"""Tests for vault.api.service (SPEC/06 §2 test_api_service)."""

from __future__ import annotations

import unittest

from support import DEFAULT_PASSWORD, tmp_vault
from vault.api.service import Service
from vault.core import semantics
from vault.errors import (
    BadRequest,
    DowngradeForbidden,
    PermissionDenied,
    VaultLocked,
)


def _expect_keys(*keys: str):
    """Return a check asserting every key is present in the result."""

    def check(test: unittest.TestCase, result: dict) -> None:
        for key in keys:
            test.assertIn(key, result)

    return check


def _expect_value(key: str, value):
    """Return a check asserting ``result[key] == value``."""

    def check(test: unittest.TestCase, result: dict) -> None:
        test.assertEqual(result[key], value)

    return check


# (label, method, params, role, expectation). ``expectation`` is either an exception
# class (the call must raise it) or a check callable ``(testcase, result) -> None``.
CASES: list[tuple[str, str, dict, str, object]] = [
    ("status_ui", "vault.status", {}, "ui", _expect_keys("locked", "home", "files")),
    ("status_mcp", "vault.status", {}, "mcp", _expect_keys("by_level", "folders")),
    ("locked_ui", "vault.locked", {}, "ui", _expect_value("locked", False)),
    ("ping_ui", "vault.ping", {}, "ui", _expect_value("pong", True)),
    ("list_root_mcp", "vault.list_folder", {"path": "/"}, "mcp",
     _expect_keys("path", "note", "entries")),
    ("list_notes_ui", "vault.list_folder", {"path": "/notes"}, "ui",
     _expect_keys("path", "note", "entries")),
    ("write_new_mcp", "vault.write_file",
     {"path": "/notes/new.md", "content": "fresh", "sensitivity": "normal"}, "mcp",
     _expect_value("created", True)),
    ("write_update_ui", "vault.write_file",
     {"path": "/notes/new.md", "content": "updated"}, "ui",
     _expect_value("created", False)),
    ("read_new_mcp", "vault.read_file", {"path": "/notes/new.md"}, "mcp",
     _expect_value("content", "updated")),
    ("read_secret_ui", "vault.read_file", {"path": "/notes/secret.md"}, "ui",
     _expect_value("sensitivity", "secret")),
    ("read_secret_mcp", "vault.read_file", {"path": "/notes/secret.md"}, "mcp",
     PermissionDenied),
    ("read_lines_ui", "vault.read_lines", {"path": "/notes/a.md", "start": 1, "count": 1},
     "ui", _expect_keys("text", "total_lines")),
    ("write_lines_ui", "vault.write_lines",
     {"path": "/notes/a.md", "text": "gamma", "mode": "append"}, "ui",
     _expect_keys("path", "size", "lines")),
    ("mkdir_mcp", "vault.mkdir", {"path": "/notes/sub"}, "mcp",
     _expect_value("created", True)),
    ("file_ops_mkdir_ui", "vault.file_ops", {"op": "mkdir", "src": "/notes/sub2"}, "ui",
     _expect_value("affected", 1)),
    ("file_ops_copy_ui", "vault.file_ops",
     {"op": "copy", "src": "/notes/a.md", "dst": "/notes/copy.md"}, "ui",
     _expect_value("op", "copy")),
    ("file_ops_move_ui", "vault.file_ops",
     {"op": "move", "src": "/notes/copy.md", "dst": "/notes/moved.md"}, "ui",
     _expect_value("op", "move")),
    ("file_ops_delete_ui", "vault.file_ops",
     {"op": "delete", "src": "/notes/moved.md"}, "ui", _expect_keys("affected")),
    ("set_tags_mcp", "vault.set_tags", {"path": "/notes/a.md", "tags": ["x", "y"]},
     "mcp", _expect_value("tags", ["x", "y"])),
    ("set_sensitivity_raise_mcp", "vault.set_sensitivity",
     {"path": "/notes/new.md", "level": "secret"}, "mcp",
     _expect_value("to", "secret")),
    ("set_sensitivity_lower_mcp", "vault.set_sensitivity",
     {"path": "/notes/new.md", "level": "normal"}, "mcp", DowngradeForbidden),
    ("folder_note_mcp", "vault.folder_note", {"path": "/notes"}, "mcp",
     _expect_keys("note")),
    ("set_folder_note_mcp", "vault.set_folder_note",
     {"path": "/notes", "text": "folder body"}, "mcp",
     _expect_value("updated", True)),
    ("search_filenames_mcp", "vault.search_filenames", {"query": "a"}, "mcp",
     _expect_keys("query", "count", "results")),
    ("search_text_ui", "vault.search_text", {"query": "alpha"}, "ui",
     _expect_keys("query", "count", "results")),
    ("search_semantic_ui", "vault.search_semantic", {"query": "alpha"}, "ui",
     _expect_keys("query", "count", "results")),
    ("request_open_secret_mcp", "vault.request_open_secret",
     {"path": "/secrets/keys.md"}, "mcp", _expect_value("status", "pending")),
    ("request_open_secret_secret_mcp", "vault.request_open_secret",
     {"path": "/notes/secret.md"}, "mcp", PermissionDenied),
    ("pending_requests_ui", "vault.pending_requests", {}, "ui",
     _expect_keys("requests")),
    ("access_log_ui", "vault.access_log", {"limit": 5}, "ui",
     _expect_keys("count", "entries")),
    ("read_secret_ui_ok", "vault.read_secret", {"path": "/notes/secret.md"}, "ui",
     _expect_value("content", "secret body")),
    ("read_secret_mcp", "vault.read_secret", {"path": "/notes/secret.md"}, "mcp",
     PermissionDenied),
    ("get_settings_ui", "vault.get_settings", {}, "ui",
     _expect_keys("plain_threshold_bytes", "auto_lock_seconds")),
    ("set_settings_ui", "vault.set_settings", {"auto_lock_seconds": 120}, "ui",
     _expect_value("updated", True)),
    ("semantic_index_ui", "vault.semantic_index", {}, "ui",
     _expect_keys("indexed", "skipped")),
    ("stats_ui", "vault.stats", {}, "ui",
     _expect_keys("files", "folders", "by_level", "store")),
    ("verify_blobs_ui", "vault.verify_blobs", {}, "ui",
     _expect_keys("checked", "bad")),
    ("unlock_mcp", "vault.unlock", {"password": DEFAULT_PASSWORD}, "mcp",
     PermissionDenied),
    ("lock_mcp", "vault.lock", {}, "mcp", PermissionDenied),
]


class ServiceDispatchTest(unittest.TestCase):
    """Table-driven routing for every service method."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.session.set_semantic_provider(semantics.StubProvider())
        self.session.write_file("notes/a.md", b"alpha beta")
        self.session.write_file("notes/secret.md", b"secret body")
        self.session.set_sensitivity("notes/secret.md", "secret")
        self.session.write_file("secrets/keys.md", b"token=abc")
        self.session.set_sensitivity("secrets/keys.md", "secretfile")
        self.session.set_folder_note("notes", "a folder note")
        semantics.index_all(self.session)
        self.service = Service(self.session)

    def tearDown(self) -> None:
        self.session.close()

    def test_dispatch_table(self) -> None:
        """Every documented method routes correctly (>30 cases)."""
        self.assertGreater(len(CASES), 30)
        for label, method, params, role, expectation in CASES:
            with self.subTest(case=label):
                if isinstance(expectation, type) and issubclass(expectation, Exception):
                    with self.assertRaises(expectation):
                        self.service.dispatch(
                            method, dict(params), role=role, session_id="t"
                        )
                else:
                    result = self.service.dispatch(
                        method, dict(params), role=role, session_id="t"
                    )
                    self.assertIsInstance(result, dict)
                    expectation(self, result)  # type: ignore[operator]

    def test_unknown_method(self) -> None:
        """An unknown method raises BadRequest('unknown_method')."""
        with self.assertRaises(BadRequest) as ctx:
            self.service.dispatch("vault.nope", {}, role="ui", session_id="t")
        self.assertEqual(ctx.exception.message, "unknown_method")

    def test_unknown_role(self) -> None:
        """A role outside {ui, mcp} is rejected."""
        with self.assertRaises(BadRequest):
            self.service.dispatch("vault.status", {}, role="root", session_id="t")

    def test_ui_only_methods_denied_to_mcp(self) -> None:
        """read_secret and unlock are never reachable with an mcp role."""
        with self.assertRaises(PermissionDenied):
            self.service.dispatch(
                "vault.read_secret", {"path": "/notes/secret.md"},
                role="mcp", session_id="t",
            )
        with self.assertRaises(PermissionDenied):
            self.service.dispatch(
                "vault.unlock", {"password": DEFAULT_PASSWORD},
                role="mcp", session_id="t",
            )

    def test_dispatch_logs_one_row_per_call(self) -> None:
        """Each dispatch appends a row with the role source, tool and outcome."""
        self.service.dispatch("vault.list_folder", {"path": "/"}, role="mcp", session_id="sock-9")
        rows = self.session.access_log(limit=5, source="mcp")
        match = [r for r in rows if r["tool"] == "vault.list_folder"]
        self.assertTrue(match)
        self.assertEqual(match[0]["outcome"], "allow")
        self.assertEqual(match[0]["session"], "sock-9")

    def test_dispatch_logs_denied_call(self) -> None:
        """A role refusal is recorded as a deny row for the dispatch layer."""
        with self.assertRaises(PermissionDenied):
            self.service.dispatch(
                "vault.read_secret", {"path": "/notes/secret.md"},
                role="mcp", session_id="sock-10",
            )
        rows = self.session.access_log(limit=5, source="mcp")
        match = [r for r in rows if r["tool"] == "vault.read_secret"]
        self.assertTrue(match)
        self.assertEqual(match[0]["outcome"], "deny")
        self.assertEqual(match[0]["code"], "PERMISSION_DENIED")


class ServiceLockedModeTest(unittest.TestCase):
    """Metadata commands work while locked; content commands do not."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.session.write_file("notes/a.md", b"body")
        self.session.lock()
        self.service = Service(self.session)

    def tearDown(self) -> None:
        self.session.close()

    def test_list_folder_while_locked(self) -> None:
        """list_folder and search_filenames work while locked; read_file does not."""
        listing = self.service.dispatch(
            "vault.list_folder", {"path": "/"}, role="mcp", session_id="t"
        )
        self.assertTrue(listing["entries"])
        found = self.service.dispatch(
            "vault.search_filenames", {"query": "a"}, role="mcp", session_id="t"
        )
        self.assertTrue(found["results"])
        with self.assertRaises(VaultLocked):
            self.service.dispatch(
                "vault.read_file", {"path": "/notes/a.md"}, role="mcp", session_id="t"
            )


if __name__ == "__main__":
    unittest.main()
