"""Tests for vault.core.index (SPEC/06 §2 test_index)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vault.core.index import Index
from vault.errors import AlreadyExists, BadRequest, InvalidPath, NotFound


class IndexTest(unittest.TestCase):
    """Metadata index behaviour."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="sv-idx-"))
        self.index = Index(self.tmp / "meta.sqlite")

    def tearDown(self) -> None:
        self.index.close()

    def test_schema_creation_is_idempotent(self) -> None:
        """Opening the same DB twice does not fail or duplicate schema rows."""
        second = Index(self.tmp / "meta.sqlite")
        try:
            row = second.conn.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
            self.assertEqual(row["value"], "1")
        finally:
            second.close()

    def test_upsert_get_require(self) -> None:
        """Insert, fetch and required-fetch behave as documented."""
        file_id = self.index.upsert_file(
            "notes/a.md", blob_id="abc", size=12, encrypted=1, sensitivity="normal"
        )
        row = self.index.get_file("notes/a.md")
        assert row is not None
        self.assertEqual(row["id"], file_id)
        self.assertEqual(row["blob_id"], "abc")
        self.assertEqual(row["size"], 12)
        self.assertIsNone(self.index.get_file("missing"))
        with self.assertRaises(NotFound):
            self.index.require_file("missing")

    def test_upsert_updates_existing(self) -> None:
        """Upserting an existing path updates it in place."""
        first = self.index.upsert_file("f", blob_id="a", size=1)
        second = self.index.upsert_file("f", blob_id="b", size=2)
        self.assertEqual(first, second)
        row = self.index.require_file("f")
        self.assertEqual(row["blob_id"], "b")
        self.assertEqual(row["size"], 2)

    def test_delete_recursive_returns_children(self) -> None:
        """Recursive delete removes and returns the whole subtree."""
        self.index.upsert_file("d", is_dir=True)
        self.index.upsert_file("d/a")
        self.index.upsert_file("d/sub", is_dir=True)
        self.index.upsert_file("d/sub/b")
        removed = self.index.delete_file("d", recursive=True)
        self.assertEqual(len(removed), 4)
        self.assertIsNone(self.index.get_file("d/a"))
        self.assertIsNone(self.index.get_file("d/sub/b"))
        self.assertIsNone(self.index.get_file("d"))

    def test_delete_non_recursive_directory_rejected(self) -> None:
        """A non-empty directory cannot be deleted non-recursively."""
        self.index.upsert_file("d", is_dir=True)
        self.index.upsert_file("d/a")
        with self.assertRaises(BadRequest):
            self.index.delete_file("d")

    def test_list_dir_ordering(self) -> None:
        """Directories come first, then case-insensitive names."""
        self.index.upsert_file("b.txt")
        self.index.upsert_file("a.txt")
        self.index.upsert_file("Zdir", is_dir=True)
        self.index.upsert_file("adir", is_dir=True)
        names = [row["logical_path"] for row in self.index.list_dir("/")]
        self.assertEqual(names, ["adir", "Zdir", "a.txt", "b.txt"])

    def test_list_dir_missing_is_not_found(self) -> None:
        """A missing directory is NotFound; the root is always listable."""
        with self.assertRaises(NotFound):
            self.index.list_dir("missing")
        self.assertEqual(self.index.list_dir("/"), [])

    def test_move_rewrites_descendants(self) -> None:
        """Moving a directory rewrites every descendant path."""
        self.index.upsert_file("d", is_dir=True)
        self.index.upsert_file("d/a")
        self.index.upsert_file("d/sub", is_dir=True)
        self.index.upsert_file("d/sub/b")
        self.index.move("d", "e")
        self.assertIsNotNone(self.index.get_file("e"))
        self.assertIsNotNone(self.index.get_file("e/a"))
        self.assertIsNotNone(self.index.get_file("e/sub/b"))
        self.assertIsNone(self.index.get_file("d/a"))

    def test_move_to_existing_is_already_exists(self) -> None:
        """Moving onto an existing path is refused."""
        self.index.upsert_file("a")
        self.index.upsert_file("b")
        with self.assertRaises(AlreadyExists):
            self.index.move("a", "b")

    def test_tags(self) -> None:
        """Tags set/get/list and reverse lookup."""
        self.index.upsert_file("f")
        self.index.set_tags("f", ["x", "y", "x", " "])
        self.assertEqual(self.index.get_tags("f"), ["x", "y"])
        self.assertEqual(
            [r["logical_path"] for r in self.index.files_by_tag("x")], ["f"]
        )
        self.assertEqual({t["name"] for t in self.index.all_tags()}, {"x", "y"})

    def test_access_log_append_filters_and_csv(self) -> None:
        """The access log is append-only, filterable and exportable."""
        self.index.log_access(
            source="mcp", role="mcp", tool="read_file", target_path="a",
            outcome="deny", code="PERMISSION_DENIED",
        )
        self.index.log_access(
            source="ui", role="ui", tool="read_file", target_path="b", outcome="allow"
        )
        self.assertEqual(self.index.access_log_count(), 2)
        rows = self.index.access_log()
        self.assertEqual(rows[0]["source"], "ui")  # newest first
        self.assertEqual(len(self.index.access_log(source="mcp")), 1)
        self.assertEqual(len(self.index.access_log(outcome="deny")), 1)
        self.assertEqual(self.index.access_log(limit=1)[0]["source"], "ui")
        dest = self.tmp / "log.csv"
        self.assertEqual(self.index.export_access_log_csv(dest), 2)
        text = dest.read_text(encoding="utf-8")
        self.assertIn("PERMISSION_DENIED", text)
        self.assertIn("source", text)

    def test_kv(self) -> None:
        """Key/value storage round-trips and defaults."""
        self.assertEqual(self.index.kv_get("missing", "default"), "default")
        self.index.kv_set("k", "v")
        self.assertEqual(self.index.kv_get("k"), "v")
        self.index.kv_set("k", "v2")
        self.assertEqual(self.index.kv_get("k"), "v2")

    def test_invalid_path_rejected(self) -> None:
        """Logical paths always go through normalize_logical_path."""
        with self.assertRaises(InvalidPath):
            self.index.upsert_file("a/../b")
        with self.assertRaises(InvalidPath):
            self.index.get_file("/absolute")

    def test_count(self) -> None:
        """Counts report files, dirs and levels."""
        self.index.upsert_file("d", is_dir=True)
        self.index.upsert_file("a")
        self.index.upsert_file("b", sensitivity="secret")
        counts = self.index.count()
        self.assertEqual(counts["files"], 2)
        self.assertEqual(counts["dirs"], 1)
        self.assertEqual(counts["by_level"]["normal"], 2)
        self.assertEqual(counts["by_level"]["secret"], 1)

    def test_sensitive_paths(self) -> None:
        """sensitive_paths lists secret levels."""
        self.index.upsert_file("a")
        self.index.upsert_file("b", sensitivity="secret")
        self.index.upsert_file("c", sensitivity="secretfile")
        self.assertEqual(self.index.sensitive_paths(), ["b", "c"])
        self.assertEqual(self.index.sensitive_paths("secret"), ["b"])


if __name__ == "__main__":
    unittest.main()
