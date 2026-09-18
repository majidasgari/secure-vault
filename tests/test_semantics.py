"""Tests for semantic cleaning, chunking and the separate vector index (SPEC/01 §11)."""

from __future__ import annotations

import pathlib
import struct
import tempfile
import unittest

from support import tmp_vault
from vault.core import semantics
from vault.core.chunking import (
    CHUNK_MODES,
    DEFAULT_CHUNK_MODE,
    chunk_text,
    strip_inline_data,
)
from vault.core.semantic_store import SemanticStore
from vault.core.semantics import (
    file_included,
    folder_included,
    normalize_folder_key,
)


def _pack(vec: list[float]) -> bytes:
    """Pack a float vector as little-endian float32."""
    return struct.pack(f"<{len(vec)}f", *vec)


class _RecordingProvider:
    """A tiny provider that records the size of every ``embed`` batch."""

    name = "recording"
    model = "recording"
    dim = 2

    def __init__(self) -> None:
        """Start with no recorded calls."""
        self.calls: list[int] = []

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Record the batch size and return a constant unit vector."""
        self.calls.append(len(texts))
        return [[1.0, 0.0] for _ in texts]


class ChunkingTest(unittest.TestCase):
    """Text cleaning and the three granularities."""

    def test_strip_inline_data_removes_base64(self) -> None:
        """A data URI and a bare base64 run disappear; the prose survives."""
        text = (
            "before data:image/png;base64,"
            + "A" * 400
            + " middle "
            + "B" * 300
            + " after"
        )
        cleaned = strip_inline_data(text)
        self.assertNotIn("base64", cleaned)
        self.assertNotIn("A" * 400, cleaned)
        self.assertNotIn("B" * 300, cleaned)
        self.assertIn("before", cleaned)
        self.assertIn("after", cleaned)

    def test_strip_markdown_data_image(self) -> None:
        """The whole ``![alt](data:…)`` wrapper is removed, not just the payload."""
        cleaned = strip_inline_data("x\n\n![shot](data:image/png;base64," + "A" * 200 + ")\n\ny")
        self.assertNotIn("![", cleaned)
        self.assertNotIn("data:", cleaned)

    def test_document_mode_is_one_chunk(self) -> None:
        """Document granularity keeps the whole text as a single chunk."""
        self.assertEqual(chunk_text("a\n\nb\n\nc", "document"), ["a\n\nb\n\nc"])

    def test_paragraph_mode(self) -> None:
        """Paragraphs split on blank lines and empty ones are dropped."""
        self.assertEqual(chunk_text("a\n\nb\n\n\nc\n\n", "paragraph"), ["a", "b", "c"])

    def test_sentence_mode(self) -> None:
        """Sentences split after terminal punctuation."""
        self.assertEqual(
            chunk_text("One. Two! Three? Four", "sentence"),
            ["One.", "Two!", "Three?", "Four"],
        )

    def test_unknown_mode_defaults_to_paragraph(self) -> None:
        """An unknown granularity falls back to the documented default."""
        self.assertEqual(DEFAULT_CHUNK_MODE, "paragraph")
        self.assertEqual(chunk_text("a\n\nb", "nonsense"), ["a", "b"])
        self.assertIn("paragraph", CHUNK_MODES)


class FolderScopeTest(unittest.TestCase):
    """Folder inclusion with inheritance (new folders follow their parent)."""

    def test_normalize_folder_key(self) -> None:
        """Root forms collapse to the ``*`` sentinel."""
        self.assertEqual(normalize_folder_key("/"), "*")
        self.assertEqual(normalize_folder_key(""), "*")
        self.assertEqual(normalize_folder_key("/Work/Payroll/"), "Work/Payroll")

    def test_inheritance_from_nearest_ancestor(self) -> None:
        """A folder follows its nearest overridden ancestor, defaulting to included."""
        states = {"private": False}
        self.assertFalse(folder_included("private", states))
        self.assertFalse(folder_included("private/sub/deep", states))
        self.assertTrue(folder_included("public", states))
        self.assertTrue(folder_included("", states))

    def test_child_can_re_include_under_excluded_parent(self) -> None:
        """An explicit child override beats an excluded ancestor."""
        states = {"private": False, "private/open": True}
        self.assertFalse(folder_included("private/other", states))
        self.assertTrue(folder_included("private/open", states))
        self.assertTrue(folder_included("private/open/deep", states))

    def test_deselect_all_sentinel(self) -> None:
        """The root override excludes everything until a child re-includes it."""
        states: dict[str, bool] = {"*": False}
        self.assertFalse(file_included("a.md", states))
        self.assertFalse(file_included("notes/a.md", states))
        states["notes"] = True
        self.assertTrue(file_included("notes/a.md", states))
        self.assertFalse(file_included("other/a.md", states))

    def test_file_included_uses_parent_folder(self) -> None:
        """A file follows its parent folder's state."""
        states = {"private": False}
        self.assertFalse(file_included("private/a.md", states))
        self.assertFalse(file_included("private/sub/a.md", states))
        self.assertTrue(file_included("a.md", states))


class SemanticIndexTest(unittest.TestCase):
    """Chunked indexing and KNN search through the encrypted ``semantic.db``."""

    def setUp(self) -> None:
        """Start from an enabled stub-provider vault."""
        self.session = tmp_vault(
            settings={
                "semantic": {
                    "enabled": True,
                    "provider": "stub",
                    "model": "stub",
                    "chunking": "paragraph",
                }
            }
        )

    def tearDown(self) -> None:
        """Release the vault."""
        self.session.close()

    def test_index_paragraphs_and_search(self) -> None:
        """Paragraphs are indexed and search returns a snippet per file."""
        self.session.write_file("a.md", b"alpha green\n\nalpha blue\n\nbeta")
        self.session.write_file("b.md", b"beta only")
        result = semantics.index_all(self.session)
        self.assertGreaterEqual(result["chunks"], 4)
        self.assertEqual(result["indexed"], 2)
        hits = self.session.search_semantic("green alpha")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["logical_path"], "a.md")
        self.assertIn("snippet", hits[0])
        self.assertIn("chunk", hits[0])

    def test_binary_and_data_uri_are_not_embedded(self) -> None:
        """Binary files are skipped and data URIs never reach a vector."""
        self.session.write_file(
            "t.md",
            ("hello world\n\n![i](data:image/png;base64," + "A" * 400 + ")").encode(),
        )
        self.session.write_file("p.png", b"\x89PNG\r\n\x1a\n\x00\x00binary")
        result = semantics.index_all(self.session)
        self.assertEqual(result["indexed"], 1)
        self.assertEqual(result["skipped"], 1)
        joined = "\n".join(self.session.semantic_store.chunk_texts())
        self.assertIn("hello world", joined)
        self.assertNotIn("base64", joined)
        self.assertNotIn("A" * 400, joined)

    def test_chunking_change_resets_layout(self) -> None:
        """Changing granularity invalidates the old chunks until a rebuild."""
        self.session.write_file("a.md", b"one. two! three?\n\nfour five")
        semantics.index_all(self.session)
        before = self.session.semantic_store.meta()
        self.assertEqual(before.get("chunking"), "paragraph")
        self.session.meta.settings["semantic"]["chunking"] = "document"
        self.session.meta.save()
        self.session.refresh_semantic_provider()
        # Warm the store, then confirm the stale layout yields nothing.
        self.assertEqual(self.session.search_semantic("one"), [])
        result = semantics.index_all(self.session)
        self.assertEqual(self.session.semantic_store.meta().get("chunking"), "document")
        self.assertEqual(result["chunks"], 1)

    def test_secret_file_never_enters_semantic(self) -> None:
        """A raised file's chunks are dropped from the semantic index."""
        self.session.write_file("s.md", b"alpha secret body")
        semantics.index_all(self.session)
        self.assertTrue(self.session.search_semantic("alpha"))
        self.session.set_sensitivity("s.md", "secret")
        self.assertFalse(self.session.search_semantic("alpha"))


    def test_excluded_folder_is_skipped_and_hidden(self) -> None:
        """An unchecked folder is neither embedded nor returned by search."""
        self.session.write_file("keep/a.md", b"alpha kept")
        self.session.write_file("private/b.md", b"alpha hidden")
        self.session.meta.settings["semantic"]["folder_states"] = {"private": False}
        self.session.meta.save()
        self.session.refresh_semantic_provider()
        result = semantics.index_all(self.session)
        self.assertEqual(result["indexed"], 1)
        paths = {h["logical_path"] for h in self.session.search_semantic("alpha")}
        self.assertIn("keep/a.md", paths)
        self.assertNotIn("private/b.md", paths)

    def test_prune_removes_newly_excluded_chunks(self) -> None:
        """Toggling a folder off drops the chunks that are now out of scope."""
        self.session.write_file("private/b.md", b"alpha hidden")
        semantics.index_all(self.session)
        self.assertTrue(self.session.search_semantic("alpha"))
        self.session.meta.settings["semantic"]["folder_states"] = {"private": False}
        self.session.meta.save()
        removed = self.session.prune_semantic_folders()
        self.assertGreaterEqual(removed, 1)
        self.assertFalse(self.session.search_semantic("alpha"))

    def test_file_note_is_embedded(self) -> None:
        """A file's short note is embedded with the body and is searchable."""
        self.session.write_file("n.md", b"body about cats")
        self.session.set_file_note("n.md", "یادداشت درباره سگ‌ها")
        semantics.index_all(self.session)
        hits = self.session.search_semantic("یادداشت درباره سگ‌ها")
        self.assertTrue(any(h["logical_path"] == "n.md" for h in hits))

    def test_index_prefix_scopes_the_build(self) -> None:
        """A prefix rebuild only embeds files inside that subtree."""
        self.session.write_file("keep/a.md", b"alpha")
        self.session.write_file("other/b.md", b"alpha")
        result = self.session.index_semantics(force=True, prefix="keep")
        self.assertEqual(result["indexed"], 1)
        paths = {h["logical_path"] for h in self.session.search_semantic("alpha")}
        self.assertIn("keep/a.md", paths)
        self.assertNotIn("other/b.md", paths)

    def test_cross_file_batching(self) -> None:
        """Chunks from many files are embedded in a few large batches, not one per file."""
        provider = _RecordingProvider()
        self.session.set_semantic_provider(provider)
        for index in range(100):
            self.session.write_file(f"n{index}.md", b"alpha")
        result = semantics.index_all(self.session)
        self.assertEqual(result["indexed"], 100)
        self.assertTrue(provider.calls)
        self.assertLessEqual(max(provider.calls), semantics.BATCH_SIZE)
        self.assertLess(len(provider.calls), 100)  # cross-file batching actually happened


class SemanticStoreTest(unittest.TestCase):
    """The standalone encrypted vector store."""

    def setUp(self) -> None:
        """Create a bare store with a scratch runtime directory."""
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="sv-semstore-"))
        self.runtime = self.base / "runtime"
        self.runtime.mkdir()
        self.db_path = self.base / "semantic.db"
        self.store = SemanticStore.create_new(self.db_path, b"k" * 32, self.runtime)

    def tearDown(self) -> None:
        """Close and forget the store."""
        self.store.close()

    def test_knn_ordering_and_delete(self) -> None:
        """Nearest chunks come first and deleting a file drops its vectors."""
        self.store.ensure_layout("m", 2, "paragraph")
        self.store.replace_file(1, ["x", "y"], [_pack([1.0, 0.0]), _pack([0.0, 1.0])])
        self.store.replace_file(2, ["z"], [_pack([0.9, 0.1])])
        hits = self.store.search(_pack([1.0, 0.0]), "m", k=5)
        self.assertEqual(hits[0]["file_id"], 1)
        self.assertAlmostEqual(hits[0]["score"], 1.0, places=5)
        self.assertEqual(self.store.count_chunks(), 3)
        self.store.delete_file(1)
        self.assertEqual(self.store.count_chunks(), 1)
        self.assertEqual(self.store.count_files(), 1)

    def test_layout_change_wipes_vectors(self) -> None:
        """A new model/dim/chunking resets the index and recreates the vec table."""
        self.store.ensure_layout("m", 2, "paragraph")
        self.store.replace_file(1, ["x"], [_pack([1.0, 0.0])])
        self.store.ensure_layout("m2", 3, "sentence")
        self.assertEqual(self.store.count_chunks(), 0)
        self.store.replace_file(1, ["x"], [_pack([1.0, 0.0, 0.0])])
        self.assertEqual(self.store.search(_pack([1.0, 0.0, 0.0]), "m2", k=1)[0]["file_id"], 1)

    def test_store_is_encrypted_at_rest(self) -> None:
        """The on-disk blob does not contain the chunk text."""
        self.store.ensure_layout("m", 2, "paragraph")
        self.store.replace_file(1, ["topsecret-chunk"], [_pack([1.0, 0.0])])
        self.store.flush()
        raw = self.db_path.read_bytes()
        self.assertNotIn(b"topsecret-chunk", raw)


if __name__ == "__main__":
    unittest.main()
