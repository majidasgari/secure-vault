"""Tests for vault.core.search (SPEC/06 §2 test_search)."""

from __future__ import annotations

import unittest

from support import tmp_vault
from vault.core import semantics
from vault.core.search import SearchKind, search_filenames, search_semantic, search_text
from vault.errors import BadRequest, ProviderUnavailable


class SearchIndependenceTest(unittest.TestCase):
    """The three search kinds never mix results."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.session.write_file("apple-notes.md", b"nothing about fruit here")
        self.session.write_file("body.md", b"an apple appears in this body")
        self.session.set_semantic_provider(semantics.StubProvider())

    def tearDown(self) -> None:
        self.session.close()

    def test_filename_only_hit(self) -> None:
        """A filename match with no body match appears only in filename results."""
        filenames = {r["logical_path"] for r in self.session.search_filenames("apple")}
        texts = {r["logical_path"] for r in self.session.search_text("apple")}
        self.assertIn("apple-notes.md", filenames)
        self.assertNotIn("apple-notes.md", texts)
        self.assertIn("body.md", texts)
        self.assertNotIn("body.md", filenames)

    def test_secret_note_filename_only(self) -> None:
        """A secret note appears in filename results but never in text/semantic."""
        self.session.write_file("secret-apple.md", b"an apple in a secret body")
        self.session.set_sensitivity("secret-apple.md", "secret")
        self.session.set_semantic_provider(semantics.StubProvider())
        semantics.index_all(self.session)
        filenames = {r["logical_path"] for r in self.session.search_filenames("apple")}
        texts = {r["logical_path"] for r in self.session.search_text("apple")}
        semantic = {r["logical_path"] for r in self.session.search_semantic("apple")}
        self.assertIn("secret-apple.md", filenames)
        self.assertNotIn("secret-apple.md", texts)
        self.assertNotIn("secret-apple.md", semantic)

    def test_search_kind_enum(self) -> None:
        """SearchKind carries the documented string values."""
        self.assertEqual(SearchKind.FILENAME, "filename")
        self.assertEqual(SearchKind.TEXT, "text")
        self.assertEqual(SearchKind.SEMANTIC, "semantic")


class SearchBehaviourTest(unittest.TestCase):
    """Validation, limits and snippets."""

    def setUp(self) -> None:
        self.session = tmp_vault()

    def tearDown(self) -> None:
        self.session.close()

    def test_empty_query_is_bad_request(self) -> None:
        """An empty query raises BadRequest for every kind."""
        for func in (search_filenames, search_text, search_semantic):
            with self.assertRaises(BadRequest):
                func(self.session, "")

    def test_limit_respected(self) -> None:
        """The limit caps filename results."""
        for index in range(5):
            self.session.write_file(f"note-{index}.md", b"x")
        self.assertEqual(len(self.session.search_filenames("note", limit=2)), 2)

    def test_snippet_bounds_and_token(self) -> None:
        """The text snippet is <= 240 chars and contains the query token."""
        body = ("padding " * 100) + "needle-token" + (" trailing" * 100)
        self.session.write_file("long.md", body.encode("utf-8"))
        results = self.session.search_text("needle-token")
        self.assertTrue(results)
        snippet = results[0]["snippet"]
        self.assertLessEqual(len(snippet), 240)
        self.assertIn("needle-token", snippet)

    def test_semantic_requires_provider(self) -> None:
        """Without a provider, semantic search is unavailable."""
        self.session.write_file("a.md", b"hello world")
        with self.assertRaises(ProviderUnavailable):
            self.session.search_semantic("hello")

    def test_semantic_ordering(self) -> None:
        """Semantic results are ordered by descending similarity."""
        self.session.set_semantic_provider(semantics.StubProvider())
        self.session.write_file("sem1.md", b"quantum physics")
        self.session.write_file("sem2.md", b"quantum physics advanced")
        semantics.index_all(self.session)
        results = self.session.search_semantic("quantum physics")
        scores = [r["score"] for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertTrue(results)
        self.assertEqual(results[0]["logical_path"], "sem1.md")


if __name__ == "__main__":
    unittest.main()
