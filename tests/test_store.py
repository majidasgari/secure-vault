"""Tests for vault.core.store (SPEC/06 §2 test_store)."""

from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from support import tmp_vault
from vault.core import semantics
from vault.core.store import STORE_FILENAME, SecureStore
from vault.util import normalize_fa


class SecureStoreTest(unittest.TestCase):
    """Encrypted store lifecycle, FTS index, notes and vectors."""

    def setUp(self) -> None:
        self.session = tmp_vault()

    def tearDown(self) -> None:
        self.session.close()

    def test_decrypted_file_lifecycle(self) -> None:
        """Unlock creates store.dec (0600); lock removes it."""
        dec = self.session._store._dec_path
        self.assertTrue(dec.exists())
        self.assertEqual(stat.S_IMODE(dec.stat().st_mode), 0o600)
        self.session.lock()
        self.assertFalse(dec.exists())

    def test_decrypted_file_never_in_vault_home(self) -> None:
        """store.dec is never written inside the vault home."""
        home = self.session.home
        self.assertEqual(list(home.rglob("store.dec")), [])

    def test_secure_store_has_no_plaintext(self) -> None:
        """Neither note text nor folder-note text appears in secure.store."""
        marker = b"STORE-MARKER-9f3a"
        self.session.write_file("note.md", b"body " + marker)
        self.session.set_folder_note("note.md", "note " + marker.decode())
        raw = (self.session.home / STORE_FILENAME).read_bytes()
        self.assertNotIn(marker, raw)
        self.assertNotIn(b"note STORE-MARKER", raw)

    def test_fts_indexing_and_ordering(self) -> None:
        """More relevant documents rank first."""
        self.session.write_file("a.md", b"apple apple apple")
        self.session.write_file("b.md", b"apple banana")
        results = self.session.search_text("apple")
        self.assertEqual(results[0]["logical_path"], "a.md")
        self.assertEqual(len(results), 2)

    def test_normalize_fa_both_sides(self) -> None:
        """Variant letters, digits and diacritics match on both sides."""
        self.session.write_file("fa.md", "ایران ۱۴۰۰ مُهِم".encode("utf-8"))
        self.assertTrue(self.session.search_text("ايران"))  # Arabic yeh query
        self.assertTrue(self.session.search_text("1400"))  # ASCII digit query
        self.assertTrue(self.session.search_text("مهم"))  # without diacritics
        self.assertIn("\u200c", normalize_fa("می\u200cرود"))  # ZWNJ preserved

    def test_removing_file_removes_rows_and_vectors(self) -> None:
        """Deleting a file clears its FTS row and vectors."""
        self.session.set_semantic_provider(semantics.StubProvider())
        self.session.write_file("r.md", b"needle in haystack")
        row = self.session.index.require_file("r.md")
        self.session.store.set_vector(int(row["id"]), "stub", b"\x00\x00\x80?" * 4)
        self.assertTrue(self.session.store.get_vectors("stub"))
        self.session.delete("r.md")
        self.assertEqual(self.session.store.get_vectors("stub"), [])
        self.assertEqual(self.session.search_text("needle"), [])

    def test_stats_counts(self) -> None:
        """stats reports FTS rows, notes, vectors and a byte size."""
        self.session.write_file("a.md", b"alpha")
        self.session.write_file("b.md", b"beta")
        self.session.set_folder_note("a.md", "note")
        row = self.session.index.require_file("a.md")
        self.session.store.set_vector(int(row["id"]), "stub", b"\x00\x00\x80?" * 4)
        stats = self.session.store.stats()
        self.assertEqual(stats["fts_rows"], 2)
        self.assertEqual(stats["notes"], 1)
        self.assertEqual(stats["vectors"], 1)
        self.assertGreater(stats["bytes"], 0)

    def test_flush_survives_simulated_crash(self) -> None:
        """A second store instance opened from secure.store sees flushed data."""
        self.session.write_file("crash.md", b"persisted content")
        master = self.session._master_key
        second_runtime = Path(tempfile.mkdtemp(prefix="sv-crash-"))
        second = SecureStore.open(self.session.home, master, second_runtime)
        try:
            hits = second.search_text("persisted")
            self.assertTrue(hits)
        finally:
            second.close()

    def test_folder_notes_round_trip(self) -> None:
        """Folder notes round-trip including Persian text."""
        self.session.set_folder_note("notes", "یادداشت مهم")
        self.assertEqual(self.session.folder_note("notes"), "یادداشت مهم")
        self.session.set_folder_note("notes", "updated")
        self.assertEqual(self.session.folder_note("notes"), "updated")


if __name__ == "__main__":
    unittest.main()
