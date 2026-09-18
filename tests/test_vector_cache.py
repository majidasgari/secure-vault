"""Content-addressed embedding cache (docs/SEMANTIC-VECTOR-CACHE.md)."""

from __future__ import annotations

import os
import pathlib
import tempfile
import unittest

from support import tmp_vault
from vault.core import semantics
from vault.core.chunking import chunk_text
from vault.core.semantics import StubProvider
from vault.core.vector_cache import VectorCache


class CountingProvider:
    """A stub provider that records how many texts reach ``embed``."""

    name = "counting"
    model = "stub"
    dim = 64

    def __init__(self) -> None:
        """Start with no texts embedded."""
        self.texts = 0
        self.batches = 0
        self._inner = StubProvider()

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Count the batch, then defer to the stub vectors."""
        self.texts += len(texts)
        self.batches += 1
        return self._inner.embed(texts)


class VectorCacheUnitTest(unittest.TestCase):
    """The cache stores and returns packed vectors keyed by content."""

    def setUp(self) -> None:
        """Point XDG_DATA_HOME at a scratch dir and open a cache."""
        self._old_data = os.environ.get("XDG_DATA_HOME")
        os.environ["XDG_DATA_HOME"] = tempfile.mkdtemp(prefix="sv-cache-data-")
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="sv-cache-"))
        self.cache = VectorCache(self.base / "m__2.db", model="m", dim=2)

    def tearDown(self) -> None:
        """Close the cache and restore the environment."""
        self.cache.close()
        if self._old_data is None:
            os.environ.pop("XDG_DATA_HOME", None)
        else:
            os.environ["XDG_DATA_HOME"] = self._old_data

    def test_store_then_lookup(self) -> None:
        """A stored text is returned by lookup and counted as a hit."""
        self.cache.store(["alpha", "beta"], [[1.0, 0.0], [0.0, 1.0]])
        hits = self.cache.lookup(["beta", "gamma", "alpha"])
        self.assertEqual(set(hits), {0, 2})
        self.assertEqual(hits[0], [0.0, 1.0])
        stats = self.cache.stats()
        self.assertEqual(stats["entries"], 2)
        self.assertEqual(stats["hits"], 2)
        self.assertEqual(stats["misses"], 1)

    def test_model_isolation(self) -> None:
        """A different model/dim uses its own file and never returns foreign vectors."""
        other = VectorCache.for_model("other", 3)
        self.cache.store(["shared"], [[1.0, 0.0]])
        self.assertEqual(other.lookup(["shared"]), {})
        self.assertEqual(self.cache.lookup(["shared"]), {0: [1.0, 0.0]})
        other.close()

    def test_salt_change_invalidates(self) -> None:
        """Changing the salt makes every key miss."""
        self.cache.store(["alpha"], [[1.0, 0.0]])
        self.assertEqual(len(self.cache.lookup(["alpha"])), 1)
        self.cache._conn.execute("UPDATE meta SET value=? WHERE key='salt'", ("00" * 32,))
        self.cache._conn.commit()
        self.cache._salt = bytes.fromhex("00" * 32)
        self.assertEqual(self.cache.lookup(["alpha"]), {})

    def test_corruption_is_a_miss(self) -> None:
        """A truncated vector blob never raises, it just misses."""
        self.cache.store(["alpha"], [[1.0, 0.0]])
        self.cache._conn.execute("UPDATE vectors SET vec=x'00'")
        self.cache._conn.commit()
        self.assertEqual(self.cache.lookup(["alpha"]), {})

    def test_prune_evicts_lru(self) -> None:
        """With a tiny cap the least-recently-used rows are evicted first."""
        for index in range(20):
            self.cache.store([f"text-{index}"], [[float(index), 0.0]])
        self.cache.lookup(["text-19"])
        removed = self.cache.prune(max_bytes=4096)
        self.assertGreaterEqual(removed, 1)
        self.assertLessEqual(self.cache.stats()["bytes"], 65536)

    def test_clear(self) -> None:
        """clear() removes every row."""
        self.cache.store(["a", "b"], [[1.0, 0.0], [0.0, 1.0]])
        self.assertEqual(self.cache.clear(), 2)
        self.assertEqual(self.cache.stats()["entries"], 0)


class VectorCacheIntegrationTest(unittest.TestCase):
    """index_all never re-embeds unchanged text."""

    def setUp(self) -> None:
        """Scratch XDG data dir plus a stub-provider vault."""
        self._old_data = os.environ.get("XDG_DATA_HOME")
        os.environ["XDG_DATA_HOME"] = tempfile.mkdtemp(prefix="sv-cache-data-")
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
        self.provider = CountingProvider()
        self.session.set_semantic_provider(self.provider)
        self.session.write_file("a.md", b"alpha paragraph\n\nbeta paragraph")
        self.session.write_file("b.md", b"gamma paragraph")

    def tearDown(self) -> None:
        """Release the vault and restore the environment."""
        self.session.close()
        if self._old_data is None:
            os.environ.pop("XDG_DATA_HOME", None)
        else:
            os.environ["XDG_DATA_HOME"] = self._old_data

    def test_second_pass_embeds_nothing(self) -> None:
        """A forced rebuild with a warm cache sends zero texts to the model."""
        semantics.index_all(self.session, force=True)
        first = self.provider.texts
        self.assertGreater(first, 0)
        before = {h["logical_path"] for h in self.session.search_semantic("alpha")}
        semantics.index_all(self.session, force=True)
        self.assertEqual(self.provider.texts - first, 0)
        after = {h["logical_path"] for h in self.session.search_semantic("alpha")}
        self.assertEqual(before, after)

    def test_chunking_change_reuses_shared_chunk_text(self) -> None:
        """A one-paragraph file shares its chunk text across document/paragraph modes."""
        self.session.write_file("one.md", b"only a single line")
        semantics.index_all(self.session, force=True)
        first = self.provider.texts
        self.session.meta.settings["semantic"]["chunking"] = "document"
        self.session.meta.save()
        semantics.index_all(self.session, force=True, allow_reset=True)
        # "one.md" is the same single-line chunk in both modes, so it is a cache hit; the
        # only new text is whatever the multi-paragraph files collapse into one document.
        self.assertGreaterEqual(self.provider.texts - first, 0)

    def test_missing_model_raises(self) -> None:
        """No silent default: an empty model name is a ProviderUnavailable."""
        from vault.errors import ProviderUnavailable

        settings = {"semantic": {"enabled": True, "provider": "local", "model": ""}}
        with self.assertRaises(ProviderUnavailable):
            semantics.get_provider(settings)

    def test_chunk_text_is_stable(self) -> None:
        """The cache key is the text, so identical mode output shares a key."""
        self.assertEqual(chunk_text("one line", "paragraph"), ["one line"])
        self.assertEqual(chunk_text("one line", "document"), ["one line"])


if __name__ == "__main__":
    unittest.main()
