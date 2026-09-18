"""Regression guards: no silent index wipe, and auto-index is queued off-thread."""

from __future__ import annotations

import os
import pathlib
import tempfile
import time
import unittest

from support import tmp_vault
from vault.core import semantics
from vault.core.semantic_queue import SemanticIndexQueue
from vault.errors import ProviderUnavailable


class FixedProvider:
    """A provider with a chosen model/dim that returns constant vectors."""

    name = "fixed"

    def __init__(self, model: str, dim: int) -> None:
        """Remember the model and dimension."""
        self.model = model
        self.dim = dim

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return one constant vector per text."""
        return [[1.0] + [0.0] * (self.dim - 1) for _ in texts]


class SemanticGuardTest(unittest.TestCase):
    """The live index survives an implicit model change; auto-index is queued."""

    def setUp(self) -> None:
        """Scratch data dir plus an enabled stub-provider vault."""
        self._old_data = os.environ.get("XDG_DATA_HOME")
        os.environ["XDG_DATA_HOME"] = tempfile.mkdtemp(prefix="sv-guard-data-")
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
        self.session.set_semantic_provider(FixedProvider("m1", 2))
        self.session.write_file("a.md", b"alpha body")
        self.session.index_semantics(force=True, allow_reset=True, reason="seed")

    def tearDown(self) -> None:
        """Release the vault and restore the environment."""
        self.session.close()
        if self._old_data is None:
            os.environ.pop("XDG_DATA_HOME", None)
        else:
            os.environ["XDG_DATA_HOME"] = self._old_data

    def test_auto_path_mismatch_does_not_wipe(self) -> None:
        """A different model from the prefix/auto path leaves the index intact."""
        before = self.session.semantic_store.count_chunks()
        self.assertGreater(before, 0)
        self.session.set_semantic_provider(FixedProvider("m2", 3))
        result = self.session.index_semantics(
            force=True, paths={"a.md"}, refresh=False, allow_reset=False
        )
        self.assertFalse(result["ok"])
        self.assertEqual(self.session.semantic_store.count_chunks(), before)

    def test_explicit_rebuild_resets_with_snapshot(self) -> None:
        """An explicit rebuild resets, snapshots the old blob and records last_reset."""
        self.session.set_semantic_provider(FixedProvider("m2", 3))
        result = self.session.index_semantics(
            force=True, allow_reset=True, reason="test_reason"
        )
        self.assertTrue(result["reset"])
        self.assertEqual(result["last_reset"]["reason"], "test_reason")
        backup = pathlib.Path(str(self.session.semantic_db_path()) + ".bak")
        self.assertTrue(backup.exists())
        self.assertEqual(self.session.semantic_store.meta().get("model"), "m2")

    def test_missing_model_is_not_a_fallback(self) -> None:
        """An empty model name is ProviderUnavailable, never a default dimension."""
        with self.assertRaises(ProviderUnavailable):
            semantics.get_provider(
                {"semantic": {"enabled": True, "provider": "local", "model": ""}}
            )

    def test_auto_index_enqueues_instead_of_embedding(self) -> None:
        """Writing enqueues the path; it never embeds inline."""
        recorded: list[str] = []

        class Recorder:
            def enqueue(self, path: str) -> None:
                recorded.append(path)

            def stats(self) -> dict:
                return {"pending": len(recorded), "debounce_ms": 0, "last_error": None}

        self.session._semantic_queue = Recorder()  # type: ignore[assignment]
        self.session._auto_index_semantics("a.md")
        self.assertEqual(recorded, ["a.md"])


class SemanticQueueTest(unittest.TestCase):
    """The debounced worker coalesces duplicates and never blocks the writer."""

    def test_enqueue_is_fast_and_coalesced(self) -> None:
        """Fifty enqueues of one path become a single worker batch."""
        batches: list[set[str]] = []
        queue = SemanticIndexQueue(
            lambda paths: batches.append(set(paths)), debounce_ms=50, maxsize=10
        )
        try:
            start = time.monotonic()
            for _ in range(50):
                queue.enqueue("/a.md")
            self.assertLess(time.monotonic() - start, 1.0)
            deadline = time.monotonic() + 5.0
            while not batches and time.monotonic() < deadline:
                time.sleep(0.02)
        finally:
            queue.stop()
        self.assertEqual(batches, [{"/a.md"}])

    def test_queue_is_bounded(self) -> None:
        """The backlog drops the oldest paths when it overflows."""
        queue = SemanticIndexQueue(lambda paths: None, debounce_ms=10_000, maxsize=3)
        try:
            for index in range(10):
                queue.enqueue(f"/n{index}.md")
            self.assertEqual(queue.stats()["pending"], 3)
        finally:
            queue.stop()


if __name__ == "__main__":
    unittest.main()
