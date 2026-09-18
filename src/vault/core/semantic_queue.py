"""A small debounced worker for auto-indexing written paths (SPEC/01 §11).

Running the embedder inline on the write path locked the app for minutes and starved the
socket server. Writing now only *enqueues* a path; a single background thread coalesces
repeated paths, waits out a short debounce window, and re-embeds the batch off-thread.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable

#: Wait this long after the last enqueue before running (a bulk write settles first).
DEFAULT_DEBOUNCE_MS = 3000

#: Bounded backlog: the oldest paths are dropped when it overflows.
DEFAULT_MAXSIZE = 500


class SemanticIndexQueue:
    """Single-thread, debounced, coalescing queue of logical paths to re-embed."""

    def __init__(
        self,
        worker: Callable[[set[str]], None],
        *,
        debounce_ms: int = DEFAULT_DEBOUNCE_MS,
        maxsize: int = DEFAULT_MAXSIZE,
    ) -> None:
        """Create the queue; the worker runs with a batch of logical paths."""
        self._worker = worker
        self._debounce = max(0.0, int(debounce_ms) / 1000.0)
        self._maxsize = max(1, int(maxsize))
        self._pending: "OrderedDict[str, None]" = OrderedDict()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_error: str | None = None

    def enqueue(self, path: str) -> None:
        """Schedule ``path`` (coalesced); starts the worker on first use."""
        logical = str(path)
        with self._lock:
            self._pending.pop(logical, None)  # last write wins
            self._pending[logical] = None
            while len(self._pending) > self._maxsize:
                self._pending.popitem(last=False)
            if self._thread is None and not self._stop.is_set():
                self._thread = threading.Thread(
                    target=self._run, name="vault-semantic-index", daemon=True
                )
                self._thread.start()
        self._wake.set()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the worker and drop any pending paths."""
        self._stop.set()
        self._wake.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=timeout)
        with self._lock:
            self._pending.clear()

    def _settle(self) -> None:
        """Block through the debounce window, extending it while writes keep arriving."""
        deadline = time.monotonic() + self._debounce
        while not self._stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self._wake.wait(timeout=remaining)
            if not self._wake.is_set():
                return
            self._wake.clear()
            deadline = time.monotonic() + self._debounce

    def _run(self) -> None:
        """Worker loop: wait for work, settle, then run the batch."""
        while not self._stop.is_set():
            self._wake.wait(timeout=1.0)
            if self._stop.is_set():
                return
            if not self._wake.is_set():
                continue
            self._wake.clear()
            self._settle()
            if self._stop.is_set():
                return
            with self._lock:
                batch = set(self._pending)
                self._pending.clear()
            if not batch:
                continue
            try:
                self._worker(batch)
            except Exception as exc:  # noqa: BLE001 - best effort, never crash the app
                self._last_error = str(exc)

    def stats(self) -> dict[str, Any]:
        """Return queue depth, debounce and the last worker error."""
        with self._lock:
            pending = len(self._pending)
        return {
            "pending": pending,
            "debounce_ms": int(self._debounce * 1000),
            "last_error": self._last_error,
        }


__all__ = ["SemanticIndexQueue", "DEFAULT_DEBOUNCE_MS", "DEFAULT_MAXSIZE"]
