"""Server-Sent Events fan-out for the web UI (SPEC/07 §3).

A tiny in-process pub/sub bus. Each open ``/api/events`` connection owns a
:class:`Subscription` backed by a bounded queue; publishers never block (a full
queue drops the event for that slow subscriber). Events are plain JSON objects of
the shape ``{"event": "log" | "lock" | "unlock" | "secret_request" | "data_changed"
| "ping", ...}``.
"""

from __future__ import annotations

import queue
import threading
from typing import Any

from ..util import now_ms

DEFAULT_QUEUE_SIZE = 256


class Subscription:
    """One SSE consumer's bounded event queue."""

    def __init__(self, maxsize: int = DEFAULT_QUEUE_SIZE) -> None:
        """Create the queue with room for ``maxsize`` pending events."""
        self.queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=maxsize)
        self._closed = False

    @property
    def closed(self) -> bool:
        """True once the subscription has been released."""
        return self._closed

    def get(self, timeout: float) -> dict[str, Any]:
        """Block up to ``timeout`` seconds for the next event."""
        return self.queue.get(timeout=timeout)

    def close(self) -> None:
        """Mark the subscription closed (the queue is simply dropped)."""
        self._closed = True


class EventBus:
    """Thread-safe fan-out of server events to every SSE subscriber."""

    def __init__(self) -> None:
        """Create an empty bus."""
        self._subs: set[Subscription] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> Subscription:
        """Register and return a new subscription."""
        sub = Subscription()
        with self._lock:
            self._subs.add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        """Release ``sub`` and drop it from the fan-out set."""
        sub.close()
        with self._lock:
            self._subs.discard(sub)

    def subscriber_count(self) -> int:
        """Return the number of currently open subscriptions."""
        with self._lock:
            return len(self._subs)

    def publish(self, event: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        """Broadcast one event; returns the payload that was queued."""
        payload: dict[str, Any] = {"event": event, "ts": now_ms()}
        if data:
            payload.update(data)
        with self._lock:
            subs = list(self._subs)
        for sub in subs:
            try:
                sub.queue.put_nowait(payload)
            except queue.Full:  # pragma: no cover - only a stalled subscriber
                pass
        return payload


__all__ = ["EventBus", "Subscription"]
