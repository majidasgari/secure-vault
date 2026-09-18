"""Content-addressed embedding cache (docs/SEMANTIC-VECTOR-CACHE.md).

The semantic index is derived data, but re-embedding unchanged text costs hours of CPU.
This cache keys every vector by ``HMAC(salt, model|dim|normalizer_version|sha256(text))``
so the same chunk is never embedded twice on this machine — for any model, any chunking
mode, and across index wipes.

The cache is unencrypted and machine-local (it holds only *derived* vectors and no vault
content), is never synced or backed up, and is fully rebuildable.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import struct
from pathlib import Path
from typing import Any

from ..config import user_data_dir
from ..util import now_ms

#: Bump whenever ``normalize_fa`` or ``chunk_text`` change output for the same input.
NORMALIZER_VERSION = 1

#: Default cache cap (prune LRU rows beyond it).
DEFAULT_MAX_BYTES = 512 * 1024 * 1024

#: SQLite's bound-parameter limit is 999; stay comfortably below it.
_BATCH = 900

#: Prune after this many inserts (in addition to pruning on open).
_PRUNE_EVERY = 2000

_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS vectors(
  key          BLOB PRIMARY KEY,
  vec          BLOB NOT NULL,
  dim          INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  hits         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS vectors_lru ON vectors(last_used_at);
"""


def _pack(vec: list[float]) -> bytes:
    """Pack a float vector into little-endian float32 (same format as the index)."""
    return struct.pack(f"<{len(vec)}f", *vec)


def _unpack(blob: bytes) -> list[float]:
    """Unpack little-endian float32 bytes into a float vector."""
    count = len(blob) // 4
    return list(struct.unpack(f"<{count}f", blob[: count * 4]))


def cache_dir() -> Path:
    """Return ``<user data dir>/semantic/cache`` (created on demand)."""
    path = user_data_dir() / "semantic" / "cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _slug(model: str) -> str:
    """Filesystem-safe slug for a model name (``BAAI/bge-m3`` → ``BAAI__bge-m3``)."""
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(model))
    return cleaned.replace("/", "__").strip("_") or "model"


class VectorCache:
    """Per-model, content-addressed SQLite cache of packed embedding vectors."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        model: str,
        dim: int,
        normalizer_version: int = NORMALIZER_VERSION,
        max_bytes: int = DEFAULT_MAX_BYTES,
        prune_on_open: bool = True,
    ) -> None:
        """Open (creating if needed) the cache for ``model``/``dim``."""
        self.model = str(model)
        self.dim = int(dim)
        self.normalizer_version = int(normalizer_version)
        self.max_bytes = int(max_bytes)
        self.path = Path(path) if path is not None else self.default_path(model, dim)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._hits = 0
        self._misses = 0
        self._inserts = 0
        self._warned = False
        self._used: set[bytes] = set()
        try:
            conn = sqlite3.connect(str(self.path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.executescript(_CACHE_SCHEMA)
            conn.commit()
            self._conn = conn
            self._salt = self._load_or_create_salt()
            if prune_on_open:
                self.prune()
        except sqlite3.Error as exc:  # pragma: no cover - corruption is a miss
            self._warn_once(f"vector cache open failed: {exc}")
            self._conn = None
            self._salt = b"\x00" * 32

    @staticmethod
    def default_path(model: str, dim: int) -> Path:
        """Return the documented per-model cache path."""
        return cache_dir() / f"{_slug(model)}__{int(dim)}.db"

    @classmethod
    def for_model(
        cls,
        model: str,
        dim: int,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        prune_on_open: bool = True,
    ) -> "VectorCache":
        """Open the cache for ``model``/``dim`` at its default location."""
        return cls(
            None, model=model, dim=dim, max_bytes=max_bytes, prune_on_open=prune_on_open
        )

    # ------------------------------------------------------------------ plumbing
    def _warn_once(self, message: str) -> None:
        """Log a cache problem once; a cache failure must never fail an index."""
        if self._warned:
            return
        self._warned = True
        import logging  # noqa: PLC0415 - keeps the module import light

        logging.getLogger(__name__).warning("vector cache: %s", message)

    def _load_or_create_salt(self) -> bytes:
        """Read the per-cache HMAC salt, generating it on first use."""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='salt'"
        ).fetchone()
        if row is not None:
            return bytes.fromhex(str(row["value"]))
        salt = secrets.token_bytes(32)
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('salt', ?)", (salt.hex(),)
        )
        self._conn.commit()
        return salt

    def key(self, text: str) -> bytes:
        """Return the 32-byte cache key for one chunk's text."""
        content = hashlib.sha256(str(text).encode("utf-8")).hexdigest()
        message = f"{self.model}|{self.dim}|{self.normalizer_version}|{content}"
        return hmac.new(self._salt, message.encode("utf-8"), hashlib.sha256).digest()

    def close(self) -> None:
        """Close the underlying connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:  # pragma: no cover
                pass
            self._conn = None

    # ------------------------------------------------------------------- lookup
    def lookup(self, texts: list[str]) -> dict[int, list[float]]:
        """Return ``{index_in_texts: vector}`` for every cache hit (batched)."""
        if self._conn is None or not texts:
            self._misses += len(texts)
            return {}
        keys = [self.key(text) for text in texts]
        index_of: dict[bytes, list[int]] = {}
        for position, key in enumerate(keys):
            index_of.setdefault(key, []).append(position)
        hits: dict[int, list[float]] = {}
        found: list[bytes] = []
        try:
            unique = list(dict.fromkeys(keys))
            for start in range(0, len(unique), _BATCH):
                batch = unique[start : start + _BATCH]
                marks = ",".join("?" * len(batch))
                rows = self._conn.execute(
                    f"SELECT key, vec FROM vectors WHERE key IN ({marks})", batch
                ).fetchall()
                for row in rows:
                    key = bytes(row["key"])
                    found.append(key)
                    vector = _unpack(bytes(row["vec"]))
                    for position in index_of.get(key, []):
                        hits[position] = vector
            if found:
                now = now_ms()
                self._conn.executemany(
                    "UPDATE vectors SET last_used_at=?, hits=hits+1 WHERE key=?",
                    [(now, key) for key in found],
                )
                self._conn.commit()
                self._used.update(found)
        except (sqlite3.Error, ValueError, struct.error) as exc:
            self._warn_once(f"lookup failed: {exc}")
            self._misses += len(texts)
            return {}
        self._hits += len(found)
        self._misses += len(texts) - len(found)
        return hits

    # -------------------------------------------------------------------- store
    def store(self, texts: list[str], vectors: list[list[float]]) -> int:
        """Insert/refresh vectors for ``texts`` in one transaction; return the count."""
        if self._conn is None or not texts:
            return 0
        now = now_ms()
        rows: list[tuple[Any, ...]] = []
        keys: list[bytes] = []
        for text, vector in zip(texts, vectors):
            key = self.key(text)
            keys.append(key)
            rows.append((key, _pack(list(vector)), len(vector), now, now))
        try:
            self._conn.executemany(
                "INSERT INTO vectors(key, vec, dim, created_at, last_used_at) "
                "VALUES(?,?,?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET vec=excluded.vec, "
                "last_used_at=excluded.last_used_at, hits=hits+1",
                rows,
            )
            self._conn.commit()
        except (sqlite3.Error, struct.error) as exc:
            self._warn_once(f"store failed: {exc}")
            return 0
        self._used.update(keys)
        self._inserts += len(rows)
        if self._inserts >= _PRUNE_EVERY:
            self._inserts = 0
            self.prune()
        return len(rows)

    # --------------------------------------------------------------------- stats
    def _size_bytes(self) -> int:
        """Return the on-disk size of the cache database."""
        try:
            return int(self.path.stat().st_size)
        except OSError:
            return 0

    def stats(self) -> dict[str, Any]:
        """Return entry/byte/hit statistics for the settings line."""
        entries = 0
        if self._conn is not None:
            try:
                entries = int(
                    self._conn.execute("SELECT COUNT(*) FROM vectors").fetchone()[0]
                )
            except sqlite3.Error:  # pragma: no cover
                entries = 0
        total = self._hits + self._misses
        return {
            "entries": entries,
            "bytes": self._size_bytes(),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": (self._hits / total) if total else 0.0,
            "path": str(self.path),
        }

    # -------------------------------------------------------------------- prune
    def prune(self, max_bytes: int | None = None, idle_days: int | None = None) -> int:
        """Evict rows to satisfy the byte cap (LRU) and/or an idle age cutoff.

        Rows used in the current run are never pruned. Returns the rows removed.
        """
        if self._conn is None:
            return 0
        target = int(max_bytes if max_bytes is not None else self.max_bytes)
        removed = 0
        try:
            if idle_days is not None:
                cutoff = now_ms() - int(idle_days) * 86_400_000
                cur = self._conn.execute(
                    "DELETE FROM vectors WHERE last_used_at < ?", (cutoff,)
                )
                removed += int(cur.rowcount or 0)
                self._conn.commit()
            guard = 0
            while self._size_bytes() > target and guard < 10_000:
                guard += 1
                rows = self._conn.execute(
                    "SELECT key FROM vectors ORDER BY last_used_at ASC LIMIT 500"
                ).fetchall()
                batch = [bytes(r["key"]) for r in rows if bytes(r["key"]) not in self._used]
                if not batch:
                    break
                marks = ",".join("?" * len(batch))
                cur = self._conn.execute(
                    f"DELETE FROM vectors WHERE key IN ({marks})", batch
                )
                removed += int(cur.rowcount or 0)
                self._conn.commit()
                try:
                    self._conn.execute("PRAGMA incremental_vacuum")
                except sqlite3.Error:  # pragma: no cover - optional
                    pass
        except sqlite3.Error as exc:
            self._warn_once(f"prune failed: {exc}")
        return removed

    def clear(self) -> int:
        """Delete every cached vector; return the number removed."""
        if self._conn is None:
            return 0
        try:
            cur = self._conn.execute("DELETE FROM vectors")
            self._conn.commit()
            return int(cur.rowcount or 0)
        except sqlite3.Error as exc:
            self._warn_once(f"clear failed: {exc}")
            return 0

    @classmethod
    def clear_all(cls) -> int:
        """Delete every per-model cache database; return the files removed."""
        removed = 0
        directory = cache_dir()
        for path in sorted(directory.glob("*.db*")):
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
        return removed


__all__ = [
    "VectorCache",
    "NORMALIZER_VERSION",
    "DEFAULT_MAX_BYTES",
    "cache_dir",
]
