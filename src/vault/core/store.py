"""The encrypted content store ``secure.store`` (SPEC/01 §8).

The store is a single encrypted blob whose plaintext is a small SQLite database holding
the FTS5 content index, folder notes and embedding vectors. At unlock it is decrypted to
``<runtime_dir>/store.dec`` (mode 0600); every mutation calls :meth:`flush`, which
re-encrypts the database back into ``secure.store``; on close the decrypted file is removed.
"""

from __future__ import annotations

import atexit
import os
import re
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from ..config import runtime_dir as default_runtime_dir
from ..errors import NotFound
from ..util import atomic_write_bytes, normalize_fa, now_ms, sha256_hex
from .crypto import decrypt_blob, encrypt_blob

STORE_FILENAME = "secure.store"
STORE_BLOB_ID = "secure.store"

#: ``data:`` URIs (inline images) are gigabytes of base64 that no search should ever index.
#: Measured on a real vault: 31 MB of base64 produced a 253 MB store (136 MB of content +
#: 117 MB of index structures) because every base64 "word" became a unique token.
_DATA_URI_RE = re.compile(r"data:[a-zA-Z0-9.+/-]+;base64,[A-Za-z0-9+/=\s]{64,}")
#: Hard cap on how much of one file goes into the FTS index (characters).
MAX_INDEX_CHARS = 200_000


def indexable_text(text: str) -> str:
    """Return the searchable part of ``text``: no inline base64, no unbounded blobs."""
    cleaned = _DATA_URI_RE.sub(" ", text)
    if len(cleaned) > MAX_INDEX_CHARS:
        cleaned = cleaned[:MAX_INDEX_CHARS]
    return cleaned


def _dec_path(runtime: Path) -> Path:
    """Return a per-store-instance path for the decrypted store inside ``runtime``.

    The name is process- and instance-unique on purpose: two vault sessions in one process
    (a test, a second tool) or two processes must never share one decrypted database file —
    doing so lets one of them unlink the file the other still has open.
    """
    return Path(runtime) / f"store.{os.getpid()}.{uuid.uuid4().hex[:8]}.dec"


def cleanup_stale(runtime: Path, *, keep: Path | None = None) -> list[Path]:
    """Delete decrypted store files left behind by processes that are no longer alive.

    A killed process (SIGKILL, a crash, a ``timeout``) never reaches :meth:`SecureStore.close`,
    so its plaintext store would otherwise sit on the runtime tmpfs — and, after a big import,
    that can be hundreds of megabytes of readable notes. Files owned by a live process are
    kept (a second vault process is legitimate); ``keep`` is never touched.

    Returns the list of removed paths.
    """
    runtime = Path(runtime)
    removed: list[Path] = []
    if not runtime.is_dir():
        return removed
    for candidate in runtime.glob("store.*.dec"):
        if keep is not None and candidate == keep:
            continue
        parts = candidate.name.split(".")
        try:
            pid = int(parts[1]) if len(parts) > 2 else -1
        except (IndexError, ValueError):
            pid = -1
        if pid > 0 and pid != os.getpid():
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            except PermissionError:
                continue
            else:
                continue  # the owning process is alive — leave it alone
        if pid == os.getpid():
            continue  # a live store of ours (another instance in this process)
        try:
            candidate.unlink()
            removed.append(candidate)
        except FileNotFoundError:
            pass
    return removed

_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS fts_content USING fts5(
  body, file_id UNINDEXED, tokenize="unicode61 remove_diacritics 2");
CREATE TABLE IF NOT EXISTS content_meta(
  file_id INTEGER PRIMARY KEY, sha256 TEXT, indexed_at INTEGER);
CREATE TABLE IF NOT EXISTS folder_notes(
  folder_path TEXT PRIMARY KEY, note_text TEXT NOT NULL, updated_at INTEGER);
CREATE TABLE IF NOT EXISTS vectors(
  file_id INTEGER PRIMARY KEY, model TEXT NOT NULL, dim INTEGER NOT NULL, vec BLOB NOT NULL);
"""


class SecureStore:
    """Encrypted-at-rest SQLite store for searchable content, notes and vectors."""

    def __init__(
        self,
        home: Path,
        master_key: bytes,
        runtime: Path,
        dec_path: Path,
        conn: sqlite3.Connection,
    ) -> None:
        """Wrap an open decrypted database; use :meth:`create_new`/:meth:`open` instead."""
        self.home = Path(home)
        self.master_key = master_key
        self.runtime_dir = Path(runtime)
        self._dec_path = Path(dec_path)
        self._store_path = self.home / STORE_FILENAME
        self._conn: sqlite3.Connection | None = conn
        self._dirty = False
        atexit.register(self._remove_dec_on_exit)

    def _remove_dec_on_exit(self) -> None:
        """Best-effort removal of the decrypted store when the interpreter exits."""
        for suffix in ("", "-journal", "-wal", "-shm"):
            try:
                Path(str(self._dec_path) + suffix).unlink()
            except OSError:
                pass

    def mark_dirty(self) -> None:
        """Flag the store as mutated so the next :meth:`flush` rewrites the blob."""
        self._dirty = True

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def _connect(cls, dec_path: Path) -> sqlite3.Connection:
        """Open the decrypted SQLite database with plain (non-WAL) journaling."""
        # ``check_same_thread=False``: the socket API dispatches on handler threads; SQLite
        # is serialized in this environment and access is serialised by ``Service``.
        conn = sqlite3.connect(str(dec_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA)
        conn.commit()
        return conn

    @classmethod
    def create_new(
        cls, home: Path, master_key: bytes, *, sensitivity: str = "normal"
    ) -> "SecureStore":
        """Create a brand new (empty) store, write ``secure.store`` and return it open."""
        home = Path(home)
        home.mkdir(parents=True, exist_ok=True)
        runtime = default_runtime_dir()
        runtime.mkdir(parents=True, exist_ok=True)
        dec_path = _dec_path(runtime)
        cleanup_stale(runtime, keep=dec_path)
        conn = cls._connect(dec_path)
        try:
            os.chmod(dec_path, 0o600)
        except OSError:  # pragma: no cover - best effort
            pass
        store = cls(home, master_key, runtime, dec_path, conn)
        store.mark_dirty()
        store.flush()
        return store

    @classmethod
    def open(cls, home: Path, master_key: bytes, runtime_dir: Path) -> "SecureStore":
        """Decrypt ``secure.store`` into ``runtime_dir/store.dec`` and open it.

        Raises:
            NotFound: when ``secure.store`` does not exist.
            TamperDetected: when the store blob fails authentication.
        """
        home = Path(home)
        runtime = Path(runtime_dir)
        runtime.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(runtime, 0o700)
        except OSError:  # pragma: no cover
            pass
        store_path = home / STORE_FILENAME
        if not store_path.exists():
            raise NotFound("store_missing", details={"path": str(store_path)})
        blob = store_path.read_bytes()
        plaintext = decrypt_blob(master_key, STORE_BLOB_ID, blob, sensitivity="normal")
        dec_path = _dec_path(runtime)
        cleanup_stale(runtime, keep=dec_path)
        atomic_write_bytes(dec_path, plaintext)
        try:
            os.chmod(dec_path, 0o600)
        except OSError:  # pragma: no cover
            pass
        conn = cls._connect(dec_path)
        return cls(home, master_key, runtime, dec_path, conn)

    def flush(self) -> None:
        """Commit and re-encrypt the decrypted database back into ``secure.store``.

        Nothing is written when the store has not been mutated since the last flush: an
        unlock/lock cycle with no edits must not rewrite the blob, otherwise every open
        would push a fresh copy of it to the user's cloud folder.
        """
        if self._conn is None:
            return
        self._conn.commit()
        if not self._dirty:
            return
        plaintext = self._materialize_dec().read_bytes()
        blob = encrypt_blob(
            self.master_key, STORE_BLOB_ID, plaintext, sensitivity="normal"
        )
        atomic_write_bytes(self._store_path, blob)
        self._dirty = False

    def _materialize_dec(self) -> Path:
        """Return the decrypted DB path, rebuilding the file when it vanished.

        The decrypted file can disappear under us (a crashed peer, an aggressive cleaner).
        Recovering with ``VACUUM INTO`` keeps the live connection's data, so a flush never
        loses the user's notes just because a file was unlinked.
        """
        if self._dec_path.exists():
            return self._dec_path
        assert self._conn is not None
        rescue = self._dec_path.with_name(self._dec_path.name + ".rescue")
        if rescue.exists():
            rescue.unlink()
        self._conn.commit()
        self._conn.execute("VACUUM INTO ?", (str(rescue),))
        os.replace(rescue, self._dec_path)
        try:
            os.chmod(self._dec_path, 0o600)
        except OSError:  # pragma: no cover - best effort
            pass
        return self._dec_path

    def close(self) -> None:
        """Flush, close the connection and remove the decrypted file and its journals."""
        if self._conn is None:
            return
        try:
            self.flush()
        finally:
            self._conn.close()
            self._conn = None
            for suffix in ("", "-wal", "-shm", "-journal"):
                try:
                    Path(str(self._dec_path) + suffix).unlink()
                except FileNotFoundError:
                    pass

    @property
    def is_open(self) -> bool:
        """Whether the decrypted database is currently open."""
        return self._conn is not None

    # --------------------------------------------------------------- content index
    def index_text(self, file_id: int, text: str) -> None:
        """Replace the FTS row for ``file_id`` with the normalized form of ``text``.

        Only the searchable part is stored (see :func:`indexable_text`); the digest is taken over
        the *whole* text so a change is still detected.
        """
        if self._conn is None:
            raise NotFound("store_closed")
        normalized = normalize_fa(indexable_text(text))
        self._conn.execute("DELETE FROM fts_content WHERE rowid=?", (int(file_id),))
        self._conn.execute(
            "INSERT INTO fts_content(rowid, body, file_id) VALUES(?,?,?)",
            (int(file_id), normalized, int(file_id)),
        )
        digest = sha256_hex(text.encode("utf-8"))
        self._conn.execute(
            "INSERT INTO content_meta(file_id, sha256, indexed_at) VALUES(?,?,?) "
            "ON CONFLICT(file_id) DO UPDATE SET sha256=excluded.sha256, "
            "indexed_at=excluded.indexed_at",
            (int(file_id), digest, now_ms()),
        )
        self._dirty = True
        self._conn.commit()

    def remove_file(self, file_id: int) -> None:
        """Remove the FTS row, content metadata and vectors for ``file_id``."""
        if self._conn is None:
            return
        fid = int(file_id)
        self._conn.execute("DELETE FROM fts_content WHERE rowid=?", (fid,))
        self._conn.execute("DELETE FROM content_meta WHERE file_id=?", (fid,))
        self._conn.execute("DELETE FROM vectors WHERE file_id=?", (fid,))
        self._dirty = True
        self._conn.commit()

    def search_text(self, query: str, *, limit: int = 50) -> list[tuple[int, float]]:
        """Return ``(file_id, bm25_score)`` hits ordered by relevance (best first)."""
        if self._conn is None:
            return []
        normalized = normalize_fa(query)
        tokens = [tok for tok in normalized.split(" ") if tok]
        if not tokens:
            return []
        match = " ".join('"' + tok.replace('"', '""') + '"' for tok in tokens)
        rows = self._conn.execute(
            "SELECT rowid AS file_id, bm25(fts_content) AS score FROM fts_content "
            "WHERE fts_content MATCH ? ORDER BY score LIMIT ?",
            (match, int(limit)),
        ).fetchall()
        return [(int(r["file_id"]), float(r["score"])) for r in rows]

    def content_meta(self, file_id: int) -> dict[str, Any] | None:
        """Return the content metadata row for ``file_id`` or None."""
        if self._conn is None:
            return None
        row = self._conn.execute(
            "SELECT * FROM content_meta WHERE file_id=?", (int(file_id),)
        ).fetchone()
        return dict(row) if row is not None else None

    # ---------------------------------------------------------------- folder notes
    def set_folder_note(self, folder_path: str, text: str) -> None:
        """Insert or replace the note attached to a folder."""
        if self._conn is None:
            raise NotFound("store_closed")
        self._conn.execute(
            "INSERT INTO folder_notes(folder_path, note_text, updated_at) VALUES(?,?,?) "
            "ON CONFLICT(folder_path) DO UPDATE SET note_text=excluded.note_text, "
            "updated_at=excluded.updated_at",
            (folder_path, text, now_ms()),
        )
        self._dirty = True
        self._conn.commit()

    def get_folder_note(self, folder_path: str) -> str | None:
        """Return the note attached to ``folder_path`` or None."""
        if self._conn is None:
            return None
        row = self._conn.execute(
            "SELECT note_text FROM folder_notes WHERE folder_path=?", (folder_path,)
        ).fetchone()
        return str(row["note_text"]) if row is not None else None

    def all_folder_notes(self) -> list[dict[str, Any]]:
        """Return every folder note as a dict."""
        if self._conn is None:
            return []
        rows = self._conn.execute(
            "SELECT * FROM folder_notes ORDER BY folder_path"
        ).fetchall()
        return [dict(r) for r in rows]

    # --------------------------------------------------------------------- vectors
    def set_vector(self, file_id: int, model: str, vec: bytes) -> None:
        """Store a float32 embedding for ``file_id`` under ``model``."""
        if self._conn is None:
            raise NotFound("store_closed")
        self._conn.execute(
            "INSERT OR REPLACE INTO vectors(file_id, model, dim, vec) VALUES(?,?,?,?)",
            (int(file_id), model, len(vec) // 4, bytes(vec)),
        )
        self._dirty = True
        self._conn.commit()

    def get_vectors(self, model: str) -> list[tuple[int, bytes]]:
        """Return ``(file_id, vec)`` pairs stored for ``model``."""
        if self._conn is None:
            return []
        rows = self._conn.execute(
            "SELECT file_id, vec FROM vectors WHERE model=? ORDER BY file_id", (model,)
        ).fetchall()
        return [(int(r["file_id"]), bytes(r["vec"])) for r in rows]

    def clear_vectors(self) -> int:
        """Delete all vectors and return the number removed."""
        if self._conn is None:
            return 0
        cur = self._conn.execute("DELETE FROM vectors")
        self._dirty = True
        self._conn.commit()
        return int(cur.rowcount if cur.rowcount is not None else 0)

    def reset_index(self) -> int:
        """Drop every FTS row and content digest so the index can be rebuilt from scratch.

        Used by the "rebuild search index" action: a store written before data URIs were
        filtered still carries megabytes of base64 tokens that only a rebuild can reclaim.
        """
        if self._conn is None:
            return 0
        rows = int(self._conn.execute("SELECT COUNT(*) FROM fts_content").fetchone()[0])
        self._conn.execute("DELETE FROM fts_content")
        self._conn.execute("DELETE FROM content_meta")
        self._dirty = True
        self._conn.commit()
        return rows

    def vacuum(self) -> None:
        """Compact the decrypted database (reclaims the pages left by rewritten rows)."""
        if self._conn is None:
            return
        self._conn.commit()
        self._conn.execute("VACUUM")
        self._conn.commit()
        self._dirty = True

    # ----------------------------------------------------------------------- stats
    def stats(self) -> dict[str, Any]:
        """Return counts of FTS rows, notes and vectors plus the encrypted store size."""
        if self._conn is None:
            return {"fts_rows": 0, "notes": 0, "vectors": 0, "bytes": 0}
        fts = int(self._conn.execute("SELECT COUNT(*) FROM fts_content").fetchone()[0])
        notes = int(self._conn.execute("SELECT COUNT(*) FROM folder_notes").fetchone()[0])
        vectors = int(self._conn.execute("SELECT COUNT(*) FROM vectors").fetchone()[0])
        size = self._store_path.stat().st_size if self._store_path.exists() else 0
        return {"fts_rows": fts, "notes": notes, "vectors": vectors, "bytes": int(size)}


__all__ = ["SecureStore", "STORE_FILENAME", "STORE_BLOB_ID"]
