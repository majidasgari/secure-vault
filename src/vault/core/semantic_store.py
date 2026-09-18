"""The separate encrypted semantic index ``semantic.db`` (SPEC/01 §11).

A small, self-contained SQLite database dedicated to the vector index. It is encrypted
at rest with the vault's master key (same scheme as ``secure.store``), decrypted to
``<runtime_dir>/semantic.<pid>.<rand>.dec`` while the vault is unlocked, and removed on
lock. Nearest-neighbour search is delegated to the embedded `sqlite-vec
<https://github.com/asg017/sqlite-vec>`_ extension: no server, no separate install, one
loadable library that the portable build can bundle.
"""

from __future__ import annotations

import atexit
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from ..config import runtime_dir as default_runtime_dir
from ..errors import NotFound, ProviderUnavailable
from ..util import atomic_write_bytes
from .crypto import decrypt_blob, encrypt_blob

SEMANTIC_BLOB_ID = "semantic.db"

_CHUNK_SCHEMA = """
CREATE TABLE IF NOT EXISTS semantic_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chunks(
  chunk_id INTEGER PRIMARY KEY,
  file_id INTEGER NOT NULL,
  ord INTEGER NOT NULL,
  text TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_semantic_chunks_file ON chunks(file_id);
"""


def _load_sqlite_vec(conn: sqlite3.Connection) -> None:
    """Load the embedded sqlite-vec extension into ``conn``.

    Raises:
        ProviderUnavailable: when the optional ``sqlite-vec`` package is not installed.
    """
    try:
        import sqlite_vec  # noqa: PLC0415 - optional, heavy-ish dependency
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ProviderUnavailable("install requirements-semantic.txt") from exc
    try:
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
    except (AttributeError, sqlite3.OperationalError, OSError) as exc:
        raise ProviderUnavailable(
            "sqlite_vec_load_failed", details={"error": str(exc)}
        ) from exc
    finally:
        try:
            conn.enable_load_extension(False)
        except sqlite3.OperationalError:  # pragma: no cover - older sqlite builds
            pass


def _dec_path(runtime: Path) -> Path:
    """Return a unique decrypted-database path inside ``runtime``."""
    return Path(runtime) / f"semantic.{os.getpid()}.{uuid.uuid4().hex[:8]}.dec"


def cleanup_stale(runtime: Path, *, keep: Path | None = None) -> list[Path]:
    """Delete ``semantic.*.dec`` files left behind by dead processes."""
    runtime = Path(runtime)
    removed: list[Path] = []
    if not runtime.is_dir():
        return removed
    for candidate in runtime.glob("semantic.*.dec"):
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
                continue
        if pid == os.getpid():
            continue
        try:
            candidate.unlink()
            removed.append(candidate)
        except FileNotFoundError:
            pass
    return removed


class SemanticStore:
    """Encrypted-at-rest SQLite database for the semantic chunk index."""

    def __init__(
        self,
        path: Path,
        master_key: bytes,
        runtime: Path,
        dec_path: Path,
        conn: sqlite3.Connection,
    ) -> None:
        """Wrap an open decrypted database; use :meth:`create_new`/:meth:`open`."""
        self.path = Path(path)
        self.master_key = master_key
        self.runtime_dir = Path(runtime)
        self._dec_path = Path(dec_path)
        self._store_path = self.path
        self._conn: sqlite3.Connection | None = conn
        self._dirty = False
        atexit.register(self._remove_dec_on_exit)

    def _remove_dec_on_exit(self) -> None:
        """Best-effort removal of the decrypted database at interpreter exit."""
        for suffix in ("", "-journal", "-wal", "-shm"):
            try:
                Path(str(self._dec_path) + suffix).unlink()
            except OSError:
                pass

    def mark_dirty(self) -> None:
        """Flag the database as mutated so the next :meth:`flush` rewrites the blob."""
        self._dirty = True

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def _connect(cls, dec_path: Path) -> sqlite3.Connection:
        """Open the decrypted database and load the sqlite-vec extension."""
        conn = sqlite3.connect(str(dec_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.executescript(_CHUNK_SCHEMA)
        conn.commit()
        _load_sqlite_vec(conn)
        return conn

    @classmethod
    def create_new(
        cls, path: Path, master_key: bytes, runtime_dir: Path | None = None
    ) -> "SemanticStore":
        """Create a brand new (empty) semantic database at ``path``."""
        store_path = Path(path)
        store_path.parent.mkdir(parents=True, exist_ok=True)
        runtime = Path(runtime_dir) if runtime_dir is not None else default_runtime_dir()
        runtime.mkdir(parents=True, exist_ok=True)
        dec_path = _dec_path(runtime)
        cleanup_stale(runtime, keep=dec_path)
        conn = cls._connect(dec_path)
        try:
            os.chmod(dec_path, 0o600)
        except OSError:  # pragma: no cover - best effort
            pass
        store = cls(store_path, master_key, runtime, dec_path, conn)
        store.mark_dirty()
        store.flush()
        return store

    @classmethod
    def open(cls, path: Path, master_key: bytes, runtime_dir: Path) -> "SemanticStore":
        """Decrypt ``path`` into ``runtime_dir`` and open it.

        Raises:
            NotFound: when the encrypted file does not exist.
            ProviderUnavailable: when ``sqlite-vec`` is not installed.
            TamperDetected: when the blob fails authentication.
        """
        store_path = Path(path)
        runtime = Path(runtime_dir)
        runtime.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(runtime, 0o700)
        except OSError:  # pragma: no cover
            pass
        if not store_path.exists():
            raise NotFound("semantic_store_missing", details={"path": str(store_path)})
        blob = store_path.read_bytes()
        plaintext = decrypt_blob(master_key, SEMANTIC_BLOB_ID, blob, sensitivity="normal")
        dec_path = _dec_path(runtime)
        cleanup_stale(runtime, keep=dec_path)
        atomic_write_bytes(dec_path, plaintext)
        try:
            os.chmod(dec_path, 0o600)
        except OSError:  # pragma: no cover
            pass
        conn = cls._connect(dec_path)
        return cls(store_path, master_key, runtime, dec_path, conn)

    def flush(self) -> None:
        """Commit and re-encrypt the decrypted database back into ``semantic.db``."""
        if self._conn is None:
            return
        self._conn.commit()
        if not self._dirty:
            return
        plaintext = self._materialize_dec().read_bytes()
        blob = encrypt_blob(
            self.master_key, SEMANTIC_BLOB_ID, plaintext, sensitivity="normal"
        )
        atomic_write_bytes(self._store_path, blob)
        self._dirty = False

    def _materialize_dec(self) -> Path:
        """Return the decrypted DB path, rebuilding it via ``VACUUM INTO`` if removed."""
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

    def _require_conn(self) -> sqlite3.Connection:
        """Return the connection or raise :class:`NotFound`."""
        if self._conn is None:
            raise NotFound("semantic_store_closed")
        return self._conn

    # --------------------------------------------------------------- meta / layout
    def meta(self) -> dict[str, str]:
        """Return the layout metadata (model, dim, chunking)."""
        conn = self._require_conn()
        rows = conn.execute("SELECT key, value FROM semantic_meta").fetchall()
        return {str(r["key"]): str(r["value"]) for r in rows}

    def _set_meta(self, key: str, value: str) -> None:
        conn = self._require_conn()
        conn.execute(
            "INSERT INTO semantic_meta(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def _vec_exists(self) -> bool:
        conn = self._require_conn()
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vec_chunks'"
        ).fetchone()
        return row is not None

    def ensure_layout(self, model: str, dim: int, chunking: str) -> None:
        """Make the index match ``(model, dim, chunking)``, wiping it on any change."""
        current = self.meta()
        if (
            current.get("model") == model
            and current.get("dim") == str(int(dim))
            and current.get("chunking") == chunking
            and self._vec_exists()
        ):
            return
        self.reset()
        self._set_meta("model", model)
        self._set_meta("dim", str(int(dim)))
        self._set_meta("chunking", chunking)
        self._require_conn().execute(
            "CREATE VIRTUAL TABLE vec_chunks USING vec0("
            f"chunk_id INTEGER PRIMARY KEY, embedding float[{int(dim)}] "
            "distance_metric=cosine)"
        )
        self._dirty = True
        self._require_conn().commit()

    def has_layout(self, model: str) -> bool:
        """Whether a usable index exists for ``model``."""
        return self.meta().get("model") == model and self._vec_exists()

    def reset(self) -> None:
        """Drop every chunk and vector, keeping the database itself."""
        conn = self._require_conn()
        if self._vec_exists():
            conn.execute("DROP TABLE vec_chunks")
        conn.execute("DELETE FROM chunks")
        conn.execute("DELETE FROM semantic_meta")
        self._dirty = True
        conn.commit()

    # --------------------------------------------------------------------- writes
    def replace_file(self, file_id: int, chunks: list[str], vectors: list[bytes]) -> int:
        """Replace every chunk of ``file_id`` with the given texts and packed vectors."""
        conn = self._require_conn()
        fid = int(file_id)
        self._delete_rows(conn, fid)
        for ord_, (text, blob) in enumerate(zip(chunks, vectors, strict=True)):
            cur = conn.execute(
                "INSERT INTO chunks(file_id, ord, text) VALUES(?,?,?)", (fid, ord_, text)
            )
            conn.execute(
                "INSERT INTO vec_chunks(chunk_id, embedding) VALUES(?,?)",
                (int(cur.lastrowid), bytes(blob)),
            )
        self._dirty = True
        conn.commit()
        return len(chunks)

    def delete_file(self, file_id: int) -> int:
        """Remove every chunk and vector for ``file_id``; return the number removed."""
        return self.delete_files([int(file_id)])

    def delete_files(self, file_ids: Any) -> int:
        """Remove the chunks/vectors of several files in one transaction.

        Returns the number of chunks removed.
        """
        conn = self._require_conn()
        ids = [int(fid) for fid in file_ids]
        if not ids:
            return 0
        marks = ",".join("?" * len(ids))
        rows = conn.execute(
            f"SELECT chunk_id FROM chunks WHERE file_id IN ({marks})", ids
        ).fetchall()
        if rows:
            conn.executemany(
                "DELETE FROM vec_chunks WHERE chunk_id=?",
                [(int(r["chunk_id"]),) for r in rows],
            )
        conn.execute(f"DELETE FROM chunks WHERE file_id IN ({marks})", ids)
        self._dirty = True
        conn.commit()
        return len(rows)

    def _delete_rows(self, conn: sqlite3.Connection, file_id: int) -> int:
        """Delete a file's chunk/vector rows without committing."""
        rows = conn.execute(
            "SELECT chunk_id FROM chunks WHERE file_id=?", (file_id,)
        ).fetchall()
        for row in rows:
            conn.execute("DELETE FROM vec_chunks WHERE chunk_id=?", (int(row["chunk_id"]),))
        conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
        return len(rows)

    def add_chunks(self, rows: list[tuple[int, int, str, bytes]]) -> int:
        """Insert many ``(file_id, ord, text, packed_vector)`` rows in one transaction.

        Callers must have deleted the file's previous rows first (see
        :meth:`delete_files`); this only appends, so it can span several files.
        """
        if not rows:
            return 0
        conn = self._require_conn()
        for file_id, ord_, text, blob in rows:
            cur = conn.execute(
                "INSERT INTO chunks(file_id, ord, text) VALUES(?,?,?)",
                (int(file_id), int(ord_), str(text)),
            )
            conn.execute(
                "INSERT INTO vec_chunks(chunk_id, embedding) VALUES(?,?)",
                (int(cur.lastrowid), bytes(blob)),
            )
        self._dirty = True
        conn.commit()
        return len(rows)

    # --------------------------------------------------------------------- reads
    def indexed_files(self) -> set[int]:
        """Return the file ids that currently have at least one chunk."""
        conn = self._require_conn()
        rows = conn.execute("SELECT DISTINCT file_id FROM chunks").fetchall()
        return {int(r["file_id"]) for r in rows}

    def search(self, query_blob: bytes, model: str, *, k: int = 50) -> list[dict[str, Any]]:
        """Return up to ``k`` nearest chunks as ``{file_id, ord, text, score}``.

        ``score`` is cosine similarity in ``[-1, 1]`` (higher is better).
        """
        if not self.has_layout(model):
            return []
        conn = self._require_conn()
        rows = conn.execute(
            "SELECT v.chunk_id AS chunk_id, c.file_id AS file_id, c.ord AS ord, "
            "c.text AS text, v.distance AS distance "
            "FROM vec_chunks v JOIN chunks c ON c.chunk_id = v.chunk_id "
            "WHERE v.embedding MATCH ? AND k = ? ORDER BY v.distance",
            (bytes(query_blob), int(max(1, k))),
        ).fetchall()
        return [
            {
                "file_id": int(r["file_id"]),
                "ord": int(r["ord"]),
                "text": str(r["text"]),
                "score": 1.0 - float(r["distance"]),
            }
            for r in rows
        ]

    def chunk_texts(self) -> list[str]:
        """Return every stored chunk text (for stats/diagnostics)."""
        conn = self._require_conn()
        rows = conn.execute("SELECT text FROM chunks ORDER BY file_id, ord").fetchall()
        return [str(r["text"]) for r in rows]

    def count_chunks(self) -> int:
        """Return the number of indexed chunks."""
        conn = self._require_conn()
        return int(conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0])

    def count_files(self) -> int:
        """Return the number of files that have at least one chunk."""
        conn = self._require_conn()
        return int(
            conn.execute("SELECT COUNT(DISTINCT file_id) FROM chunks").fetchone()[0]
        )

    def stats(self) -> dict[str, Any]:
        """Return chunk/file counts, the layout and the encrypted file size."""
        meta = self.meta()
        size = self._store_path.stat().st_size if self._store_path.exists() else 0
        return {
            "chunks": self.count_chunks(),
            "files": self.count_files(),
            "model": meta.get("model"),
            "chunking": meta.get("chunking"),
            "bytes": int(size),
        }


__all__ = ["SemanticStore", "SEMANTIC_BLOB_ID", "cleanup_stale"]
