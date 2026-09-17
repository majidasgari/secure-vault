"""The plaintext ``meta.sqlite`` metadata index (SPEC/01 §6).

This DB deliberately contains only names, levels, tags and the append-only access log —
never file content, folder-note text or FTS rows (the tests scan it for plaintext markers).
"""

from __future__ import annotations

import csv
import io
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..errors import AlreadyExists, BadRequest, NotFound
from ..util import atomic_write_bytes, normalize_logical_path, now_ms
from .security import LEVELS

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY,
  logical_path TEXT NOT NULL UNIQUE COLLATE NOCASE,
  blob_id TEXT,
  is_dir INTEGER NOT NULL DEFAULT 0,
  size INTEGER NOT NULL DEFAULT 0,
  encrypted INTEGER NOT NULL DEFAULT 1,
  sensitivity TEXT NOT NULL DEFAULT 'normal'
      CHECK(sensitivity IN ('normal','secret','secretfile')),
  mtime INTEGER NOT NULL,
  created INTEGER NOT NULL,
  source TEXT NOT NULL DEFAULT 'ui'
);
CREATE INDEX IF NOT EXISTS idx_files_parent ON files(logical_path);
CREATE TABLE IF NOT EXISTS tags(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS file_tags(
  file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY(file_id, tag_id)
);
CREATE TABLE IF NOT EXISTS access_log(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL,
  role TEXT NOT NULL, tool TEXT NOT NULL, target_path TEXT, outcome TEXT NOT NULL,
  code TEXT, details TEXT, session TEXT
);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT);
"""


def _parent_of(logical_path: str) -> str:
    """Return the parent logical path (``"/"`` for a top-level entry)."""
    if logical_path == "/":
        return "/"
    parent, _, _ = logical_path.rpartition("/")
    return parent or "/"


class Index:
    """SQLite-backed metadata index with normalized logical paths."""

    def __init__(self, path: Path) -> None:
        """Open (creating/migrating as needed) the metadata DB at ``path``."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # The socket API serves requests on per-connection threads; SQLite is compiled in
        # serialized mode here (``sqlite3.threadsafety == 3``) so one shared connection is
        # safe. Callers serialise logical access through ``Service``.
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self._conn.commit()

    # ------------------------------------------------------------------ plumbing
    @property
    def conn(self) -> sqlite3.Connection:
        """The underlying sqlite connection (used by tests and later phases)."""
        return self._conn

    def close(self) -> None:
        """Close the underlying database connection."""
        try:
            self._conn.close()
        except sqlite3.Error:  # pragma: no cover - already closed
            pass

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        """Convert a sqlite row into a plain dict (or None)."""
        return dict(row) if row is not None else None

    @staticmethod
    def _norm(logical_path: str) -> str:
        """Normalize a logical path, mapping the empty string to the root."""
        return normalize_logical_path(logical_path)

    def _children(self, logical_path: str) -> list[sqlite3.Row]:
        """Return direct children rows of a canonical directory path."""
        if logical_path == "/":
            cur = self._conn.execute(
                "SELECT * FROM files WHERE instr(logical_path,'/')=0 "
                "ORDER BY is_dir DESC, logical_path COLLATE NOCASE"
            )
        else:
            prefix = logical_path + "/"
            cur = self._conn.execute(
                "SELECT * FROM files WHERE substr(logical_path,1,?)=? "
                "AND instr(substr(logical_path,?+1),'/')=0 "
                "ORDER BY is_dir DESC, logical_path COLLATE NOCASE",
                (len(prefix), prefix, len(prefix)),
            )
        return list(cur.fetchall())

    # --------------------------------------------------------------------- files
    def upsert_file(
        self,
        logical_path: str,
        *,
        blob_id: str | None = None,
        is_dir: bool = False,
        size: int = 0,
        encrypted: int = 1,
        sensitivity: str = "normal",
        mtime: int | None = None,
        created: int | None = None,
        source: str = "ui",
    ) -> int:
        """Insert or update a file/directory row and return its id."""
        path = self._norm(logical_path)
        if sensitivity not in LEVELS:
            raise BadRequest("unknown_level", details={"level": sensitivity})
        now = now_ms()
        existing = self._conn.execute(
            "SELECT id, created FROM files WHERE logical_path=? COLLATE NOCASE", (path,)
        ).fetchone()
        if existing is None:
            cur = self._conn.execute(
                "INSERT INTO files(logical_path, blob_id, is_dir, size, encrypted, "
                "sensitivity, mtime, created, source) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    path,
                    blob_id,
                    int(bool(is_dir)),
                    int(size),
                    int(encrypted),
                    sensitivity,
                    int(mtime if mtime is not None else now),
                    int(created if created is not None else now),
                    source,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)
        created_value = int(created if created is not None else existing["created"])
        self._conn.execute(
            "UPDATE files SET blob_id=?, is_dir=?, size=?, encrypted=?, sensitivity=?, "
            "mtime=?, created=?, source=? WHERE id=?",
            (
                blob_id,
                int(bool(is_dir)),
                int(size),
                int(encrypted),
                sensitivity,
                int(mtime if mtime is not None else now),
                created_value,
                source,
                existing["id"],
            ),
        )
        self._conn.commit()
        return int(existing["id"])

    def get_file(self, logical_path: str) -> dict[str, Any] | None:
        """Return the row for ``logical_path`` or None when absent."""
        path = self._norm(logical_path)
        row = self._conn.execute(
            "SELECT * FROM files WHERE logical_path=? COLLATE NOCASE", (path,)
        ).fetchone()
        return self._row(row)

    def get_file_by_id(self, file_id: int) -> dict[str, Any] | None:
        """Return the row with primary key ``file_id`` or None when absent."""
        row = self._conn.execute("SELECT * FROM files WHERE id=?", (int(file_id),)).fetchone()
        return self._row(row)

    def require_file(self, logical_path: str) -> dict[str, Any]:
        """Like :meth:`get_file` but raises :class:`NotFound` when absent."""
        row = self.get_file(logical_path)
        if row is None:
            raise NotFound("path_not_found", details={"path": logical_path})
        return row

    def delete_file(self, logical_path: str, *, recursive: bool = False) -> list[dict[str, Any]]:
        """Delete a row (and, when ``recursive``, its descendants); return removed rows."""
        path = self._norm(logical_path)
        row = self.require_file(path)
        if path == "/":
            raise BadRequest("cannot_delete_root")
        if int(row["is_dir"]) and not recursive:
            if self._children(path):
                raise BadRequest("directory_not_empty", details={"path": path})
        if recursive:
            prefix = path + "/"
            cur = self._conn.execute(
                "SELECT * FROM files WHERE logical_path=? COLLATE NOCASE "
                "OR substr(logical_path,1,?)=? COLLATE NOCASE ORDER BY logical_path",
                (path, len(prefix), prefix),
            )
            rows = [self._row(r) for r in cur.fetchall()]
        else:
            rows = [row]
        ids = [int(r["id"]) for r in rows if r is not None]
        if ids:
            placeholders = ",".join("?" for _ in ids)
            self._conn.execute(f"DELETE FROM files WHERE id IN ({placeholders})", ids)
            self._conn.commit()
        return [r for r in rows if r is not None]

    def list_dir(self, logical_path: str) -> list[dict[str, Any]]:
        """Return the direct children of a directory, directories first, name-sorted."""
        path = self._norm(logical_path)
        if path != "/":
            row = self.get_file(path)
            if row is None or not int(row["is_dir"]):
                raise NotFound("directory_not_found", details={"path": logical_path})
            path = row["logical_path"]
        return [self._row(r) for r in self._children(path) if r is not None]

    def walk(self, logical_path: str = "/") -> Iterator[dict[str, Any]]:
        """Yield every row at or below ``logical_path`` in path order."""
        path = self._norm(logical_path)
        if path != "/":
            row = self.get_file(path)
            if row is None:
                raise NotFound("path_not_found", details={"path": logical_path})
            path = row["logical_path"]
            prefix = path + "/"
            cur = self._conn.execute(
                "SELECT * FROM files WHERE logical_path=? COLLATE NOCASE "
                "OR substr(logical_path,1,?)=? COLLATE NOCASE ORDER BY logical_path",
                (path, len(prefix), prefix),
            )
        else:
            cur = self._conn.execute("SELECT * FROM files ORDER BY logical_path")
        for row in cur.fetchall():
            yield self._row(row)  # type: ignore[misc]

    def move(self, src: str, dst: str) -> None:
        """Move ``src`` to ``dst``, rewriting descendant paths."""
        source = self._norm(src)
        dest = self._norm(dst)
        if source == "/":
            raise BadRequest("cannot_move_root")
        self.require_file(source)
        if self.get_file(dest) is not None:
            raise AlreadyExists("destination_exists", details={"path": dest})
        if dest == source or dest.startswith(source + "/"):
            raise BadRequest("cannot_move_into_itself", details={"src": source, "dst": dest})
        prefix = source + "/"
        cur = self._conn.execute(
            "SELECT id, logical_path FROM files WHERE logical_path=? COLLATE NOCASE "
            "OR substr(logical_path,1,?)=? COLLATE NOCASE ORDER BY length(logical_path)",
            (source, len(prefix), prefix),
        )
        updates = []
        for row in cur.fetchall():
            old = row["logical_path"]
            new = dest + old[len(source):]
            updates.append((new, int(row["id"])))
        for new, row_id in updates:
            self._conn.execute("UPDATE files SET logical_path=? WHERE id=?", (new, row_id))
        self._conn.commit()

    def count(self) -> dict[str, Any]:
        """Return ``{"files", "dirs", "by_level"}`` counts."""
        files = self._conn.execute("SELECT COUNT(*) FROM files WHERE is_dir=0").fetchone()[0]
        dirs = self._conn.execute("SELECT COUNT(*) FROM files WHERE is_dir=1").fetchone()[0]
        by_level = {level: 0 for level in LEVELS}
        for row in self._conn.execute(
            "SELECT sensitivity, COUNT(*) AS n FROM files GROUP BY sensitivity"
        ).fetchall():
            by_level[row["sensitivity"]] = int(row["n"])
        return {"files": int(files), "dirs": int(dirs), "by_level": by_level}

    # -------------------------------------------------------------------- levels
    def set_sensitivity(self, logical_path: str, level: str) -> None:
        """Update the sensitivity level of an existing row."""
        if level not in LEVELS:
            raise BadRequest("unknown_level", details={"level": level})
        path = self._norm(logical_path)
        self.require_file(path)
        self._conn.execute(
            "UPDATE files SET sensitivity=? WHERE logical_path=? COLLATE NOCASE",
            (level, path),
        )
        self._conn.commit()

    def sensitive_paths(self, level: str | None = None) -> list[str]:
        """Return paths that are ``secret``/``secretfile`` (or exactly ``level``)."""
        if level is None:
            cur = self._conn.execute(
                "SELECT logical_path FROM files WHERE sensitivity!='normal' "
                "ORDER BY logical_path"
            )
        else:
            if level not in LEVELS:
                raise BadRequest("unknown_level", details={"level": level})
            cur = self._conn.execute(
                "SELECT logical_path FROM files WHERE sensitivity=? ORDER BY logical_path",
                (level,),
            )
        return [str(r["logical_path"]) for r in cur.fetchall()]

    # ---------------------------------------------------------------------- tags
    def set_tags(self, logical_path: str, tags: list[str]) -> None:
        """Replace the tag set of a file."""
        path = self._norm(logical_path)
        row = self.require_file(path)
        file_id = int(row["id"])
        self._conn.execute("DELETE FROM file_tags WHERE file_id=?", (file_id,))
        seen: set[str] = set()
        for tag in tags:
            name = str(tag).strip()
            if not name or name in seen:
                continue
            seen.add(name)
            self._conn.execute("INSERT OR IGNORE INTO tags(name) VALUES(?)", (name,))
            tag_row = self._conn.execute(
                "SELECT id FROM tags WHERE name=?", (name,)
            ).fetchone()
            self._conn.execute(
                "INSERT OR IGNORE INTO file_tags(file_id, tag_id) VALUES(?,?)",
                (file_id, int(tag_row["id"])),
            )
        self._conn.commit()

    def get_tags(self, logical_path: str) -> list[str]:
        """Return the sorted tags of a file."""
        path = self._norm(logical_path)
        row = self.require_file(path)
        cur = self._conn.execute(
            "SELECT t.name FROM tags t JOIN file_tags ft ON ft.tag_id=t.id "
            "WHERE ft.file_id=? ORDER BY t.name COLLATE NOCASE",
            (int(row["id"]),),
        )
        return [str(r["name"]) for r in cur.fetchall()]

    def files_by_tag(self, tag: str) -> list[dict[str, Any]]:
        """Return all file rows carrying ``tag``."""
        cur = self._conn.execute(
            "SELECT f.* FROM files f JOIN file_tags ft ON ft.file_id=f.id "
            "JOIN tags t ON t.id=ft.tag_id WHERE t.name=? ORDER BY f.logical_path",
            (tag,),
        )
        return [self._row(r) for r in cur.fetchall()]  # type: ignore[misc]

    def all_tags(self) -> list[dict[str, Any]]:
        """Return every tag with its usage count."""
        cur = self._conn.execute(
            "SELECT t.id AS id, t.name AS name, COUNT(ft.file_id) AS count "
            "FROM tags t LEFT JOIN file_tags ft ON ft.tag_id=t.id "
            "GROUP BY t.id, t.name ORDER BY t.name COLLATE NOCASE"
        )
        return [dict(r) for r in cur.fetchall()]

    # ----------------------------------------------------------------------- log
    def log_access(
        self,
        *,
        source: str,
        role: str,
        tool: str,
        target_path: str | None = None,
        outcome: str,
        code: str | None = None,
        details: str | None = None,
        session: str | None = None,
    ) -> None:
        """Append one access-log row (append-only: never updated or deleted)."""
        self._conn.execute(
            "INSERT INTO access_log(ts, source, role, tool, target_path, outcome, code, "
            "details, session) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                now_ms(),
                source,
                role,
                tool,
                target_path,
                outcome,
                code,
                details,
                session,
            ),
        )
        self._conn.commit()

    def access_log(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        source: str | None = None,
        outcome: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return access-log rows, newest first, with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if source is not None:
            clauses.append("source=?")
            params.append(source)
        if outcome is not None:
            clauses.append("outcome=?")
            params.append(outcome)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.extend([int(limit), int(offset)])
        cur = self._conn.execute(
            f"SELECT * FROM access_log{where} ORDER BY id DESC LIMIT ? OFFSET ?", params
        )
        return [dict(r) for r in cur.fetchall()]

    def access_log_count(self) -> int:
        """Return the total number of access-log rows."""
        return int(self._conn.execute("SELECT COUNT(*) FROM access_log").fetchone()[0])

    def export_access_log_csv(self, dest: Path) -> int:
        """Write the full access log as CSV to ``dest`` atomically; return the row count."""
        rows = self._conn.execute("SELECT * FROM access_log ORDER BY id").fetchall()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            ["id", "ts", "source", "role", "tool", "target_path", "outcome", "code",
             "details", "session"]
        )
        for row in rows:
            writer.writerow([row[key] for key in row.keys()])
        atomic_write_bytes(Path(dest), buffer.getvalue().encode("utf-8"))
        return len(rows)

    # ------------------------------------------------------------------------ kv
    def kv_get(self, key: str, default: Any = None) -> Any:
        """Return the value stored under ``key`` or ``default``."""
        row = self._conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return row["value"] if row is not None else default

    def kv_set(self, key: str, value: str) -> None:
        """Store ``value`` under ``key`` (insert or replace)."""
        self._conn.execute(
            "INSERT INTO kv(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self._conn.commit()


__all__ = ["Index", "SCHEMA_VERSION"]
