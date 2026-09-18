"""The three independent searches (SPEC/01 §10).

Filenames, literal content and semantic results are never mixed or re-ranked across
kinds. Filename search sees names (including secret levels); content and semantic search
only ever see ``normal`` files.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from ..errors import BadRequest
from ..util import normalize_fa, normalize_vault_path
from . import semantics
from .security import Policy

MAX_SNIPPET = 240


class SearchKind(StrEnum):
    """The three search kinds, kept deliberately separate."""

    FILENAME = "filename"
    TEXT = "text"
    SEMANTIC = "semantic"


def _result(row: dict[str, Any], match: str) -> dict[str, Any]:
    """Build the common result dict for a metadata row."""
    return {
        "logical_path": row["logical_path"],
        "is_dir": bool(row["is_dir"]),
        "sensitivity": row["sensitivity"],
        "size": int(row["size"]),
        "mtime": int(row["mtime"]),
        "match": match,
    }


def search_filenames(
    session: Any,
    query: str,
    *,
    limit: int = 50,
    include_secret: bool = True,
    path_prefix: str | None = None,
) -> list[dict[str, Any]]:
    """Search the whole logical path (names only), newest rows last.

    ``path_prefix`` restricts the search to a folder subtree, which keeps results from a
    small folder from being crowded out by a huge one.

    Raises:
        BadRequest: when the query is empty after normalization.
    """
    normalized = normalize_fa(query)
    if not normalized:
        raise BadRequest("empty_query")
    scope = normalize_vault_path(path_prefix) if path_prefix else None
    tokens = [tok for tok in normalized.split(" ") if tok]
    results: list[dict[str, Any]] = []
    for row in session.index.walk("/"):
        level = row["sensitivity"]
        if not include_secret and level != "normal":
            continue
        if not semantics.path_under(str(row["logical_path"]), scope):
            continue
        name = normalize_fa(row["logical_path"])
        if normalized in name or all(tok in name for tok in tokens):
            results.append(_result(row, "filename"))
    results.sort(key=lambda item: item["logical_path"])
    return results[: int(limit)]


def _snippet(body: str, normalized_query: str) -> str:
    """Return at most :data:`MAX_SNIPPET` chars of ``body`` around the first match."""
    normalized_body = normalize_fa(body)
    token = normalized_query.split(" ")[0] if normalized_query else ""
    position = normalized_body.find(token) if token else -1
    if position < 0:
        position = 0
    start = max(0, position - 60)
    return body[start : start + MAX_SNIPPET]


def _match_location(body: str, normalized_query: str) -> tuple[int, int]:
    """Return the 1-based ``(line, offset)`` of the first line matching the query."""
    tokens = [token for token in normalized_query.split(" ") if token]
    offset = 0
    for number, line in enumerate(body.splitlines(), start=1):
        normalized_line = normalize_fa(line)
        if any(token in normalized_line for token in tokens):
            return number, offset
        offset += len(line) + 1
    return 0, 0


def search_text(
    session: Any,
    query: str,
    *,
    limit: int = 50,
    path_prefix: str | None = None,
) -> list[dict[str, Any]]:
    """Search literal content via FTS5 BM25 over ``normal`` files only.

    Each hit carries a ``line`` and ``offset`` (1-based line, character offset) so a
    caller can jump straight to the match with ``read_lines``. ``path_prefix`` scopes the
    search to a subtree.

    Raises:
        BadRequest: when the query is empty.
        VaultLocked: when the session is locked.
    """
    normalized = normalize_fa(query)
    if not normalized:
        raise BadRequest("empty_query")
    session._require_unlocked()
    scope = normalize_vault_path(path_prefix) if path_prefix else None
    fetch = int(limit) * 5 if scope else int(limit)
    hits = session.store.search_text(normalized, limit=max(fetch, int(limit)))
    results: list[dict[str, Any]] = []
    for file_id, score in hits:
        row = session.index.get_file_by_id(file_id)
        if row is None:
            continue
        if not Policy.can_search_content(row["sensitivity"], "ui"):
            continue
        if not semantics.path_under(str(row["logical_path"]), scope):
            continue
        try:
            body = session.fs.read_bytes(row).decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001 - a missing blob should not break search
            continue
        result = _result(row, "text")
        result["snippet"] = _snippet(body, normalized)
        result["score"] = score
        result["line"], result["offset"] = _match_location(body, normalized)
        results.append(result)
        if len(results) >= int(limit):
            break
    return results


def search_semantic(
    session: Any,
    query: str,
    *,
    limit: int = 50,
    path_prefix: str | None = None,
) -> list[dict[str, Any]]:
    """Search by embedding cosine similarity over ``normal`` files only.

    Raises:
        BadRequest: when the query is empty.
        ProviderUnavailable: when no embedding provider is configured.
    """
    if not normalize_fa(query):
        raise BadRequest("empty_query")
    return semantics.search(session, query, limit=limit, path_prefix=path_prefix)


__all__ = ["SearchKind", "search_filenames", "search_text", "search_semantic"]
