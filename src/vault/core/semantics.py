"""Opt-in local semantic search (SPEC/01 §11).

Nothing here ever touches the network. The heavy ``sentence-transformers`` dependency is
imported lazily; without it the module reports ``ProviderUnavailable`` and the rest of the
app keeps working. Tests inject :class:`StubProvider` via ``session.set_semantic_provider``.
"""

from __future__ import annotations

import hashlib
import math
import struct
from typing import Any, Callable, Protocol, runtime_checkable

from ..errors import ProviderUnavailable
from ..util import normalize_fa
from .security import Policy

MIN_SIMILARITY = 0.25


@runtime_checkable
class EmbeddingProvider(Protocol):
    """Protocol for embedding backends used by the semantic search."""

    name: str
    dim: int
    model: str

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return one embedding vector per input text."""
        ...


class LocalProvider:
    """``sentence-transformers`` backed provider (guarded, offline after model download)."""

    name = "local"

    def __init__(self, model: str) -> None:
        """Load ``model`` locally.

        Raises:
            ProviderUnavailable: when ``sentence-transformers`` is not installed.
        """
        try:
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ProviderUnavailable(
                "install requirements-semantic.txt",
                details={"model": model},
            ) from exc
        self.model = model
        self._model = SentenceTransformer(model)
        self.dim = int(self._model.get_sentence_embedding_dimension())

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed ``texts`` with the local model."""
        vectors = self._model.encode(texts)
        return [[float(x) for x in vec] for vec in vectors]


class StubProvider:
    """Deterministic, dependency-free provider used by the tests."""

    name = "stub"
    dim = 64
    model = "stub"

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return a deterministic unit vector per text (hashed bag of words)."""
        result: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self.dim
            for token in normalize_fa(text).split(" "):
                if not token:
                    continue
                digest = hashlib.sha256(token.encode("utf-8")).digest()
                index = int.from_bytes(digest[:4], "big") % self.dim
                sign = 1.0 if (digest[4] & 1) else -1.0
                vec[index] += sign
            norm = math.sqrt(sum(v * v for v in vec))
            if norm > 0.0:
                vec = [v / norm for v in vec]
            result.append(vec)
        return result


def _pack(vec: list[float]) -> bytes:
    """Pack a float vector into little-endian float32 bytes."""
    return struct.pack(f"<{len(vec)}f", *vec)


def _unpack(blob: bytes) -> list[float]:
    """Unpack little-endian float32 bytes into a float vector."""
    count = len(blob) // 4
    return list(struct.unpack(f"<{count}f", blob[: count * 4]))


def get_provider(settings: dict[str, Any]) -> EmbeddingProvider:
    """Return the configured embedding provider.

    Raises:
        ProviderUnavailable: when semantic search is disabled or its backend is missing.
    """
    semantic = settings.get("semantic") or {}
    if not semantic.get("enabled"):
        raise ProviderUnavailable("semantic_disabled")
    provider = semantic.get("provider", "local")
    if provider == "stub":
        return StubProvider()
    if provider == "local":
        return LocalProvider(str(semantic.get("model", "all-MiniLM-L6-v2")))
    raise ProviderUnavailable("unknown_provider", details={"provider": provider})


def is_available(settings: dict[str, Any]) -> tuple[bool, str]:
    """Return ``(ok, reason)`` describing whether semantic search can run."""
    semantic = settings.get("semantic") or {}
    if not semantic.get("enabled"):
        return False, "semantic_disabled"
    provider = semantic.get("provider", "local")
    if provider == "stub":
        return True, "stub"
    if provider != "local":
        return False, "unknown_provider"
    try:
        import sentence_transformers  # noqa: F401,PLC0415
    except ImportError:
        return False, "install requirements-semantic.txt"
    return True, "ok"


def _normal_files(session: Any) -> list[dict[str, Any]]:
    """Return the unlocked session's indexed (normal, non-directory) files."""
    return [
        row
        for row in session.index.walk("/")
        if not int(row["is_dir"]) and row["sensitivity"] == "normal"
    ]


def index_all(
    session: Any,
    *,
    force: bool = False,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, int]:
    """Embed every ``normal`` file into the encrypted store.

    Returns ``{"indexed": n, "skipped": n}``.
    """
    provider = session.semantic_provider
    if provider is None:
        raise ProviderUnavailable("semantic_disabled")
    session._require_unlocked()
    files = _normal_files(session)
    existing = {file_id for file_id, _ in session.store.get_vectors(provider.model)}
    indexed = 0
    skipped = 0
    total = len(files)
    for position, row in enumerate(files, start=1):
        file_id = int(row["id"])
        if not force and file_id in existing:
            skipped += 1
        else:
            try:
                body = session.fs.read_bytes(row).decode("utf-8", errors="ignore")
            except Exception:  # noqa: BLE001 - skip unreadable files
                skipped += 1
                continue
            vector = provider.embed([normalize_fa(body)])[0]
            session.store.set_vector(file_id, provider.model, _pack(vector))
            indexed += 1
        if progress is not None:
            progress(position, total)
    session.flush()
    return {"indexed": indexed, "skipped": skipped}


def search(session: Any, query: str, *, limit: int = 50) -> list[dict[str, Any]]:
    """Return semantic hits with cosine similarity >= 0.25, best first.

    Raises:
        ProviderUnavailable: when no provider is configured/injected.
    """
    provider = session.semantic_provider
    if provider is None:
        raise ProviderUnavailable("semantic_disabled")
    session._require_unlocked()
    query_vec = provider.embed([normalize_fa(query)])[0]
    qnorm = math.sqrt(sum(v * v for v in query_vec)) or 1.0
    results: list[tuple[float, dict[str, Any]]] = []
    for file_id, blob in session.store.get_vectors(provider.model):
        vec = _unpack(blob)
        if len(vec) != len(query_vec):
            continue
        dot = sum(a * b for a, b in zip(query_vec, vec))
        vnorm = math.sqrt(sum(v * v for v in vec)) or 1.0
        score = dot / (qnorm * vnorm)
        if score < MIN_SIMILARITY:
            continue
        row = session.index.get_file_by_id(file_id)
        if row is None or row["sensitivity"] != "normal":
            continue
        if not Policy.can_search_content(row["sensitivity"], "ui"):
            continue
        results.append(
            (
                score,
                {
                    "logical_path": row["logical_path"],
                    "is_dir": bool(row["is_dir"]),
                    "sensitivity": row["sensitivity"],
                    "size": int(row["size"]),
                    "mtime": int(row["mtime"]),
                    "match": "semantic",
                    "score": score,
                },
            )
        )
    results.sort(key=lambda item: item[0], reverse=True)
    return [item[1] for item in results[: int(limit)]]


__all__ = [
    "EmbeddingProvider",
    "LocalProvider",
    "StubProvider",
    "get_provider",
    "is_available",
    "index_all",
    "search",
    "MIN_SIMILARITY",
]
