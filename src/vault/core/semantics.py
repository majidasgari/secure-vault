"""Opt-in local semantic search (SPEC/01 §11).

Text is cleaned (inline ``data:`` URIs and base64 dropped) and split into
document/paragraph/sentence chunks; each chunk is embedded with a local model and the
vectors are stored in the separate encrypted :mod:`~vault.core.semantic_store`, which
does nearest-neighbour search through the embedded ``sqlite-vec`` extension.

Nothing here ever touches the network. The heavy dependencies are optional: without
``sentence-transformers`` or ``sqlite-vec`` the module reports ``ProviderUnavailable``
and the rest of the app keeps working. Tests inject :class:`StubProvider` via
``session.set_semantic_provider``.
"""

from __future__ import annotations

import hashlib
import math
import struct
from typing import Any, Callable, Protocol, runtime_checkable

from ..errors import InvalidPath, ProviderUnavailable
from ..util import normalize_fa, normalize_vault_path
from .chunking import CHUNK_MODES, DEFAULT_CHUNK_MODE, chunk_text
from .security import Policy

MIN_SIMILARITY = 0.25

#: How many chunks are accumulated across files before one ``embed`` call. Cross-file
#: batching is what keeps a 1000-note vault from becoming 1000 tiny model calls.
BATCH_SIZE = 64

#: Soft cap on the characters in one batch: long paragraphs from many files must not
#: balloon the process resident memory (the model tokenizes the whole batch at once).
BATCH_MAX_CHARS = 120_000

#: Hard cap on the model's sequence length (tokens), which bounds per-batch activation
#: memory for a model like ``bge-m3`` whose default is 8192 tokens.
MAX_SEQ_TOKENS = 2048

#: How many texts ``sentence-transformers`` forwards at once inside one ``embed`` call.
MODEL_BATCH = 32

#: Candidate chunks pulled from the vector index before per-file dedupe/policy filtering.
SEARCH_POOL_FACTOR = 4


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
        try:
            self._model = SentenceTransformer(model)
        except Exception as exc:  # noqa: BLE001 - surface load/download failures uniformly
            raise ProviderUnavailable(
                f"model_load_failed: {exc}", details={"model": model}
            ) from exc
        get_dim = getattr(self._model, "get_embedding_dimension", None) or getattr(
            self._model, "get_sentence_embedding_dimension"
        )
        self.dim = int(get_dim())
        # Bound per-batch activation memory (``bge-m3`` defaults to 8192 tokens).
        current = int(getattr(self._model, "max_seq_length", 0) or 0)
        if current <= 0 or current > MAX_SEQ_TOKENS:
            self._model.max_seq_length = MAX_SEQ_TOKENS

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed ``texts`` with the local model (bounded, no progress bar)."""
        vectors = self._model.encode(
            texts, batch_size=MODEL_BATCH, show_progress_bar=False
        )
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
        model = str(semantic.get("model") or "").strip()
        if not model:
            # No silent fallback: a default with a different dimension silently wiped
            # the live index (the incident this guards against).
            raise ProviderUnavailable("model_not_set")
        return LocalProvider(model)
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
    if not str(semantic.get("model") or "").strip():
        return False, "model_not_set"
    try:
        import sentence_transformers  # noqa: F401,PLC0415
    except ImportError:
        return False, "install requirements-semantic.txt"
    try:
        import sqlite_vec  # noqa: F401,PLC0415
    except ImportError:
        return False, "install requirements-semantic.txt"
    return True, "ok"


def chunk_mode(settings: dict[str, Any]) -> str:
    """Return the validated chunking granularity from ``settings``."""
    mode = str((settings.get("semantic") or {}).get("chunking") or DEFAULT_CHUNK_MODE)
    return mode if mode in CHUNK_MODES else DEFAULT_CHUNK_MODE


def normalize_folder_key(raw: str) -> str:
    """Normalize a folder path used as a :data:`folder_states` key.

    The root is represented by the sentinel ``"*"``; every other folder is stored without
    a leading slash (``"work/payroll"``).
    """
    text = str(raw).strip()
    if text in ("", "/", "*"):
        return "*"
    try:
        normalized = normalize_vault_path(text).strip("/")
    except InvalidPath:
        return "*"
    return normalized or "*"


def folder_states(settings: dict[str, Any]) -> dict[str, bool]:
    """Return the per-folder semantic-search overrides from ``settings``.

    Only folders the user explicitly toggled are present; everything else inherits from
    its nearest overridden ancestor (and defaults to included). A newly created folder
    therefore follows its parent without any extra bookkeeping.
    """
    raw = (settings.get("semantic") or {}).get("folder_states") or {}
    states: dict[str, bool] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            states[normalize_folder_key(str(key))] = bool(value)
    return states


def folder_included(folder: str, states: dict[str, bool]) -> bool:
    """Whether ``folder`` is included, inheriting from the nearest overridden ancestor."""
    parts = [part for part in str(folder or "").strip("/").split("/") if part]
    for index in range(len(parts), -1, -1):
        key = "/".join(parts[:index]) if index else "*"
        if key in states:
            return bool(states[key])
    return True


def file_included(logical_path: str, states: dict[str, bool]) -> bool:
    """Whether a file is in scope for semantic search, based on its parent folder."""
    path = str(logical_path or "").strip("/")
    folder = path.rsplit("/", 1)[0] if "/" in path else ""
    return folder_included(folder, states)


def _require_provider(session: Any) -> EmbeddingProvider:
    """Return the session's provider, raising a descriptive error when absent."""
    provider = session.semantic_provider
    if provider is not None:
        return provider
    reason = "semantic_disabled"
    try:
        reason = is_available(session.meta.settings)[1]
    except Exception:  # noqa: BLE001 - fall back to the generic reason
        reason = "semantic_disabled"
    raise ProviderUnavailable(reason)


def path_under(path: str, prefix: str | None) -> bool:
    """Whether ``path`` equals ``prefix`` or lives under it (``None`` matches everything)."""
    if not prefix:
        return True
    candidate = str(path or "").strip("/")
    root = str(prefix).strip("/")
    return not root or candidate == root or candidate.startswith(root + "/")


def _normal_files(
    session: Any,
    states: dict[str, bool],
    prefix: str | None = None,
    paths: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Return the in-scope ``normal`` files (folders excluded by ``states`` are skipped)."""
    return [
        row
        for row in session.index.walk("/")
        if not int(row["is_dir"])
        and row["sensitivity"] == "normal"
        and file_included(str(row["logical_path"]), states)
        and path_under(str(row["logical_path"]), prefix)
        and (paths is None or str(row["logical_path"]) in paths)
    ]


def _snippet(text: str, limit: int = 240) -> str:
    """Return a single-line snippet of a matching chunk."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "…"


def _read_chunks(session: Any, row: dict[str, Any], mode: str) -> list[str] | None:
    """Read one file and return its cleaned chunks, or ``None`` when it is not text.

    The file's short note is embedded together with the body so a note makes the file
    discoverable semantically.
    """
    try:
        raw = session.fs.read_bytes(row)
    except Exception:  # noqa: BLE001 - skip unreadable files
        return None
    if b"\x00" in raw:
        return None  # binary attachment (image, archive, …) is not searchable text
    body = raw.decode("utf-8", errors="ignore")
    try:
        note = session.store.get_file_note(int(row["id"]))
    except Exception:  # noqa: BLE001 - notes are best effort
        note = None
    if note:
        body = f"{note}\n\n{body}"
    return chunk_text(body, mode)


def _cache_for(session: Any, provider: Any) -> Any:
    """Build the content-addressed cache for ``provider`` or ``None`` on failure."""
    try:
        from .vector_cache import VectorCache  # noqa: PLC0415 - avoid an import cycle

        settings = session.meta.settings
        cap_mb = int((settings.get("semantic") or {}).get("cache_max_mb", 512) or 512)
        return VectorCache.for_model(
            provider.model, provider.dim, max_bytes=max(0, cap_mb) * 1024 * 1024
        )
    except Exception:  # noqa: BLE001 - the cache is an optimisation only
        return None


def index_all(
    session: Any,
    *,
    force: bool = False,
    progress: Callable[[int, int], None] | None = None,
    prefix: str | None = None,
    paths: set[str] | None = None,
    allow_reset: bool = False,
    reason: str | None = None,
) -> dict[str, Any]:
    """Embed every ``normal`` text file into the encrypted semantic store.

    Chunks from *many* files are accumulated and embedded in large cross-file batches.
    Embeddings are served from the content-addressed :class:`VectorCache` when unchanged,
    so only genuinely new text reaches the model.

    A layout mismatch is **never** wiped implicitly: with ``allow_reset=False`` the call
    returns ``ok=False`` and leaves the live index untouched. Returns
    ``{"indexed", "skipped", "chunks", "ok", "reset", "last_reset"}``.
    """
    provider = _require_provider(session)
    session._require_unlocked()
    settings = session.meta.settings
    mode = chunk_mode(settings)
    states = folder_states(settings)
    scope = normalize_vault_path(prefix) if prefix else None
    store = session.semantic_store
    layout = store.ensure_layout(
        provider.model, provider.dim, mode, allow_reset=allow_reset, reason=reason
    )
    if not layout.get("ok"):
        # Keep the live index; the caller can tell the user why nothing was indexed.
        return {
            "indexed": 0,
            "skipped": 0,
            "chunks": 0,
            "ok": False,
            "reset": False,
            "last_reset": layout.get("last_reset"),
            "reason": layout.get("reason"),
        }
    files = _normal_files(session, states, scope, paths)
    existing = set() if force else store.indexed_files()
    cache = _cache_for(session, provider)
    indexed = 0
    skipped = 0
    chunks_total = 0
    total = len(files)

    #: ``(file_id, ord, raw_text)`` waiting to be embedded, plus the normalized texts.
    pending_rows: list[tuple[int, int, str]] = []
    pending_texts: list[str] = []
    pending_chars = 0
    #: Files whose previous chunks must be dropped before their new ones are written.
    dirty_files: set[int] = set()

    def flush() -> None:
        """Delete replaced files, then embed (cache-aware) and insert the chunks."""
        nonlocal chunks_total, pending_chars
        if dirty_files:
            store.delete_files(dirty_files)
            dirty_files.clear()
        if pending_texts:
            hits = cache.lookup(pending_texts) if cache is not None else {}
            miss_positions = [i for i in range(len(pending_texts)) if i not in hits]
            miss_texts = [pending_texts[i] for i in miss_positions]
            model_vectors = provider.embed(miss_texts) if miss_texts else []
            if cache is not None and miss_texts:
                cache.store(miss_texts, model_vectors)
            vectors: list[list[float]] = []
            cursor = 0
            for position in range(len(pending_texts)):
                if position in hits:
                    vectors.append(hits[position])
                else:
                    vectors.append(model_vectors[cursor])
                    cursor += 1
            rows = [
                (file_id, ord_, text, _pack(vec))
                for (file_id, ord_, text), vec in zip(pending_rows, vectors)
            ]
            chunks_total += store.add_chunks(rows)
            pending_texts.clear()
            pending_rows.clear()
            pending_chars = 0

    for position, row in enumerate(files, start=1):
        file_id = int(row["id"])
        if file_id in existing:
            skipped += 1
        else:
            chunks = _read_chunks(session, row, mode)
            dirty_files.add(file_id)  # drop stale chunks (empty/binary files included)
            if not chunks:
                skipped += 1
            else:
                for ord_, text in enumerate(chunks):
                    pending_rows.append((file_id, ord_, text))
                    pending_texts.append(normalize_fa(text))
                    pending_chars += len(text)
                indexed += 1
                if len(pending_texts) >= BATCH_SIZE or pending_chars >= BATCH_MAX_CHARS:
                    flush()
        if progress is not None:
            progress(position, total)
    flush()
    store.flush()
    return {
        "indexed": indexed,
        "skipped": skipped,
        "chunks": chunks_total,
        "ok": True,
        "reset": bool(layout.get("reset")),
        "last_reset": layout.get("last_reset"),
    }


def search(
    session: Any,
    query: str,
    *,
    limit: int = 50,
    path_prefix: str | None = None,
) -> list[dict[str, Any]]:
    """Return the best matching chunk per file (``normal`` files only), best first.

    ``path_prefix`` restricts the hits to a folder subtree (or a single file).

    Raises:
        ProviderUnavailable: when no provider is configured/injected.
    """
    provider = _require_provider(session)
    session._require_unlocked()
    store = session.semantic_store
    if (
        not store.has_layout(provider.model)
        or store.meta().get("chunking") != chunk_mode(session.meta.settings)
    ):
        return []
    states = folder_states(session.meta.settings)
    scope = normalize_vault_path(path_prefix) if path_prefix else None
    query_vec = provider.embed([normalize_fa(query)])[0]
    pool = max(int(limit) * SEARCH_POOL_FACTOR, 50)
    if scope:
        pool = max(pool, 200)  # a narrow subtree still needs a deep enough candidate pool
    hits = store.search(_pack(query_vec), provider.model, k=pool)
    best: dict[int, dict[str, Any]] = {}
    for hit in hits:
        if hit["score"] < MIN_SIMILARITY:
            continue
        row = session.index.get_file_by_id(int(hit["file_id"]))
        if row is None or row["sensitivity"] != "normal":
            continue
        if not file_included(str(row["logical_path"]), states):
            continue
        if not path_under(str(row["logical_path"]), scope):
            continue
        if not Policy.can_search_content(row["sensitivity"], "ui"):
            continue
        current = best.get(int(hit["file_id"]))
        if current is None or hit["score"] > current["score"]:
            best[int(hit["file_id"])] = {
                "logical_path": row["logical_path"],
                "is_dir": bool(row["is_dir"]),
                "sensitivity": row["sensitivity"],
                "size": int(row["size"]),
                "mtime": int(row["mtime"]),
                "match": "semantic",
                "score": float(hit["score"]),
                "snippet": _snippet(str(hit["text"])),
                "chunk": int(hit["ord"]),
            }
    results = sorted(best.values(), key=lambda item: item["score"], reverse=True)
    return results[: int(limit)]


__all__ = [
    "EmbeddingProvider",
    "LocalProvider",
    "StubProvider",
    "get_provider",
    "is_available",
    "chunk_mode",
    "index_all",
    "search",
    "MIN_SIMILARITY",
]
