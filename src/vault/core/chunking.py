"""Text cleaning and chunking for the semantic index (SPEC/01 §11).

Embeddings are only ever built from *text*: inline ``data:`` URIs (base64 images in the
Joplin mirror) and long base64 runs are stripped first, and callers skip binary blobs.
The user picks the granularity (document / paragraph / sentence); paragraphs are the
default because they keep a useful amount of context without burying a single relevant
sentence in one giant document vector.
"""

from __future__ import annotations

import re

#: Granularities the user may choose; ``paragraph`` is the default.
CHUNK_MODES = ("document", "paragraph", "sentence")
DEFAULT_CHUNK_MODE = "paragraph"

#: A single chunk longer than this is truncated before embedding (the model truncates
#: anyway; this only keeps the stored chunk text bounded).
MAX_CHUNK_CHARS = 4000

#: Markdown image/link whose whole target is a ``data:`` URI (removed with its wrapper).
_MD_DATA_LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*data:[^)]*\)")
#: Inline images: ``data:image/png;base64,<very long base64>``. The base64 tail is
#: matched greedily across newlines; anything shorter than 64 chars is left alone.
_DATA_URI_RE = re.compile(r"data:[a-zA-Z0-9.+/-]+;base64,[A-Za-z0-9+/=\r\n]{64,}")
#: Bare base64 runs (no ``data:`` prefix) that survived as their own token.
_LONG_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{200,}={0,2}")
#: Paragraph = blank-line separated.
_PARAGRAPH_RE = re.compile(r"\n[ \t]*\n+")
#: Sentence = after ``. ! ? ؟ …`` followed by whitespace, or at a newline.
_SENTENCE_RE = re.compile(r"(?<=[.!?؟…])\s+|\n+")


def strip_inline_data(text: str) -> str:
    """Remove inline ``data:`` URIs and long base64 runs from ``text``."""
    text = _MD_DATA_LINK_RE.sub(" ", text)
    text = _DATA_URI_RE.sub(" ", text)
    return _LONG_BASE64_RE.sub(" ", text)


def _truncate(chunk: str) -> str:
    """Bound one chunk's length, preserving whole words where possible."""
    if len(chunk) <= MAX_CHUNK_CHARS:
        return chunk
    clipped = chunk[:MAX_CHUNK_CHARS]
    cut = clipped.rfind(" ")
    if cut > MAX_CHUNK_CHARS // 2:
        clipped = clipped[:cut]
    return clipped.rstrip()


def chunk_text(text: str, mode: str = DEFAULT_CHUNK_MODE) -> list[str]:
    """Split ``text`` into embeddable chunks at the chosen granularity.

    ``mode`` is one of :data:`CHUNK_MODES`; an unknown value falls back to
    :data:`DEFAULT_CHUNK_MODE`. Empty chunks are dropped and every chunk is length-capped
    (:data:`MAX_CHUNK_CHARS`).
    """
    if mode not in CHUNK_MODES:
        mode = DEFAULT_CHUNK_MODE
    cleaned = strip_inline_data(text)
    if mode == "document":
        parts = [cleaned]
    elif mode == "sentence":
        parts = _SENTENCE_RE.split(cleaned)
    else:  # paragraph
        parts = _PARAGRAPH_RE.split(cleaned)
    chunks: list[str] = []
    for part in parts:
        piece = part.strip()
        if piece:
            chunks.append(_truncate(piece))
    return chunks


__all__ = [
    "CHUNK_MODES",
    "DEFAULT_CHUNK_MODE",
    "MAX_CHUNK_CHARS",
    "strip_inline_data",
    "chunk_text",
]
