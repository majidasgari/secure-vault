"""Small dependency-free helpers shared by the whole core layer (SPEC/01 §3)."""

from __future__ import annotations

import hashlib
import os
import time
import unicodedata
from pathlib import Path

from .errors import InvalidPath

_MAX_PATH_BYTES = 1024

# Extended Arabic-Indic (U+06F0..) and Arabic-Indic (U+0660..) digits mapped to ASCII.
_DIGIT_MAP = {
    **{0x06F0 + i: ord("0") + i for i in range(10)},
    **{0x0660 + i: ord("0") + i for i in range(10)},
}

# Character substitutions for Persian search normalization (variant -> canonical).
_CHAR_MAP = {
    0x064A: 0x06CC,  # Arabic yeh -> Farsi yeh
    0x0643: 0x06A9,  # Arabic kaf -> Farsi kaf
    0x06C0: 0x0647,  # heh with yeh above -> heh
    0x0629: 0x0647,  # teh marbuta -> heh
    0x0623: 0x0627,  # alef with hamza above -> alef
    0x0625: 0x0627,  # alef with hamza below -> alef
    0x0622: 0x0627,  # alef with madda -> alef
}

# Diacritics and tatweel stripped during normalization.
_STRIP = set(range(0x064B, 0x0653)) | {0x0670, 0x0640}

_WHITESPACE = set(" \t\n\r\v\f\u00a0\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
                  "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000")


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomically write ``data`` to ``path``.

    Writes to ``<path>.tmp`` in the same directory, flushes and ``fsync``s it, then
    ``os.replace``s it over the target. The parent directory is created if needed.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
    except OSError:  # pragma: no cover - best effort directory fsync
        return
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover
        pass
    finally:
        os.close(dir_fd)


def normalize_logical_path(raw: str) -> str:
    """Return the canonical POSIX relative path for ``raw``.

    Applies NFC, strips surrounding whitespace, converts ``\\`` to ``/``, collapses
    repeated slashes, and rejects absolute paths, empty strings, ``..`` segments,
    control characters (``< 0x20``) or NUL, and paths longer than 1024 UTF-8 bytes.
    The vault root is returned as ``"/"``; all other paths have no leading slash.

    Raises:
        InvalidPath: if the input is not a valid vault-relative logical path.
    """
    if not isinstance(raw, str):
        raise InvalidPath("path_must_be_string", details={"path": repr(raw)})
    text = unicodedata.normalize("NFC", raw).strip()
    if text == "":
        raise InvalidPath("empty_path", details={"path": raw})
    if any(ord(ch) < 0x20 for ch in text):
        raise InvalidPath("control_characters_forbidden", details={"path": raw})
    text = text.replace("\\", "/")
    if text.strip("/") == "":
        return "/"
    if text.startswith("/"):
        raise InvalidPath("absolute_path_forbidden", details={"path": raw})
    segments: list[str] = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            raise InvalidPath("parent_segment_forbidden", details={"path": raw})
        segments.append(segment)
    if not segments:
        return "/"
    result = "/".join(segments)
    if len(result.encode("utf-8")) > _MAX_PATH_BYTES:
        raise InvalidPath("path_too_long", details={"path": raw})
    return result


def normalize_vault_path(raw: str) -> str:
    """Normalize a path as accepted from the API/MCP/UI layer.

    Callers (MCP tools, the socket API, the UI) naturally write the vault-absolute form
    ``"/"`` and ``"/folder/note.md"``. This accepts both that form and the bare relative
    form, and delegates to :func:`normalize_logical_path` for the actual rules, so storage
    always uses the canonical (no leading slash, root ``"/"``) form.

    Raises:
        InvalidPath: for anything :func:`normalize_logical_path` rejects.
    """
    if not isinstance(raw, str):
        raise InvalidPath("path_must_be_string", details={"path": repr(raw)})
    text = unicodedata.normalize("NFC", raw).strip().replace("\\", "/")
    if text == "":
        raise InvalidPath("empty_path", details={"path": raw})
    if text.strip("/") == "":
        return "/"
    if text.startswith("/"):
        text = text.lstrip("/")
    return normalize_logical_path(text)


def normalize_fa(text: str) -> str:
    """Normalize Persian/Arabic text for search on both index and query sides.

    Substitutes common letter variants, strips diacritics and tatweel, maps Persian
    and Arabic digits to ASCII, and collapses whitespace runs to a single space.
    Zero-width non-joiner (U+200C) is preserved.
    """
    if not text:
        return ""
    text = unicodedata.normalize("NFC", text)
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _STRIP:
            continue
        if cp in _CHAR_MAP:
            out.append(chr(_CHAR_MAP[cp]))
            continue
        if cp in _DIGIT_MAP:
            out.append(chr(_DIGIT_MAP[cp]))
            continue
        if cp in _WHITESPACE:
            out.append(" ")
            continue
        out.append(ch)
    collapsed = "".join(out)
    while "  " in collapsed:
        collapsed = collapsed.replace("  ", " ")
    return collapsed.strip(" ")


def human_size(n: int) -> str:
    """Return a compact human-readable size such as ``"1.5 MB"``."""
    if n < 0:
        n = 0
    if n < 1024:
        return f"{n} B"
    size = float(n)
    for unit in ("KB", "MB", "GB", "TB"):
        size /= 1024.0
        if size < 1024.0 or unit == "TB":
            return f"{size:.1f} {unit}"
    return f"{n} B"  # pragma: no cover - unreachable


def now_ms() -> int:
    """Return the current wall-clock time in milliseconds since the Unix epoch."""
    return int(time.time() * 1000)


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def wipe(buf: bytearray) -> None:
    """Overwrite ``buf`` with zeros in place (best-effort secret hygiene)."""
    for i in range(len(buf)):
        buf[i] = 0


__all__ = [
    "atomic_write_bytes",
    "normalize_logical_path",
    "normalize_fa",
    "human_size",
    "now_ms",
    "sha256_hex",
    "wipe",
]
