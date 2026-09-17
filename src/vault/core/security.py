"""The sensitivity policy boundary — the single source of truth (SPEC/01 §9).

Encodes ``docs/DESIGN.md`` §4 as pure functions with no I/O so the whole matrix is
unit-testable. The table implemented here is::

    level        see name   MCP read   UI read    content search  MCP request-open  UI viewer
    normal       yes        yes        yes        yes             yes               web preview
    secret       yes        no         after confirm  no          no                native viewer
    secretfile   yes        no         native viewer  no          yes               native viewer
"""

from __future__ import annotations

from ..errors import BadRequest

LEVELS: tuple[str, str, str] = ("normal", "secret", "secretfile")
LEVEL_RANK: dict[str, int] = {"normal": 0, "secret": 1, "secretfile": 2}

SOURCE_UI = "ui"
SOURCE_MCP = "mcp"
SOURCE_IMPORTER = "importer"
SOURCES: tuple[str, str, str] = (SOURCE_UI, SOURCE_MCP, SOURCE_IMPORTER)


def _require_level(level: str) -> str:
    """Return ``level`` unchanged, raising :class:`BadRequest` when unknown."""
    if level not in LEVEL_RANK:
        raise BadRequest("unknown_level", details={"level": level})
    return level


def rank(level: str) -> int:
    """Return the numeric rank of ``level`` (``normal`` < ``secret`` < ``secretfile``)."""
    return LEVEL_RANK[_require_level(level)]


def is_higher_or_equal(a: str, b: str) -> bool:
    """Return True when level ``a`` is at least as sensitive as level ``b``."""
    return rank(a) >= rank(b)


class Policy:
    """Pure policy predicates; see the module docstring for the full matrix."""

    @staticmethod
    def can_see_name(level: str, source: str) -> bool:
        """Names, sizes and levels are visible to every source, even while locked."""
        _require_level(level)
        return True

    @staticmethod
    def can_read_content(level: str, source: str) -> bool:
        """Whether ``source`` may read the *content* of a file at ``level``."""
        _require_level(level)
        if source == SOURCE_MCP:
            return level == "normal"
        if source in (SOURCE_UI, SOURCE_IMPORTER):
            return True
        raise BadRequest("unknown_source", details={"source": source})

    @staticmethod
    def can_search_content(level: str, source: str) -> bool:
        """Only ``normal`` content is ever searchable; source does not widen this."""
        _require_level(level)
        return level == "normal"

    @staticmethod
    def can_request_open_secret(level: str, source: str) -> bool:
        """MCP may request display of ``normal`` and ``secretfile`` (never ``secret``)."""
        _require_level(level)
        if source == SOURCE_MCP:
            return level != "secret"
        return False

    @staticmethod
    def can_raise(from_level: str, to_level: str, source: str) -> bool:
        """Raising sensitivity is allowed for UI/MCP/importer when the rank increases."""
        _require_level(from_level)
        _require_level(to_level)
        if source not in SOURCES:
            raise BadRequest("unknown_source", details={"source": source})
        return rank(to_level) > rank(from_level)

    @staticmethod
    def can_lower(from_level: str, to_level: str, source: str) -> bool:
        """Only the UI may lower a level, and only to a strictly lower rank."""
        _require_level(from_level)
        _require_level(to_level)
        if source not in SOURCES:
            raise BadRequest("unknown_source", details={"source": source})
        return source == SOURCE_UI and rank(to_level) < rank(from_level)

    @staticmethod
    def ui_requires_confirmation(level: str) -> bool:
        """Whether the UI must show a confirmation dialog before reading ``level``."""
        _require_level(level)
        return level in ("secret", "secretfile")

    @staticmethod
    def ui_uses_native_viewer(level: str) -> bool:
        """Whether the UI renders ``level`` with the native viewer (not the web preview)."""
        _require_level(level)
        return level in ("secret", "secretfile")


__all__ = [
    "LEVELS",
    "LEVEL_RANK",
    "SOURCE_UI",
    "SOURCE_MCP",
    "SOURCE_IMPORTER",
    "SOURCES",
    "rank",
    "is_higher_or_equal",
    "Policy",
]
