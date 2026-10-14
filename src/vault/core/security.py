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
#: The two gated levels: their content never reaches a plain ``read_file`` (SPEC/09 §B).
SECRET_LEVELS: tuple[str, str] = ("secret", "secretfile")
LEVEL_RANK: dict[str, int] = {"normal": 0, "secret": 1, "secretfile": 2}

SOURCE_UI = "ui"
SOURCE_MCP = "mcp"
SOURCE_IMPORTER = "importer"
SOURCES: tuple[str, str, str] = (SOURCE_UI, SOURCE_MCP, SOURCE_IMPORTER)
#: The browser-autofill bridge. Deliberately *not* part of :data:`SOURCES`: it is a read-only
#: consumer of credentials, and ``can_lower`` keeps refusing it outright. ``can_raise`` allows it
#: exactly one transition — creating a *new* file at :data:`BROWSER_CREATABLE_LEVELS` — which is
#: what "save this password in the vault" needs; a credential must be born at the credential
#: level, never as a searchable ``normal`` file. What it may reach is bounded by the ``browser``
#: role's method table and by the credential-root containment check in ``api/browser.py``.
SOURCE_BROWSER = "browser"

#: The levels the browser bridge may create a file at (see :meth:`Policy.can_raise`).
BROWSER_CREATABLE_LEVELS: tuple[str, ...] = ("secretfile",)


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
        if source == SOURCE_BROWSER:
            # Read-only credential bridge: the ``browser`` role has no route to a generic read
            # (``vault.read_file`` is not in its method table) and every path it may touch is
            # confined to the credential root, so the level itself adds no further gate here.
            return True
        raise BadRequest("unknown_source", details={"source": source})

    @staticmethod
    def can_search_content(level: str, source: str) -> bool:
        """Only ``normal`` content is ever searchable; source does not widen this."""
        _require_level(level)
        return level == "normal"

    @staticmethod
    def can_request_open_secret(level: str, source: str) -> bool:
        """Whether ``source`` may ask the desktop UI to display a file.

        MCP may request ``normal`` and ``secretfile`` (never ``secret``). The UI role may
        request **both** gated levels: that is how the browser hands a ``secret``/
        ``secretfile`` to the desktop app instead of ever putting its content in an HTML page
        (the approval it comes back with is what releases the text; SPEC/09 §B).
        """
        _require_level(level)
        if source == SOURCE_MCP:
            return level != "secret"
        if source == SOURCE_UI:
            return level in SECRET_LEVELS
        return False

    @staticmethod
    def can_raise(from_level: str, to_level: str, source: str) -> bool:
        """Raising sensitivity is allowed for UI/MCP/importer when the rank increases.

        The browser bridge may only *create* a file at :data:`BROWSER_CREATABLE_LEVELS` — never
        raise an existing file's level, never reach ``secret``, never lower anything.
        """
        _require_level(from_level)
        _require_level(to_level)
        if source == SOURCE_BROWSER:
            return rank(to_level) > rank(from_level) and to_level in BROWSER_CREATABLE_LEVELS
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
    "SECRET_LEVELS",
    "LEVEL_RANK",
    "SOURCE_UI",
    "SOURCE_MCP",
    "SOURCE_IMPORTER",
    "SOURCE_BROWSER",
    "SOURCES",
    "rank",
    "is_higher_or_equal",
    "Policy",
]
