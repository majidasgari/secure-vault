"""The shared, transport-independent command surface (SPEC/02 §1).

:class:`Service` wraps a :class:`~vault.core.session.VaultSession` and routes the exact
commands the two transports (the local socket and the in-process UI) need. ``role`` is
supplied by the transport — never by client data — and decides both policy enforcement
and the ``source`` recorded in the append-only access log.
"""

from __future__ import annotations

import base64
import binascii
import json
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from ..core.chunking import CHUNK_MODES
from ..core.semantics import normalize_folder_key
from ..core.security import LEVELS, SOURCE_MCP, SOURCE_UI
from ..errors import (
    BadRequest,
    DowngradeForbidden,
    PermissionDenied,
    VaultError,
    VaultLocked,
)
from ..util import normalize_vault_path, now_ms

ROLE_UI = SOURCE_UI
ROLE_MCP = SOURCE_MCP
ROLES = (ROLE_UI, ROLE_MCP)

#: Read-only telemetry that must never write an access-log row.
#:
#: The status bar and the log panel poll these while the UI is open. Logging a poll writes a row
#: per poll (measured: ~1000 rows in 18 minutes — 40 % of the whole log, i.e. the log filled
#: itself), and the DB grows for as long as anything watches the vault. Refusals and errors are
#: still logged: only the "allow" row of a pure telemetry read is dropped.
QUIET_METHODS = frozenset(
    {
        "vault.status",
        "vault.access_log",
        "vault.access_log_count",
        "vault.ping",
        "vault.recent",
        "vault.i18n",
    }
)

SecretRequestCallback = Callable[[dict[str, Any]], Any]


def _decode_content(content: str, encoding: str) -> bytes:
    """Turn a JSON string into the bytes to store.

    ``base64`` is not a Python text codec, so ``"…".encode("base64")`` raises — the web editor
    uploads pasted images that way, so binary payloads are decoded here instead.
    """
    name = str(encoding or "utf-8").strip().lower()
    if name in ("base64", "b64"):
        try:
            return base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("invalid_base64") from exc
    if name in ("hex", "hexadecimal"):
        try:
            return bytes.fromhex(content)
        except ValueError as exc:
            raise ValueError("invalid_hex") from exc
    return content.encode(encoding, errors="strict")

#: Maximum number of activity events kept by the UI feed (SPEC/09 §D).
ACTIVITY_LIMIT = 200


class ActivityFeed:
    """A bounded, newest-first activity feed (metadata only; SPEC/09 §7).

    Pure Python so it can be unit-tested without Qt. The feed never stores file
    content — events are the metadata dicts emitted by ``VaultSession.on_activity``.

    Only **agent** traffic is kept (``mcp``/``socket``) plus every secret-level event from any
    source: the feed drives the tray's "what is being read right now" indicator, and status
    polls, imports or a human clicking around in the GUI would drown it.
    """

    #: Sources that mean "an agent is touching the vault right now".
    AGENT_SOURCES = ("mcp", "socket")
    #: Sensitivity levels that always make it into the feed, whatever the source.
    ALWAYS_LEVELS = ("secret", "secretfile")

    def __init__(self, limit: int = ACTIVITY_LIMIT) -> None:
        """Create an empty feed bounded to ``limit`` entries."""
        self.limit = max(1, int(limit))
        self._items: deque[dict[str, Any]] = deque(maxlen=self.limit)

    def add(self, event: dict[str, Any]) -> dict[str, Any]:
        """Append one event, dropping the oldest once the limit is reached.

        Events that are neither agent traffic nor a secret/deny signal are returned unchanged
        but **not stored** — that keeps the tray honest about who is reading what.
        """
        item = dict(event or {})
        source = str(item.get("source") or "")
        kind = str(item.get("kind") or "")
        level = str(item.get("sensitivity") or "")
        if source not in self.AGENT_SOURCES and level not in self.ALWAYS_LEVELS and kind != "deny":
            return item
        self._items.append(item)
        return item

    def events(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return the newest-first events (optionally capped at ``limit``)."""
        items = list(reversed(self._items))
        return items[:limit] if limit else items

    def last_read(self) -> dict[str, Any] | None:
        """Return the most recent ``kind == "read"`` event, if any."""
        for event in reversed(self._items):
            if event.get("kind") == "read":
                return event
        return None

    def clear(self) -> None:
        """Drop every stored event."""
        self._items.clear()

    def __len__(self) -> int:
        """Return the number of stored events."""
        return len(self._items)

    def extend(self, events: Iterable[dict[str, Any]]) -> None:
        """Append several events in order."""
        for event in events:
            self.add(event)

# Methods callable by each role. Anything absent from the table is unknown (``-32601``).
_UI_ONLY = "ui"
_MCP_ONLY = "mcp"
_BOTH = "both"


def _api_path(logical: str) -> str:
    """Render a canonical logical path in the vault-absolute form clients use."""
    return "/" if logical == "/" else "/" + logical


def _iso(ts: int) -> str:
    """Return an ISO-8601 UTC timestamp for a millisecond epoch value."""
    return datetime.fromtimestamp(int(ts) / 1000.0, tz=timezone.utc).isoformat()


class Service:
    """Wraps :class:`VaultSession` and exposes exactly the commands the transports need."""

    def __init__(
        self,
        session: Any,
        *,
        on_secret_request: SecretRequestCallback | None = None,
    ) -> None:
        """Bind the service to ``session`` and register the secret-request callback."""
        self.session = session
        self._lock = threading.RLock()
        if on_secret_request is not None:
            session.on_secret_request = on_secret_request

    # ------------------------------------------------------------------ dispatch
    def dispatch(
        self,
        method: str,
        params: dict,
        *,
        role: str,
        session_id: str,
        source: str | None = None,
    ) -> dict:
        """Route one command and return its result dict.

        Every call appends exactly one access-log row (``source`` from ``role``,
        ``tool`` = ``method``, ``outcome`` = ``allow|deny|error``). Errors are re-raised
        as :class:`~vault.errors.VaultError` subclasses for the transport to map.

        Raises:
            BadRequest: for an unknown method or malformed parameters.
            PermissionDenied: when ``role`` may not call ``method``.
        """
        if role not in ROLES:
            raise BadRequest("unknown_role", details={"role": role})
        if not isinstance(params, dict):
            raise BadRequest("params_must_be_object")
        route = self._ROUTES.get(method)
        target = self._target_path(params)
        with self._lock:
            if route is None:
                self._log(
                    role=role, tool=method, target=target, outcome="error",
                    code=BadRequest.code, session_id=session_id,
                )
                raise BadRequest("unknown_method", details={"method": method})
            handler, scope = route
            if scope != _BOTH and scope != role:
                self._log(
                    role=role, tool=method, target=target, outcome="deny",
                    code=PermissionDenied.code, session_id=session_id,
                )
                raise PermissionDenied(
                    "method_not_allowed", details={"method": method, "role": role}
                )
            previous_source = getattr(self.session, "_activity_source", None)
            self.session._activity_source = source or (
                SOURCE_MCP if role == ROLE_MCP else "gui"
            )
            previous_suppress = getattr(self.session, "_suppress_log", False)
            self.session._suppress_log = True      # this layer writes the one row for the call
            try:
                result = handler(self, params, role, session_id)
            except PermissionDenied as exc:
                self._log(
                    role=role, tool=method, target=target, outcome="deny",
                    code=exc.code, session_id=session_id,
                )
                raise
            except (DowngradeForbidden, VaultLocked) as exc:
                self._log(
                    role=role, tool=method, target=target, outcome="deny",
                    code=exc.code, session_id=session_id,
                )
                raise
            except VaultError as exc:
                self._log(
                    role=role, tool=method, target=target, outcome="error",
                    code=exc.code, session_id=session_id,
                )
                raise
            finally:
                self.session._activity_source = previous_source
                self.session._suppress_log = previous_suppress
            if method not in QUIET_METHODS:
                self._log(
                    role=role, tool=method, target=target, outcome="allow",
                    session_id=session_id,
                )
            return result

    # ------------------------------------------------------------------ helpers
    def _log(
        self,
        *,
        role: str,
        tool: str,
        target: str | None,
        outcome: str,
        code: str | None = None,
        session_id: str | None = None,
        source: str | None = None,
    ) -> None:
        """Append one access-log row; logging must never mask the operation."""
        try:
            self.session.index.log_access(
                source=source or role,
                role=role,
                tool=tool,
                target_path=target,
                outcome=outcome,
                code=code,
                session=session_id,
            )
        except Exception:  # noqa: BLE001 - best effort logging
            pass

    @staticmethod
    def _target_path(params: dict) -> str | None:
        """Pick the most relevant target path from a params mapping."""
        for key in ("path", "src", "target"):
            value = params.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _require(params: dict, key: str) -> Any:
        """Return ``params[key]`` or raise :class:`BadRequest` when absent/None."""
        if key not in params or params[key] is None:
            raise BadRequest("missing_param", details={"param": key})
        return params[key]

    @staticmethod
    def _text(value: Any, *, param: str) -> str:
        """Coerce a parameter to ``str`` or raise :class:`BadRequest`."""
        if not isinstance(value, str):
            raise BadRequest("param_must_be_string", details={"param": param})
        return value

    def _entry(self, row: dict[str, Any]) -> dict[str, Any]:
        """Shape a raw index row into the documented listing entry."""
        logical = row["logical_path"]
        name = "/" if logical == "/" else logical.rsplit("/", 1)[-1]
        try:
            tags = self.session.index.get_tags(logical)
        except Exception:  # noqa: BLE001 - tags are best effort metadata
            tags = []
        return {
            "name": name,
            "path": _api_path(logical),
            "is_dir": bool(row["is_dir"]),
            "size": int(row["size"]),
            "mtime": int(row["mtime"]),
            "sensitivity": row["sensitivity"],
            "tags": tags,
            "secret": row["sensitivity"] != "normal",
        }

    def _read_payload(self, logical: str, data: bytes, encoding: str) -> dict[str, Any]:
        """Build a read result from raw bytes and an encoding."""
        try:
            content = data.decode(encoding, errors="strict")
        except (UnicodeDecodeError, LookupError) as exc:
            raise BadRequest("decode_error", details={"encoding": encoding}) from exc
        row = self.session.index.require_file(logical)
        try:
            tags = self.session.index.get_tags(logical)
        except Exception:  # noqa: BLE001 - tags are best-effort metadata
            tags = []
        source_url = next(
            (tag[len("source:") :] for tag in tags if tag.startswith("source:")),
            None,
        )
        return {
            "path": _api_path(logical),
            "content": content,
            "sensitivity": row["sensitivity"],
            "size": int(row["size"]),
            "mtime": int(row["mtime"]),
            "created": int(row.get("created", row["mtime"])),
            "tags": tags,
            "source_url": source_url,
        }

    # -------------------------------------------------------------- handlers: vault
    def _h_status(self, params: dict, role: str, session_id: str) -> dict:
        return self.session.status()

    def _h_locked(self, params: dict, role: str, session_id: str) -> dict:
        return {"locked": bool(self.session.is_locked)}

    def _h_unlock(self, params: dict, role: str, session_id: str) -> dict:
        password = self._text(self._require(params, "password"), param="password")
        self.session.unlock(password)
        return {"locked": False, "status": self.session.status()}

    def _h_lock(self, params: dict, role: str, session_id: str) -> dict:
        self.session.lock()
        return {"locked": True}

    def _h_ping(self, params: dict, role: str, session_id: str) -> dict:
        return {"pong": True, "locked": bool(self.session.is_locked), "ts": now_ms()}

    # ------------------------------------------------------------ handlers: files
    def _h_list_folder(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(params.get("path", "/"), param="path"))
        result = self.session.list_folder(logical, source=role)
        note = None
        entries = [self._entry(row) for row in result["entries"]]
        if not self.session.is_locked:
            note = self.session.folder_note(logical, source=role)
            self._attach_notes(result["entries"], entries)
        return {
            "path": _api_path(result["path"]),
            "note": note,
            "entries": entries,
        }

    def _attach_notes(
        self, rows: list[dict[str, Any]], entries: list[dict[str, Any]]
    ) -> None:
        """Attach each child's note (file or folder) to its listing entry."""
        if self.session._store is None:
            return
        file_ids = [int(row["id"]) for row in rows if not int(row["is_dir"])]
        file_notes = self.session.store.get_file_notes(file_ids) if file_ids else {}
        for row, entry in zip(rows, entries):
            if int(row["is_dir"]):
                entry["note"] = self.session.store.get_folder_note(
                    str(row["logical_path"])
                )
            else:
                entry["note"] = file_notes.get(int(row["id"]))

    def _h_read_file(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        encoding = self._text(params.get("encoding", "utf-8"), param="encoding")
        data = self.session.read_file(logical, source=role, session=session_id)
        payload = self._read_payload(logical, data, encoding)
        try:
            payload["note"] = self.session.file_note(logical, source=role)
        except VaultError:  # noqa: BLE001 - the note is optional
            payload["note"] = None
        return payload

    def _h_read_lines(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        encoding = self._text(params.get("encoding", "utf-8"), param="encoding")
        start = int(params.get("start", 1))
        count = int(params.get("count", 200))
        data = self.session.read_file(logical, source=role, session=session_id)
        try:
            text = data.decode(encoding, errors="strict")
        except (UnicodeDecodeError, LookupError) as exc:
            raise BadRequest("decode_error", details={"encoding": encoding}) from exc
        lines = text.splitlines()
        start = max(1, start)
        chunk = lines[start - 1 : start - 1 + max(0, count)]
        return {
            "path": _api_path(logical),
            "start": start,
            "count": count,
            "text": "\n".join(chunk),
            "total_lines": len(lines),
        }

    def _h_write_file(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        content = self._text(self._require(params, "content"), param="content")
        encoding = self._text(params.get("encoding", "utf-8"), param="encoding")
        sensitivity = params.get("sensitivity")
        if sensitivity is not None:
            sensitivity = self._text(sensitivity, param="sensitivity")
        try:
            data = _decode_content(content, encoding)
        except ValueError as exc:
            raise BadRequest("encode_error", details={"encoding": encoding}) from exc
        created = self.session.index.get_file(logical) is None
        row = self.session.write_file(
            logical, data, source=role, sensitivity=sensitivity
        )
        return {
            "path": _api_path(logical),
            "size": int(row["size"]),
            "sensitivity": row["sensitivity"],
            "created": created,
        }

    def _h_write_lines(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        text = self._text(self._require(params, "text"), param="text")
        mode = self._text(params.get("mode", "append"), param="mode")
        at_line = params.get("at_line")
        row = self.session.write_lines(
            logical, text, mode=mode, at_line=at_line, source=role
        )
        return {
            "path": _api_path(logical),
            "size": int(row["size"]),
            "lines": len(text.splitlines()),
        }

    def _h_mkdir(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        self.session.mkdir(logical, source=role)
        return {"path": _api_path(logical), "created": True}

    def _h_file_ops(self, params: dict, role: str, session_id: str) -> dict:
        op = self._text(self._require(params, "op"), param="op")
        src = normalize_vault_path(self._text(self._require(params, "src"), param="src"))
        dst_raw = params.get("dst")
        dst = normalize_vault_path(dst_raw) if isinstance(dst_raw, str) else None
        recursive = bool(params.get("recursive", False))
        if op == "move":
            if dst is None:
                raise BadRequest("missing_param", details={"param": "dst"})
            self.session.move(src, dst, source=role)
            affected = 1
        elif op == "copy":
            if dst is None:
                raise BadRequest("missing_param", details={"param": "dst"})
            self.session.copy(src, dst, source=role)
            affected = 1
        elif op == "delete":
            result = self.session.delete(src, source=role, recursive=recursive)
            affected = int(result["deleted"])
        elif op == "mkdir":
            self.session.mkdir(src, source=role)
            affected = 1
        else:
            raise BadRequest("unknown_op", details={"op": op})
        return {
            "op": op,
            "src": _api_path(src),
            "dst": _api_path(dst) if dst is not None else None,
            "affected": affected,
        }

    def _h_set_sensitivity(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        level = self._text(self._require(params, "level"), param="level")
        old = self.session.index.require_file(logical)["sensitivity"]
        self.session.set_sensitivity(logical, level, source=role)
        return {"path": _api_path(logical), "from": old, "to": level}

    def _h_set_tags(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        tags = self._require(params, "tags")
        if not isinstance(tags, list):
            raise BadRequest("tags_must_be_list")
        self.session.set_tags(logical, [str(tag) for tag in tags], source=role)
        return {"path": _api_path(logical), "tags": [str(tag) for tag in tags]}

    def _h_folder_note(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        note = self.session.folder_note(logical, source=role)
        return {"path": _api_path(logical), "note": note}

    def _h_set_folder_note(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        text = self._text(self._require(params, "text"), param="text")
        self.session.set_folder_note(logical, text, source=role)
        return {"path": _api_path(logical), "updated": True}

    def _h_file_note(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        note = self.session.file_note(logical, source=role)
        return {"path": _api_path(logical), "note": note}

    def _h_set_file_note(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        text = self._text(self._require(params, "text"), param="text")
        self.session.set_file_note(logical, text, source=role)
        return {"path": _api_path(logical), "updated": True}

    def _h_digest(self, params: dict, role: str, session_id: str) -> dict:
        """One compact overview of a folder/file (notes + first lines), not N calls."""
        logical = normalize_vault_path(self._text(params.get("path", "/"), param="path"))
        depth = int(params.get("depth", 1))
        return self.session.digest(logical, depth=depth, source=role)

    def _h_versions(self, params: dict, role: str, session_id: str) -> dict:
        """List every stored version of a file (UI only; history is never exposed to MCP)."""
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        return self.session.versions(logical, source=role)

    def _h_version_text(self, params: dict, role: str, session_id: str) -> dict:
        """Return the text of one historical version (UI only)."""
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        version = int(self._require(params, "version"))
        encoding = self._text(params.get("encoding", "utf-8"), param="encoding")
        content = self.session.version_text(
            logical, version, source=role, encoding=encoding
        )
        return {
            "path": _api_path(logical),
            "version": version,
            "content": content,
        }

    def _h_diff(self, params: dict, role: str, session_id: str) -> dict:
        """Return a git-style diff between two versions (UI only)."""
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        from_version = int(self._require(params, "from_version"))
        to_version = int(self._require(params, "to_version"))
        result = self.session.diff(
            logical, from_version, to_version, source=role
        )
        result["path"] = _api_path(logical)
        return result

    # ------------------------------------------------------------ handlers: search
    @staticmethod
    def _prefix(params: dict) -> str | None:
        """Return the optional normalized ``path_prefix`` search scope."""
        raw = params.get("path_prefix") or params.get("path")
        if not isinstance(raw, str) or not raw.strip():
            return None
        return normalize_vault_path(raw)

    def _h_search_filenames(self, params: dict, role: str, session_id: str) -> dict:
        query = self._text(self._require(params, "query"), param="query")
        limit = int(params.get("limit", 50))
        results = self.session.search_filenames(
            query, limit=limit, path_prefix=self._prefix(params), source=role
        )
        return {"query": query, "count": len(results), "results": results}

    def _h_search_text(self, params: dict, role: str, session_id: str) -> dict:
        query = self._text(self._require(params, "query"), param="query")
        limit = int(params.get("limit", 50))
        results = self.session.search_text(
            query, limit=limit, path_prefix=self._prefix(params), source=role
        )
        return {"query": query, "count": len(results), "results": results}

    def _h_search_semantic(self, params: dict, role: str, session_id: str) -> dict:
        query = self._text(self._require(params, "query"), param="query")
        limit = int(params.get("limit", 50))
        results = self.session.search_semantic(
            query, limit=limit, path_prefix=self._prefix(params), source=role
        )
        return {"query": query, "count": len(results), "results": results}

    # ----------------------------------------------------------- handlers: secrets
    def _h_request_open_secret(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        result = self.session.request_open_secret(
            logical, source=ROLE_MCP, session=session_id
        )
        result["note"] = (
            "The user is asked to display it on their desktop; the content is never "
            "returned to the agent."
        )
        return result

    def _h_resolve_open_secret(self, params: dict, role: str, session_id: str) -> dict:
        request_id = self._text(
            self._require(params, "request_id"), param="request_id"
        )
        approved = bool(params.get("approved", False))
        return self.session.resolve_open_secret(request_id, approved=approved)

    def _h_pending_requests(self, params: dict, role: str, session_id: str) -> dict:
        return {"requests": self.session.pending_requests()}

    def _h_read_secret(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        encoding = self._text(params.get("encoding", "utf-8"), param="encoding")
        data = self.session.read_file(logical, source=ROLE_UI)
        return self._read_payload(logical, data, encoding)

    # ----------------------------------------------------------------- handlers: log
    def _h_access_log(self, params: dict, role: str, session_id: str) -> dict:
        limit = int(params.get("limit", 100))
        offset = int(params.get("offset", 0))
        source = params.get("source")
        outcome = params.get("outcome")
        rows = self.session.access_log(
            limit=limit,
            offset=offset,
            source=source if isinstance(source, str) else None,
            outcome=outcome if isinstance(outcome, str) else None,
        )
        entries = []
        for row in rows:
            entry = dict(row)
            entry["iso"] = _iso(row["ts"])
            entries.append(entry)
        return {"count": len(entries), "entries": entries}

    # -------------------------------------------------------------- handlers: misc
    def _h_get_settings(self, params: dict, role: str, session_id: str) -> dict:
        settings = json.loads(json.dumps(self.session.meta.settings))
        return settings

    def _h_set_settings(self, params: dict, role: str, session_id: str) -> dict:
        settings = self.session.meta.settings
        if "language" in params:
            settings["language"] = self._text(params["language"], param="language")
        if "auto_lock_seconds" in params:
            settings["auto_lock_seconds"] = int(params["auto_lock_seconds"])
        if "default_sensitivity" in params:
            level = self._text(params["default_sensitivity"], param="default_sensitivity")
            if level not in LEVELS:
                raise BadRequest("unknown_level", details={"level": level})
            settings["default_sensitivity"] = level
        semantic = params.get("semantic")
        if isinstance(semantic, dict):
            current = settings.setdefault("semantic", {})
            if "enabled" in semantic:
                current["enabled"] = bool(semantic["enabled"])
            if semantic.get("model"):
                current["model"] = self._text(semantic["model"], param="semantic.model")
            chunking = semantic.get("chunking")
            if chunking is not None:
                mode = self._text(chunking, param="semantic.chunking")
                if mode not in CHUNK_MODES:
                    raise BadRequest("unknown_chunking", details={"value": mode})
                current["chunking"] = mode
            db_path = semantic.get("db_path")
            if db_path is not None:
                current["db_path"] = self._text(db_path, param="semantic.db_path")
            states = semantic.get("folder_states")
            if states is not None:
                if not isinstance(states, dict):
                    raise BadRequest("folder_states_must_be_object")
                clean_states: dict[str, bool] = {}
                for key, value in states.items():
                    clean_states[normalize_folder_key(str(key))] = bool(value)
                current["folder_states"] = clean_states
        importer = params.get("import_joplin")
        if isinstance(importer, dict):
            current = settings.setdefault("import_joplin", {})
            if importer.get("mirror_root"):
                current["mirror_root"] = self._text(
                    importer["mirror_root"], param="import_joplin.mirror_root"
                )
            globs = importer.get("sensitive_globs")
            if isinstance(globs, list):
                current["sensitive_globs"] = [
                    self._text(str(item), param="import_joplin.sensitive_globs")
                    for item in globs
                    if str(item).strip()
                ]
        web = params.get("web")
        if isinstance(web, dict):
            current = settings.setdefault("web", {})
            if "enabled" in web:
                current["enabled"] = bool(web["enabled"])
            if "host" in web:
                current["host"] = self._text(web["host"], param="web.host")
            if "port" in web:
                try:
                    current["port"] = max(0, min(65535, int(web["port"])))
                except (TypeError, ValueError) as exc:
                    raise BadRequest("param_must_be_int", details={"param": "web.port"}) from exc
            if "allow_lan" in web:
                current["allow_lan"] = bool(web["allow_lan"])
            if "open_browser_on_start" in web:
                current["open_browser_on_start"] = bool(web["open_browser_on_start"])
        self.session.meta.save()
        if isinstance(semantic, dict):
            self.session.refresh_semantic_provider()
            if "db_path" in semantic:
                self.session.reload_semantic_store()
            if "folder_states" in semantic:
                self.session.prune_semantic_folders()
        return {"updated": True, "settings": json.loads(json.dumps(settings))}

    def _h_semantic_index(self, params: dict, role: str, session_id: str) -> dict:
        force = bool(params.get("force", False))
        # Only an explicit rebuild may reset a mismatched layout (with a snapshot).
        return self.session.index_semantics(
            force=force, allow_reset=True, reason="user_rebuild"
        )

    def _h_semantic_status(self, params: dict, role: str, session_id: str) -> dict:
        """Return the semantic index status (model, chunks, availability)."""
        return {"semantic": self.session.status()["semantic"]}

    def _h_semantic_reindex(self, params: dict, role: str, session_id: str) -> dict:
        """Re-embed everything, or just one folder/file subtree (``path``)."""
        prefix = self._prefix(params)
        force = bool(params.get("force", True))
        return self.session.index_semantics(
            force=force, prefix=prefix, allow_reset=True, reason="user_reindex"
        )

    def _h_semantic_cache_clear(self, params: dict, role: str, session_id: str) -> dict:
        """Delete the local embedding cache (rebuildable; never synced)."""
        return {"removed": self.session.clear_semantic_cache()}

    def _h_stats(self, params: dict, role: str, session_id: str) -> dict:
        status = self.session.status()
        return {
            "files": status["files"],
            "folders": status["folders"],
            "by_level": status["by_level"],
            "store": status["store"],
        }

    def _h_verify_blobs(self, params: dict, role: str, session_id: str) -> dict:
        self.session._require_unlocked()
        checked = 0
        bad: list[str] = []
        for row in self.session.index.walk("/"):
            if row.get("blob_id"):
                checked += 1
                if not self.session.fs.verify_blob(row):
                    bad.append(_api_path(row["logical_path"]))
        return {"checked": checked, "bad": bad}

    def _h_recent(self, params: dict, role: str, session_id: str) -> dict:
        limit = int(params.get("limit", 20))
        files = [
            row
            for row in self.session.index.walk("/")
            if not int(row["is_dir"])
        ]
        files.sort(key=lambda row: (int(row["mtime"]), row["logical_path"]), reverse=True)
        return {"entries": [self._entry(row) for row in files[: max(0, limit)]]}

    # --------------------------------------------------- handlers: aggregates (web)
    def _h_tree(self, params: dict, role: str, session_id: str) -> dict:
        """Return the folder tree with per-subtree note counts (metadata only).

        Used by the browser UI's sidebar; works while the vault is locked because it
        only reads names/levels from the plaintext index.
        """
        rows = list(self.session.index.walk("/"))
        nodes: dict[str, dict[str, Any]] = {}
        for row in rows:
            logical = row["logical_path"]
            if logical == "/":
                continue
            nodes[logical] = {
                "path": _api_path(logical),
                "name": logical.rsplit("/", 1)[-1],
                "is_dir": bool(row["is_dir"]),
                "sensitivity": row["sensitivity"],
                "size": int(row["size"]),
                "mtime": int(row["mtime"]),
                "note": None,
                "_id": int(row["id"]),
                "note_count": 0,
                "children": [],
            }
        roots: list[dict[str, Any]] = []
        for logical, node in nodes.items():
            parent = logical.rsplit("/", 1)[0] if "/" in logical else ""
            if parent and parent in nodes and nodes[parent]["is_dir"]:
                nodes[parent]["children"].append(node)
            else:
                roots.append(node)

        def _count(node: dict[str, Any]) -> int:
            """Return the number of note files in ``node``'s subtree."""
            if not node["is_dir"]:
                node["note_count"] = 0
                return 1
            total = 0
            for child in node["children"]:
                total += _count(child)
            node["note_count"] = total
            return total

        for root in roots:
            _count(root)

        def _sort(items: list[dict[str, Any]]) -> None:
            items.sort(key=lambda item: (not item["is_dir"], item["name"].lower()))
            for item in items:
                _sort(item["children"])

        _sort(roots)
        if not self.session.is_locked and self.session._store is not None:
            file_ids = [
                int(node["_id"]) for node in nodes.values() if not node["is_dir"]
            ]
            file_notes = self.session.store.get_file_notes(file_ids) if file_ids else {}
            for logical, node in nodes.items():
                if node["is_dir"]:
                    node["note"] = self.session.store.get_folder_note(logical)
                else:
                    node["note"] = file_notes.get(int(node["_id"]))
        for node in nodes.values():
            node.pop("_id", None)
        counts = self.session.index.count()
        return {
            "tree": roots,
            "counts": {
                "files": int(counts["files"]),
                "folders": int(counts["dirs"]),
                "by_level": counts["by_level"],
            },
        }

    def _h_all_tags(self, params: dict, role: str, session_id: str) -> dict:
        """Return every tag with its usage count."""
        rows = self.session.index.all_tags()
        return {
            "tags": [
                {"name": str(row["name"]), "count": int(row["count"])} for row in rows
            ]
        }

    def _h_files_by_tag(self, params: dict, role: str, session_id: str) -> dict:
        """Return every file carrying ``tag`` (metadata only)."""
        tag = self._text(self._require(params, "tag"), param="tag")
        rows = self.session.index.files_by_tag(tag)
        return {
            "tag": tag,
            "count": len(rows),
            "results": [self._entry(row) for row in rows],
        }

    # ------------------------------------------------------------------- routing
    _ROUTES: dict[str, tuple[Any, str]] = {
        "vault.status": (_h_status, _BOTH),
        "vault.locked": (_h_locked, _BOTH),
        "vault.unlock": (_h_unlock, _UI_ONLY),
        "vault.lock": (_h_lock, _UI_ONLY),
        "vault.ping": (_h_ping, _BOTH),
        "vault.list_folder": (_h_list_folder, _BOTH),
        "vault.read_file": (_h_read_file, _BOTH),
        "vault.read_lines": (_h_read_lines, _BOTH),
        "vault.write_file": (_h_write_file, _BOTH),
        "vault.write_lines": (_h_write_lines, _BOTH),
        "vault.mkdir": (_h_mkdir, _BOTH),
        "vault.file_ops": (_h_file_ops, _BOTH),
        "vault.set_sensitivity": (_h_set_sensitivity, _BOTH),
        "vault.set_tags": (_h_set_tags, _BOTH),
        "vault.folder_note": (_h_folder_note, _BOTH),
        "vault.set_folder_note": (_h_set_folder_note, _BOTH),
        "vault.file_note": (_h_file_note, _BOTH),
        "vault.set_file_note": (_h_set_file_note, _BOTH),
        "vault.digest": (_h_digest, _BOTH),
        "vault.versions": (_h_versions, _UI_ONLY),
        "vault.version_text": (_h_version_text, _UI_ONLY),
        "vault.diff": (_h_diff, _UI_ONLY),
        "vault.search_filenames": (_h_search_filenames, _BOTH),
        "vault.search_text": (_h_search_text, _BOTH),
        "vault.search_semantic": (_h_search_semantic, _BOTH),
        "vault.request_open_secret": (_h_request_open_secret, _MCP_ONLY),
        "vault.resolve_open_secret": (_h_resolve_open_secret, _UI_ONLY),
        "vault.pending_requests": (_h_pending_requests, _UI_ONLY),
        "vault.read_secret": (_h_read_secret, _UI_ONLY),
        "vault.access_log": (_h_access_log, _BOTH),
        "vault.get_settings": (_h_get_settings, _BOTH),
        "vault.set_settings": (_h_set_settings, _UI_ONLY),
        "vault.semantic_index": (_h_semantic_index, _UI_ONLY),
        "vault.semantic_status": (_h_semantic_status, _BOTH),
        "vault.semantic_reindex": (_h_semantic_reindex, _BOTH),
        "vault.semantic_cache_clear": (_h_semantic_cache_clear, _UI_ONLY),
        "vault.stats": (_h_stats, _BOTH),
        "vault.verify_blobs": (_h_verify_blobs, _UI_ONLY),
        "vault.recent": (_h_recent, _BOTH),
        "vault.tree": (_h_tree, _UI_ONLY),
        "vault.all_tags": (_h_all_tags, _BOTH),
        "vault.files_by_tag": (_h_files_by_tag, _BOTH),
    }


__all__ = [
    "Service",
    "ROLE_UI",
    "ROLE_MCP",
    "ROLES",
    "ActivityFeed",
    "ACTIVITY_LIMIT",
]
