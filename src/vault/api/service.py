"""The shared, transport-independent command surface (SPEC/02 §1).

:class:`Service` wraps a :class:`~vault.core.session.VaultSession` and routes the exact
commands the two transports (the local socket and the in-process UI) need. ``role`` is
supplied by the transport — never by client data — and decides both policy enforcement
and the ``source`` recorded in the append-only access log.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from ..core import semantics
from ..core.security import SOURCE_MCP, SOURCE_UI
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

SecretRequestCallback = Callable[[dict[str, Any]], Any]

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
        self, method: str, params: dict, *, role: str, session_id: str
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
        return {
            "path": _api_path(logical),
            "content": content,
            "sensitivity": row["sensitivity"],
            "size": int(row["size"]),
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
        if not self.session.is_locked:
            note = self.session.folder_note(logical, source=role)
        return {
            "path": _api_path(result["path"]),
            "note": note,
            "entries": [self._entry(row) for row in result["entries"]],
        }

    def _h_read_file(self, params: dict, role: str, session_id: str) -> dict:
        logical = normalize_vault_path(self._text(self._require(params, "path"), param="path"))
        encoding = self._text(params.get("encoding", "utf-8"), param="encoding")
        data = self.session.read_file(logical, source=role, session=session_id)
        return self._read_payload(logical, data, encoding)

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
            data = content.encode(encoding, errors="strict")
        except (UnicodeEncodeError, LookupError) as exc:
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

    # ------------------------------------------------------------ handlers: search
    def _h_search_filenames(self, params: dict, role: str, session_id: str) -> dict:
        query = self._text(self._require(params, "query"), param="query")
        limit = int(params.get("limit", 50))
        results = self.session.search_filenames(query, limit=limit, source=role)
        return {"query": query, "count": len(results), "results": results}

    def _h_search_text(self, params: dict, role: str, session_id: str) -> dict:
        query = self._text(self._require(params, "query"), param="query")
        limit = int(params.get("limit", 50))
        results = self.session.search_text(query, limit=limit, source=role)
        return {"query": query, "count": len(results), "results": results}

    def _h_search_semantic(self, params: dict, role: str, session_id: str) -> dict:
        query = self._text(self._require(params, "query"), param="query")
        limit = int(params.get("limit", 50))
        results = self.session.search_semantic(query, limit=limit, source=role)
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
        semantic = params.get("semantic")
        if isinstance(semantic, dict):
            current = settings.setdefault("semantic", {})
            if "enabled" in semantic:
                current["enabled"] = bool(semantic["enabled"])
        self.session.meta.save()
        return {"updated": True, "settings": json.loads(json.dumps(settings))}

    def _h_semantic_index(self, params: dict, role: str, session_id: str) -> dict:
        force = bool(params.get("force", False))
        return semantics.index_all(self.session, force=force)

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
        "vault.stats": (_h_stats, _BOTH),
        "vault.verify_blobs": (_h_verify_blobs, _UI_ONLY),
        "vault.recent": (_h_recent, _BOTH),
    }


__all__ = ["Service", "ROLE_UI", "ROLE_MCP", "ROLES"]
