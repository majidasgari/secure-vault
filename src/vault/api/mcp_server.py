"""MCP over stdio with no external dependencies (SPEC/02 §4).

Implements JSON-RPC 2.0 for the ``stdio`` transport used by Claude/Hermes: it accepts
newline-delimited JSON and LSP-style ``Content-Length`` framing, and always emits
newline-delimited JSON on stdout. Diagnostics go to stderr only.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from typing import Any, BinaryIO, Callable

from .. import __version__
from ..errors import VaultError, VaultLocked, VaultNotRunning
from .client import VaultClient

SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

INSTRUCTIONS = (
    "Personal encrypted vault. Content of secret/secretfile files is never returned to "
    "agents; use request_open_secret for secretfile."
)

# JSON-RPC error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
SERVER_ERROR = -32000


class _RPCError(Exception):
    """A JSON-RPC level error (never a tool-level failure)."""

    def __init__(self, code: int, message: str, data: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


# --------------------------------------------------------------------------- tools
def _forward(method: str) -> Callable[[VaultClient, dict], dict]:
    """Build a tool caller that forwards its arguments to ``method`` unchanged."""

    def call(client: VaultClient, arguments: dict) -> dict:
        return client.call(method, arguments)

    return call


def _vault_status(client: VaultClient, arguments: dict) -> dict:
    """Return the status payload with the daemon liveness marker."""
    payload = dict(client.call("vault.status", {}))
    payload["daemon"] = {"running": True}
    return payload


def _tool(
    name: str,
    description: str,
    properties: dict[str, Any],
    required: list[str],
    call: Callable[[VaultClient, dict], dict],
) -> dict[str, Any]:
    """Build an internal tool specification (``call`` is stripped from the wire form)."""
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
        "call": call,
    }


_TOOL_SPECS: list[dict[str, Any]] = [
    _tool(
        "vault_status",
        "Return vault status and daemon liveness. Works while locked (metadata only).",
        {},
        [],
        _vault_status,
    ),
    _tool(
        "list_folder",
        "List the direct children of a vault folder. Names and sensitivity levels are "
        "visible for every level; content is not returned.",
        {"path": {"type": "string", "default": "/"}},
        [],
        _forward("vault.list_folder"),
    ),
    _tool(
        "read_file",
        "Read the content of a normal file. secret/secretfile content is denied to agents.",
        {
            "path": {"type": "string"},
            "encoding": {"type": "string", "default": "utf-8"},
        },
        ["path"],
        _forward("vault.read_file"),
    ),
    _tool(
        "read_lines",
        "Read a range of lines from a normal file. secret/secretfile content is denied.",
        {
            "path": {"type": "string"},
            "start": {"type": "integer", "default": 1},
            "count": {"type": "integer", "default": 200},
        },
        ["path"],
        _forward("vault.read_lines"),
    ),
    _tool(
        "write_file",
        "Write a file. Agents may only create normal files; raising the level of an "
        "existing file is allowed, lowering is not.",
        {
            "path": {"type": "string"},
            "content": {"type": "string"},
            "encoding": {"type": "string", "default": "utf-8"},
            "sensitivity": {
                "type": "string",
                "enum": ["normal", "secret", "secretfile"],
                "default": "normal",
            },
        },
        ["path", "content"],
        _forward("vault.write_file"),
    ),
    _tool(
        "write_lines",
        "Append, prepend or insert lines into a file. Agents may only create normal files.",
        {
            "path": {"type": "string"},
            "text": {"type": "string"},
            "mode": {
                "type": "string",
                "enum": ["append", "prepend", "insert"],
                "default": "append",
            },
            "at_line": {"type": "integer"},
        },
        ["path", "text"],
        _forward("vault.write_lines"),
    ),
    _tool(
        "mkdir",
        "Create a folder (and any missing parents).",
        {"path": {"type": "string"}},
        ["path"],
        _forward("vault.mkdir"),
    ),
    _tool(
        "file_ops",
        "Move, copy, delete or create a folder. Deleting a non-empty folder needs "
        "recursive=true.",
        {
            "op": {"type": "string", "enum": ["move", "copy", "delete", "mkdir"]},
            "src": {"type": "string"},
            "dst": {"type": "string"},
            "recursive": {"type": "boolean", "default": False},
        },
        ["op", "src"],
        _forward("vault.file_ops"),
    ),
    _tool(
        "set_sensitivity",
        "Raise the sensitivity of a file. Agents may raise but never lower a level; "
        "lowering returns SENSITIVITY_DOWNGRADE_FORBIDDEN.",
        {
            "path": {"type": "string"},
            "level": {"type": "string", "enum": ["normal", "secret", "secretfile"]},
        },
        ["path", "level"],
        _forward("vault.set_sensitivity"),
    ),
    _tool(
        "search_filenames",
        "Search file and folder names (all levels, including secret). Works while locked.",
        {
            "query": {"type": "string"},
            "limit": {"type": "integer", "default": 50},
        },
        ["query"],
        _forward("vault.search_filenames"),
    ),
    _tool(
        "search_text",
        "Search literal content of normal files only. secret/secretfile content is never "
        "searchable.",
        {
            "query": {"type": "string"},
            "limit": {"type": "integer", "default": 50},
        },
        ["query"],
        _forward("vault.search_text"),
    ),
    _tool(
        "search_semantic",
        "Semantic search over normal files only (requires an embedding provider).",
        {
            "query": {"type": "string"},
            "limit": {"type": "integer", "default": 50},
        },
        ["query"],
        _forward("vault.search_semantic"),
    ),
    _tool(
        "read_folder_note",
        "Read the note attached to a folder.",
        {"path": {"type": "string"}},
        ["path"],
        _forward("vault.folder_note"),
    ),
    _tool(
        "write_folder_note",
        "Attach or replace the note on a folder.",
        {"path": {"type": "string"}, "text": {"type": "string"}},
        ["path", "text"],
        _forward("vault.set_folder_note"),
    ),
    _tool(
        "request_open_secret",
        "Ask the user to display a secretfile on their desktop. The content is never "
        "returned to the agent.",
        {"path": {"type": "string"}},
        ["path"],
        _forward("vault.request_open_secret"),
    ),
    _tool(
        "get_access_log",
        "Read the append-only access log (newest first).",
        {
            "limit": {"type": "integer", "default": 100},
            "offset": {"type": "integer", "default": 0},
            "source": {"type": "string", "enum": ["ui", "mcp", "socket"]},
            "outcome": {"type": "string", "enum": ["allow", "deny", "error"]},
        },
        [],
        _forward("vault.access_log"),
    ),
]

_TOOL_MAP: dict[str, dict[str, Any]] = {spec["name"]: spec for spec in _TOOL_SPECS}


def _wire_tools() -> list[dict[str, Any]]:
    """Return the tool specifications without the internal ``call`` key."""
    return [
        {key: value for key, value in spec.items() if key != "call"}
        for spec in _TOOL_SPECS
    ]


RESOURCES: list[dict[str, Any]] = [
    {"uri": "vault://status", "name": "Vault status", "mimeType": "application/json"},
    {"uri": "vault://root", "name": "Vault root", "mimeType": "application/json"},
    {"uri": "vault://recent", "name": "Recent files", "mimeType": "application/json"},
]

RESOURCE_TEMPLATES: list[dict[str, Any]] = [
    {
        "uriTemplate": "vault://folder/{path}",
        "name": "Folder listing",
        "mimeType": "application/json",
    },
    {
        "uriTemplate": "vault://note/{path}",
        "name": "Note content",
        "mimeType": "text/markdown",
    },
    {
        "uriTemplate": "vault://search?q={query}",
        "name": "Content search",
        "mimeType": "application/json",
    },
    {
        "uriTemplate": "vault://log?limit={n}",
        "name": "Access log",
        "mimeType": "application/json",
    },
]


def _tool_error(exc: VaultError) -> dict[str, Any]:
    """Build the MCP tool-level error payload (``isError: true``)."""
    return {
        "content": [{"type": "text", "text": f"{exc.code}: {exc.message}"}],
        "isError": True,
        "structuredContent": {
            "code": exc.code,
            "message": exc.message,
            "details": exc.details,
        },
    }


class MCPServer:
    """MCP stdio server that forwards every request to a :class:`VaultClient`."""

    def __init__(
        self,
        client: VaultClient,
        *,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
        stderr: Any | None = None,
        debug: bool = False,
    ) -> None:
        """Bind the server to ``client`` and the stdio streams."""
        self.client = client
        self._in = stdin if stdin is not None else sys.stdin.buffer
        self._out = stdout if stdout is not None else sys.stdout.buffer
        self._err = stderr if stderr is not None else sys.stderr
        self.debug = debug

    # ------------------------------------------------------------------ transport
    def serve(self) -> int:
        """Read messages until EOF and return the process exit code."""
        while True:
            raw = self._read_message()
            if raw is None:
                return 0
            try:
                message = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                self._diag(f"parse error: {exc!r}")
                self._write(
                    self._error_envelope(None, PARSE_ERROR, "Parse error")
                )
                continue
            response = self.handle_message(message)
            if response is not None:
                self._write(response)

    def _read_message(self) -> bytes | None:
        """Read one message, accepting newline JSON or LSP ``Content-Length`` framing."""
        while True:
            line = self._in.readline()
            if not line:
                return None
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.lower().startswith(b"content-length:"):
                try:
                    length = int(stripped.split(b":", 1)[1].strip())
                except (ValueError, IndexError):
                    return stripped
                while True:
                    header = self._in.readline()
                    if not header or header.strip() == b"":
                        break
                return self._in.read(length)
            return stripped

    def _write(self, obj: dict[str, Any]) -> None:
        """Emit one newline-delimited JSON object on stdout."""
        data = json.dumps(obj, ensure_ascii=False) + "\n"
        self._out.write(data.encode("utf-8"))
        self._out.flush()

    def _diag(self, text: str) -> None:
        """Write a diagnostic line to stderr (never stdout)."""
        try:
            self._err.write(f"[secure-vault-mcp] {text}\n")
            self._err.flush()
        except Exception:  # noqa: BLE001 - diagnostics must never break the protocol
            pass

    # ------------------------------------------------------------------ protocol
    def handle_message(self, message: Any) -> dict[str, Any] | None:
        """Handle one decoded JSON-RPC message; return a response or None."""
        if not isinstance(message, dict):
            return self._error_envelope(None, INVALID_REQUEST, "Invalid request")
        has_id = "id" in message
        request_id = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            if has_id:
                return self._error_envelope(request_id, INVALID_REQUEST, "Invalid request")
            return None
        if not has_id:
            self._handle_notification(method, message.get("params") or {})
            return None
        try:
            result = self._dispatch(method, message.get("params") or {})
        except _RPCError as exc:
            return self._error_envelope(request_id, exc.code, exc.message, exc.data)
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the client
            self._diag(f"internal error in {method}: {exc!r}")
            return self._error_envelope(
                request_id, SERVER_ERROR, "internal_error", {"code": "ERROR"}
            )
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _handle_notification(self, method: str, params: Any) -> None:
        """Handle notifications (no response is ever sent)."""
        if method == "notifications/initialized":
            self._diag("client initialized")
        else:
            self._diag(f"ignored notification: {method}")

    def _dispatch(self, method: str, params: Any) -> Any:
        """Route a request method to its handler."""
        if not isinstance(params, dict):
            params = {}
        if method == "initialize":
            return self._initialize(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": _wire_tools()}
        if method == "tools/call":
            return self._tools_call(params)
        if method == "resources/list":
            return {"resources": RESOURCES}
        if method == "resources/templates/list":
            return {"resourceTemplates": RESOURCE_TEMPLATES}
        if method == "resources/read":
            return self._resources_read(params)
        if method == "resources/subscribe":
            raise _RPCError(METHOD_NOT_FOUND, "resources/subscribe is not supported")
        if method == "prompts/list":
            return {"prompts": []}
        if method == "logging/setLevel":
            return {}
        raise _RPCError(METHOD_NOT_FOUND, f"unknown method: {method}")

    def _initialize(self, params: dict) -> dict:
        """Build the ``initialize`` result, negotiating the protocol version."""
        requested = params.get("protocolVersion")
        version = (
            requested
            if requested in SUPPORTED_PROTOCOL_VERSIONS
            else DEFAULT_PROTOCOL_VERSION
        )
        return {
            "protocolVersion": version,
            "capabilities": {
                "tools": {},
                "resources": {"listChanged": False},
                "prompts": {},
            },
            "serverInfo": {"name": "secure-vault", "version": __version__},
            "instructions": INSTRUCTIONS,
        }

    def _tools_call(self, params: dict) -> dict:
        """Handle ``tools/call``: tool failures are ``isError``, protocol ones -32602."""
        name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        spec = _TOOL_MAP.get(name) if isinstance(name, str) else None
        if spec is None:
            raise _RPCError(INVALID_PARAMS, f"unknown tool: {name}")
        required = spec["inputSchema"].get("required", [])
        missing = [key for key in required if key not in arguments or arguments[key] is None]
        if missing:
            raise _RPCError(
                INVALID_PARAMS, f"missing required argument(s): {', '.join(missing)}"
            )
        try:
            payload = spec["call"](self.client, arguments)
        except VaultNotRunning as exc:
            raise _RPCError(SERVER_ERROR, exc.message, exc.to_dict()) from exc
        except VaultLocked as exc:
            raise _RPCError(SERVER_ERROR, exc.message, exc.to_dict()) from exc
        except VaultError as exc:
            return _tool_error(exc)
        if not isinstance(payload, dict):
            payload = {"result": payload}
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": payload,
            "isError": False,
        }

    def _resources_read(self, params: dict) -> dict:
        """Handle ``resources/read`` for the ``vault://`` URI scheme."""
        uri = params.get("uri")
        if not isinstance(uri, str) or not uri:
            raise _RPCError(INVALID_PARAMS, "missing uri")
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme != "vault":
            raise _RPCError(INVALID_PARAMS, f"unsupported uri scheme: {uri}")
        kind = parsed.netloc
        path = urllib.parse.unquote(parsed.path)
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if kind == "status":
                payload = dict(self.client.call("vault.status", {}))
                payload.setdefault("daemon", {"running": True})
                mime = "application/json"
            elif kind == "root":
                payload = self.client.call("vault.list_folder", {"path": "/"})
                mime = "application/json"
            elif kind == "recent":
                payload = self.client.call("vault.recent", {"limit": 20})
                mime = "application/json"
            elif kind == "folder":
                payload = self.client.call("vault.list_folder", {"path": path or "/"})
                mime = "application/json"
            elif kind == "note":
                payload = self.client.call("vault.read_file", {"path": path})
                mime = "text/markdown" if path.endswith(".md") else "text/plain"
            elif kind == "search":
                payload = self.client.call(
                    "vault.search_text", {"query": (query.get("q") or [""])[0]}
                )
                mime = "application/json"
            elif kind == "log":
                try:
                    limit = int((query.get("limit") or ["100"])[0])
                except ValueError:
                    limit = 100
                payload = self.client.call("vault.access_log", {"limit": limit})
                mime = "application/json"
            else:
                raise _RPCError(INVALID_PARAMS, f"unknown resource: {uri}")
        except VaultNotRunning as exc:
            raise _RPCError(SERVER_ERROR, exc.message, exc.to_dict()) from exc
        except VaultError as exc:
            raise _RPCError(SERVER_ERROR, exc.message, exc.to_dict()) from exc
        text = (
            json.dumps(payload, ensure_ascii=False, indent=2)
            if mime == "application/json"
            else str(payload.get("content", ""))
        )
        return {"contents": [{"uri": uri, "mimeType": mime, "text": text}]}

    @staticmethod
    def _error_envelope(
        request_id: Any, code: int, message: str, data: dict | None = None
    ) -> dict[str, Any]:
        """Build a JSON-RPC error response envelope."""
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}


__all__ = [
    "MCPServer",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "DEFAULT_PROTOCOL_VERSION",
    "INSTRUCTIONS",
]
