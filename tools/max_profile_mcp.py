# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=1.2,<2"]
# ///
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""max_profile_mcp.py — MCP server for Max's self-knowledge, backed by Secure Vault.

The profile used to be served straight off the plaintext folders
``max_auto_bio/`` and ``hermes_knowing_from_max/`` under
``/data/Cloud/Documents/Writing/M. for me/hermes``.  Since Sep 2026 the live copy
lives **inside the encrypted vault** (default folder ``/max-profile``) and this
server reads it from there, so every profile read is encrypted at rest and lands
in the vault's append-only access log.  The plaintext folders stay behind as the
rebuild source (``tools/import_max_profile.py`` pushes them into the vault).

It talks to the running app over the local daemon socket (SPEC/02 §3:
newline-delimited JSON-RPC, ``mcp`` role token from ``runtime_dir()/tokens.json``).

The socket client is inlined on purpose: this server is launched with ``uv run``
(PEP 723 — stdlib + the ``mcp`` SDK only) and must not depend on the vault's own
venv.  The wire format is three fields wide and frozen; keep it in sync with
``src/vault/api/client.py``.

Tools: ``get_index`` · ``read_section`` · ``list_files`` · ``search`` ·
``write_section`` · ``get_stats`` — the same voice as before plus writes.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# --------------------------------------------------------------------- profile layout

ROOT = "/" + os.environ.get("SECURE_VAULT_PROFILE_ROOT", "max-profile").strip("/")
"""Vault folder holding the profile."""

SIDES = ("max_auto_bio", "hermes_knowing_from_max")
GATEWAY = "_index.md"
SENSITIVE = {"04_desires-shadows.md"}

mcp = FastMCP("max-profile")

# ------------------------------------------------------------------ vault socket client

SOCKET_FILENAME = "daemon.sock"
TOKENS_FILENAME = "tokens.json"


class VaultUnavailable(RuntimeError):
    """The app is not running, is locked, or refused our token."""


def _runtime_dir() -> Path:
    """Mirror ``vault.config.runtime_dir()`` — decrypted scratch lives outside the vault."""
    base = os.environ.get("XDG_RUNTIME_DIR")
    path = Path(base) / "secure-vault" if base else Path("/tmp") / f"secure-vault-{os.getuid()}"
    return path


def _token() -> str | None:
    """Read the current ``mcp`` role token (fresh every call: an app restart rotates it)."""
    try:
        data = json.loads((_runtime_dir() / TOKENS_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    token = data.get("mcp") if isinstance(data, dict) else None
    return token if isinstance(token, str) and token else None


def _roundtrip(method: str, params: dict, token: str | None) -> dict:
    """Send one request line to the daemon socket and return the decoded response."""
    request = {"id": 1, "token": token, "method": method, "params": params}
    payload = json.dumps(request, ensure_ascii=False).encode("utf-8") + b"\n"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(30.0)
    try:
        try:
            sock.connect(str(_runtime_dir() / SOCKET_FILENAME))
        except OSError as exc:
            raise VaultUnavailable(
                "VAULT_NOT_RUNNING: برنامهٔ Secure Vault در حال اجرا نیست — آن را باز کن "
                f"({exc})"
            ) from exc
        sock.sendall(payload)
        chunks = bytearray()
        while b"\n" not in chunks:
            block = sock.recv(65536)
            if not block:
                break
            chunks.extend(block)
    finally:
        sock.close()
    line = bytes(chunks).split(b"\n", 1)[0]
    if not line:
        raise VaultUnavailable("VAULT_NOT_RUNNING: پاسخ خالی از سوکت والت")
    return json.loads(line.decode("utf-8", errors="replace"))


def _call(method: str, params: dict | None = None) -> dict:
    """Forward one method to the daemon, retrying once with a freshly read token."""
    for attempt in (0, 1):
        response = _roundtrip(method, params or {}, _token())
        if response.get("ok"):
            result = response.get("result")
            return result if isinstance(result, dict) else {}
        error = response.get("error") or {}
        code = str(error.get("code", "ERROR"))
        message = str(error.get("message", code))
        # A rotated token means the app restarted after this process read tokens.json.
        if code == "UNAUTHORIZED" and attempt == 0:
            continue
        if code == "VAULT_LOCKED":
            raise VaultUnavailable(
                "VAULT_LOCKED: والت قفل است — در برنامه بازش کن (رمز اصلی) و دوباره صدا بزن"
            )
        if code == "VAULT_NOT_RUNNING":
            raise VaultUnavailable("VAULT_NOT_RUNNING: برنامهٔ Secure Vault در حال اجرا نیست")
        raise VaultUnavailable(f"{code}: {message}")
    raise VaultUnavailable("UNAUTHORIZED: توکن دسترسی به والت نامعتبر است")


# ---------------------------------------------------------------------------- helpers


def _vault_path(side: str, name: str = "") -> str:
    """Return the vault-absolute path of a side folder or one of its files."""
    if side not in SIDES:
        raise ValueError(f"side باید یکی از: {', '.join(SIDES)} باشد")
    return f"{ROOT}/{side}" + (f"/{name}" if name else "")


def _entries(side: str) -> list[dict]:
    """List one side folder as vault entries (empty list when it does not exist yet)."""
    try:
        listing = _call("vault.list_folder", {"path": _vault_path(side)})
    except VaultUnavailable as exc:
        if "NOT_FOUND" not in str(exc):
            raise
        return []
    return [e for e in listing.get("entries", []) if not e.get("is_dir") and e["name"].endswith(".md")]


def _info(entry: dict, side: str) -> dict:
    """Shape one vault entry like the pre-vault profile listing."""
    return {
        "name": entry["name"],
        "side": side,
        "path": entry["path"],
        "vault_path": entry["path"],
        "sensitive": entry["name"] in SENSITIVE,
        "chars": int(entry.get("size") or 0),
        "gateway": entry["name"] == GATEWAY,
        "sensitivity": entry.get("sensitivity", "normal"),
        "mtime": entry.get("mtime"),
    }


def _files(side: str) -> list[dict]:
    """All chapter entries of one side, sorted by name."""
    return [_info(e, side) for e in sorted(_entries(side), key=lambda e: e["name"])]


def _resolve_file(side: str, file: str) -> dict:
    """Normalize a chapter reference like '01', '01_core-identity', 'core-identity'."""
    stem = file.strip().rstrip(".md")
    files = _files(side)
    for entry in files:
        if entry["name"][:-3] == stem:
            return entry
    if stem.isdigit() and len(stem) == 2:
        for entry in files:
            if entry["name"].startswith(stem + "_"):
                return entry
    for entry in files:
        if stem in entry["name"]:
            return entry
    raise ValueError(
        f"فایلی مثل '{file}' در {side} پیدا نشد. فایل‌ها: "
        + ", ".join(e["name"] for e in files)
    )


def _read(path: str) -> str:
    """Read a vault file as text (``normal`` files only)."""
    return str(_call("vault.read_file", {"path": path}).get("content", ""))


def _hit(path: str, snippet: str, score: float | None, source: str) -> dict:
    """Shape one search hit the same way whichever engine produced it."""
    name = path.rsplit("/", 1)[-1]
    return {
        "name": name,
        "side": path.split("/")[-2],
        "path": path,
        "vault_path": path,
        "sensitive": name in SENSITIVE,
        "snippet": snippet,
        "score": score,
        "source": source,
    }


def _scan_sides(query: str, sides: tuple[str, ...], limit: int) -> list[dict]:
    """Literal substring scan of the profile files themselves (last-resort top-up).

    ``vault.search_text`` covers the whole vault, so a crowded page can push every
    profile hit out of the window; scanning the 16 profile files is exact and cheap.
    """
    needle = query.casefold()
    hits: list[dict] = []
    for side in sides:
        for entry in _files(side):
            text = _read(entry["path"])
            if needle not in text.casefold():
                continue
            snippet = next(
                (ln.strip()[:220] for ln in text.splitlines() if needle in ln.casefold()), ""
            )
            hits.append(_hit(entry["path"], snippet, None, "text-scan"))
            if len(hits) >= limit:
                return hits
    return hits


# ------------------------------------------------------------------------------- tools


@mcp.tool()
def get_index() -> dict:
    """نقشهٔ کل شناخت مکس (معادل خواندن _index.md ها): متن هر دو دروازه + فهرست فایل‌ها.
    اولین صدا همیشه این باشد؛ بعد فقط فصلِ مرتبط را بخوان."""
    sides: dict[str, dict] = {}
    for side in SIDES:
        files = _files(side)
        gateway = next((e for e in files if e["gateway"]), None)
        sides[side] = {
            "vault_path": _vault_path(side),
            "files": files,
            "index": _read(gateway["path"]) if gateway else None,
        }
    return {
        "root": ROOT,
        "backend": "secure-vault",
        "vault_home": _call("vault.status", {}).get("home"),
        "sides": list(SIDES),
        "indexes": sides,
        "note": "اول _index.md (دروازه) را بخوان، سپس فقط فصل مرتبط؛ "
        "04_desires-shadows.md حساس است.",
    }


@mcp.tool()
def list_files(side: str = "") -> dict:
    """فهرست فایل‌های یک شاخه (side = max_auto_bio یا hermes_knowing_from_max؛ خالی = هر دو)."""
    sides = SIDES if not side else (side,)
    return {"root": ROOT, "files": {s: _files(s) for s in sides}}


@mcp.tool()
def read_section(side: str, file: str) -> dict:
    """خواندن یک فصل. side = max_auto_bio | hermes_knowing_from_max | both.
    file = نام فایل یا عدد فصل ('01', '01_core-identity', 'core-identity')."""
    if side == "both":
        chapters = {}
        for s in SIDES:
            entry = _resolve_file(s, file)
            chapters[s] = {**entry, "content": _read(entry["path"])}
        return {
            "side": "both",
            "file": file,
            "sensitive": any(c["sensitive"] for c in chapters.values()),
            "chapters": chapters,
        }
    entry = _resolve_file(side, file)
    return {**entry, "side": side, "content": _read(entry["path"])}


@mcp.tool()
def search(query: str, side: str = "", limit: int = 20, mode: str = "auto") -> dict:
    """جستجو در پروفایل. mode = auto (پیش‌فرض) | index | semantic | text.
    auto: اول ایندکس متن و جستجوی معنایی والت، و اگر صفحه پر نشد، اسکنِ خودِ فایل‌ها.
    هر نتیجه source دارد: index | semantic | text-scan."""
    sides = SIDES if not side else (side,)
    prefixes = tuple(_vault_path(s) + "/" for s in sides)
    results: list[dict] = []
    seen: set[str] = set()
    window = max(limit * 10, 200)

    def absorb(raw: dict, source: str) -> None:
        for hit in raw.get("results", []):
            path = hit.get("logical_path") or hit.get("path") or ""
            if not path.startswith(prefixes) or path in seen:
                continue
            seen.add(path)
            results.append(_hit(path, hit.get("snippet", ""), hit.get("score"), source))

    if mode in ("auto", "index"):
        absorb(_call("vault.search_text", {"query": query, "limit": window}), "index")
    if mode in ("auto", "semantic"):
        try:
            absorb(_call("vault.search_semantic", {"query": query, "limit": window}), "semantic")
        except VaultUnavailable:
            pass  # semantic search is opt-in; the other engines still answer
    if mode in ("auto", "text") and len(results) < limit:
        for hit in _scan_sides(query, sides, limit):
            if hit["path"] not in seen:
                seen.add(hit["path"])
                results.append(hit)

    return {
        "query": query,
        "mode": mode,
        "count": len(results[:limit]),
        "results": results[:limit],
        "note": "search_text/search_semantic کل والت را می‌گردند و محدود به این پوشه نیستند؛ "
        "پس در حالت auto نتیجه‌های این پوشه با اسکن مستقیم کامل می‌شوند.",
    }


@mcp.tool()
def write_section(side: str, file: str, content: str) -> dict:
    """نوشتن/به‌روزرسانی یک فصل داخل والت (فقط فایل‌های normal).
    برای به‌روزرسانی «hermes_knowing_from_max» از گفتگوهای عمیق استفاده شود."""
    if not file.endswith(".md"):
        file = file + ".md"
    if "/" in file or file.startswith("."):
        raise ValueError("نام فایل باید ساده باشد (بدون مسیر)")
    entry = _resolve_file(side, file) if _entries(side) else None
    target = entry["path"] if entry else _vault_path(side, file)
    result = _call(
        "vault.write_file",
        {"path": target, "content": content, "sensitivity": "normal"},
    )
    return {
        "path": target,
        "vault_path": target,
        "sensitive": file in SENSITIVE,
        "created": bool(result.get("created")),
        "size": result.get("size"),
    }


@mcp.tool()
def get_stats() -> dict:
    """آمار کلی: تعداد فایل‌ها و حجم هر شاخه (از خود والت)."""
    status = _call("vault.status", {})
    sides = {}
    for side in SIDES:
        files = _files(side)
        sides[side] = {
            "vault_path": _vault_path(side),
            "files": len(files),
            "total_chars": sum(e["chars"] for e in files),
        }
    return {
        "root": ROOT,
        "backend": "secure-vault",
        "vault_home": status.get("home"),
        "locked": status.get("locked"),
        "vault_files": status.get("files"),
        "sides": sides,
    }


if __name__ == "__main__":
    mcp.run()
