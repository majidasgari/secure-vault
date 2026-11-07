#!/usr/bin/env python3
"""Minimal stdio driver for the max-profile MCP server.

Why this exists: the `mcp_max_profile_*` tools only load into a Hermes session at
session start. In a session that began before the server was reachable they are
absent, and the server can still be driven directly over stdio.

Usage:
    cd /d/Codes/Personal/secure-vault && unset PYTHONPATH
    ./mcp/.venv/Scripts/python.exe tools/mcp_stdio_call.py <tool> '<json-args>'

Examples:
    ... tools/mcp_stdio_call.py get_index '{}'
    ... tools/mcp_stdio_call.py get_stats '{}'
    ... tools/mcp_stdio_call.py read_section '{"side":"max_auto_bio","file":"01_core-identity.md"}'
    ... tools/mcp_stdio_call.py search '{"query":"آرامش","limit":5}'

Requires the vault app running and unlocked; otherwise the tool answers
VAULT_NOT_RUNNING / VAULT_LOCKED (which the driver prints verbatim).
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

CANDIDATES = [
    os.path.join(HERE, "max_profile_mcp.py"),
    os.path.join(REPO, "tools", "max_profile_mcp.py"),
]
SERVER = next((p for p in CANDIDATES if os.path.exists(p)), CANDIDATES[0])

PY = os.path.join(REPO, "mcp", ".venv", "Scripts", "python.exe")
if not os.path.exists(PY):
    PY = sys.executable


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    tool = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}

    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "hermes-driver", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": tool, "arguments": args}},
    ]
    payload = "\n".join(json.dumps(r) for r in reqs) + "\n"

    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    p = subprocess.run([PY, SERVER], input=payload, capture_output=True,
                       text=True, encoding="utf-8", timeout=180, env=env)

    for line in p.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        if msg.get("id") != 2:
            continue
        if msg.get("error"):
            print("ERROR:", json.dumps(msg["error"], ensure_ascii=False))
            return 1
        result = msg.get("result", {})
        for part in result.get("content", []):
            print(part.get("text", ""))
        if result.get("isError"):
            return 1
        return 0

    print("no response from server; stderr:\n" + (p.stderr or "").strip(), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
