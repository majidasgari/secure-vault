# ORCHESTRATOR-OWNED black-box verification of the P2 interfaces (daemon socket + MCP bridge).
# Reference script; run via tests/test_api_invariants.py. Do not weaken the assertions.

#!/usr/bin/env python3
"""Independent adversarial verification of P2 (orchestrator-written, black-box).

Drives the real headless daemon over its real Unix socket and the real MCP stdio bridge.
"""
from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, signal, traceback
from pathlib import Path

ROOT = Path("/data/Codes/secure-vault")
sys.path.insert(0, str(ROOT / "src"))
PY = ROOT / ".venv" / "bin" / "python"
PW = "verify-p2-passphrase"

tmp = Path(tempfile.mkdtemp(prefix="sv-p2-"))
rt = tmp / "runtime"; rt.mkdir(mode=0o700)
rt_locked = tmp / "runtime-locked"; rt_locked.mkdir(mode=0o700)
home = tmp / "home"
pwfile = tmp / "pw"; pwfile.write_text(PW); os.chmod(pwfile, 0o600)
env = dict(os.environ, XDG_RUNTIME_DIR=str(rt), SECURE_VAULT_HOME=str(home), PYTHONPATH=str(ROOT / "src"))

PASS, FAIL = [], []
def check(name, fn):
    try:
        fn(); PASS.append(name); print(f"PASS  {name}")
    except Exception as e:
        FAIL.append((name, e)); print(f"FAIL  {name}: {type(e).__name__}: {e}")
        traceback.print_exc(limit=4)

def raw_call(sock_path, obj, timeout=20):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(timeout)
    s.connect(str(sock_path))
    s.sendall((json.dumps(obj) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk: break
        buf += chunk
    s.close()
    return json.loads(buf.decode().splitlines()[0])

def start_daemon(env_over, unlock=True, extra=()):
    cmd = [str(PY), "-m", "vault.daemon", "--home", str(home), "--json-events"]
    if unlock: cmd += ["--unlock-file", str(pwfile)]
    cmd += list(extra)
    p = subprocess.Popen(cmd, env=env_over, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(ROOT))
    # wait for the ready event
    deadline = time.time() + 45
    sock_path = Path(env_over["XDG_RUNTIME_DIR"]) / "secure-vault" / "daemon.sock"
    while time.time() < deadline:
        if p.poll() is not None:
            raise AssertionError(f"daemon exited early rc={p.returncode}: {p.stderr.read()[-800:]}")
        if sock_path.exists():
            try:
                r = raw_call(sock_path, {"id": 1, "token": "x", "method": "vault.ping", "params": {}})
                if r.get("error", {}).get("code") == "UNAUTHORIZED":
                    return p, sock_path, Path(env_over["XDG_RUNTIME_DIR"]) / "secure-vault"
            except Exception:
                pass
        time.sleep(0.3)
    raise AssertionError("daemon did not become ready in time")

def token_of(rundir: Path) -> str:
    return json.loads((rundir / "tokens.json").read_text())["mcp"]

state = {}
def t01_start_and_perms():
    from vault.core.session import VaultSession
    s = VaultSession.create(home, PW)
    s.write_file("/notes/hello.md", b"# hello\nbody-one")
    s.write_file("/secrets/creds.md", b"username: a\npassword: hunter2-zzz", source="ui")
    s.set_sensitivity("/secrets/creds.md", "secretfile")
    s.write_file("/notes/hidden.md", b"hidden-body-marker")
    s.set_sensitivity("/notes/hidden.md", "secret")
    s.close()
    p, sock, rundir = start_daemon(env)
    state.update(p=p, sock=sock, rundir=rundir, token=token_of(rundir))
    assert (rundir / "tokens.json").exists()
    assert (rundir / "tokens.json").stat().st_mode & 0o777 == 0o600, "tokens.json mode wrong"
    assert sock.stat().st_mode & 0o777 == 0o600, f"socket mode {oct(sock.stat().st_mode & 0o777)}"
check("01 daemon starts, socket+tokens 0600", t01_start_and_perms)

def t02_bad_token():
    r = raw_call(state["sock"], {"id": 1, "token": "deadbeef", "method": "vault.status", "params": {}})
    assert r.get("ok") is False and r["error"]["code"] == "UNAUTHORIZED", r
    r = raw_call(state["sock"], {"id": 2, "method": "vault.status", "params": {}})
    assert r["error"]["code"] == "UNAUTHORIZED", r
    # malformed line
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(str(state["sock"]))
    s.sendall(b"not-json-at-all\n"); buf = s.recv(65536); s.close()
    got = json.loads(buf.decode().splitlines()[0])
    assert got["error"]["code"] == "BAD_REQUEST", got
check("02 token auth + malformed line", t02_bad_token)

def t03_role_enforcement():
    tok = state["token"]
    for method in ("vault.unlock", "vault.lock", "vault.read_secret", "vault.set_settings",
                   "vault.resolve_open_secret", "vault.pending_requests", "vault.verify_blobs"):
        r = raw_call(state["sock"], {"id": 3, "token": tok, "method": method, "params": {"password": PW, "path": "/secrets/creds.md"}})
        assert r.get("ok") is False, f"{method} unexpectedly allowed: {r}"
        assert r["error"]["code"] == "PERMISSION_DENIED", f"{method}: {r}"
    # ui-only methods are NOT reachable over the socket at all
    for method in ("vault.ping", "vault.status", "vault.list_folder"):
        r = raw_call(state["sock"], {"id": 4, "token": tok, "method": method, "params": {"path": "/"}})
        assert r.get("ok") is True, f"{method} denied: {r}"
check("03 mcp token cannot call ui-only methods", t03_role_enforcement)

def t04_content_and_policy_over_socket():
    tok = state["token"]
    def call(method, **params):
        r = raw_call(state["sock"], {"id": 5, "token": tok, "method": method, "params": params})
        if not r.get("ok"):
            code = r["error"]["code"]
            raise getattr(__import__("vault.errors", fromlist=["x"]), "VaultError")(code) if False else RuntimeError(f"{code}: {r['error']['message']}")
        return r["result"]
    assert call("vault.read_file", path="/notes/hello.md")["content"].startswith("# hello")
    call("vault.write_file", path="/notes/new.md", content="written-by-agent")
    assert call("vault.read_file", path="/notes/new.md")["content"] == "written-by-agent"
    try:
        call("vault.read_file", path="/notes/hidden.md")
    except RuntimeError as e:
        assert "PERMISSION_DENIED" in str(e), e
    else:
        raise AssertionError("agent read a secret file")
    try:
        call("vault.read_file", path="/secrets/creds.md")
    except RuntimeError as e:
        assert "PERMISSION_DENIED" in str(e), e
    else:
        raise AssertionError("agent read a secretfile")
    call("vault.set_sensitivity", path="/notes/new.md", level="secret")
    try:
        call("vault.set_sensitivity", path="/notes/new.md", level="normal")
    except RuntimeError as e:
        assert "SENSITIVITY_DOWNGRADE_FORBIDDEN" in str(e), e
    else:
        raise AssertionError("agent lowered a level")
    # searches
    res = call("vault.search_filenames", query="creds")
    assert res["results"], f"filename search missed a secretfile: {res}"
    res = call("vault.search_text", query="hidden-body-marker")
    assert not res["results"], f"secret body searchable: {res}"
    res = call("vault.search_text", query="body-one")
    assert res["results"], f"normal body not searchable: {res}"
    # secret request: never returns content
    res = call("vault.request_open_secret", path="/secrets/creds.md")
    assert res["status"] == "pending", res
    assert "hunter2-zzz" not in json.dumps(res), "secret content leaked in the request result"
    try:
        call("vault.request_open_secret", path="/notes/hidden.md")
    except RuntimeError as e:
        assert "PERMISSION_DENIED" in str(e), e
    else:
        raise AssertionError("request_open_secret accepted a 'secret' (non-secretfile) level")
    # the access log records the denials with the mcp role
    log = call("vault.access_log", limit=100)
    assert any(e["outcome"] == "deny" and e["role"] == "mcp" for e in log["entries"]), "no deny rows logged"
check("04 policy + search + secret-request over the socket", t04_content_and_policy_over_socket)

def t05_mcp_stdio_protocol():
    me = dict(env)
    proc = subprocess.Popen([str(PY), "-m", "vault.mcp"], env=me, cwd=str(ROOT),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    state["mcp"] = proc
    lines: list[str] = []
    def send(obj, expect=True):
        proc.stdin.write(json.dumps(obj) + "\n"); proc.stdin.flush()
        if not expect: return None
        line = proc.stdout.readline()
        assert line.strip(), f"no response for {obj.get('method')} (stderr: {proc.stderr.read()[-400:] if proc.stderr else ''})"
        lines.append(line)
        return json.loads(line)
    r = send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "verify", "version": "1"}}})
    assert r["result"]["protocolVersion"] == "2025-06-18", r
    assert r["result"]["serverInfo"]["name"] == "secure-vault", r
    send({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect=False)
    r = send({"jsonrpc": "2.0", "id": 2, "method": "ping"}); assert r["result"] == {}, r
    r = send({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    tools = {t["name"]: t for t in r["result"]["tools"]}
    required = {"vault_status", "list_folder", "read_file", "read_lines", "write_file", "write_lines",
                "mkdir", "file_ops", "set_sensitivity", "search_filenames", "search_text",
                "search_semantic", "read_folder_note", "write_folder_note", "request_open_secret", "get_access_log"}
    missing = required - set(tools)
    assert not missing, f"missing MCP tools: {sorted(missing)} (got {sorted(tools)})"
    for name in ("read_file", "write_file", "list_folder", "search_filenames"):
        assert tools[name]["inputSchema"]["properties"], f"{name} has no input schema"
    def call_tool(name, args):
        r = send({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": name, "arguments": args}})
        assert "result" in r, f"{name} -> {r}"
        res = r["result"]
        payload = res.get("structuredContent")
        if payload is None:
            payload = json.loads(res["content"][0]["text"])
        return res, payload
    res, payload = call_tool("vault_status", {})
    assert res.get("isError") in (False, None), res
    res, payload = call_tool("list_folder", {"path": "/"})
    assert payload["entries"], payload
    res, payload = call_tool("read_file", {"path": "/notes/hello.md"})
    assert "hello" in payload["content"], payload
    call_tool("write_file", {"path": "/notes/mcp.md", "content": "from-mcp"})
    res, payload = call_tool("read_file", {"path": "/notes/mcp.md"})
    assert payload["content"] == "from-mcp", payload
    res, payload = call_tool("read_file", {"path": "/secrets/creds.md"})
    assert res.get("isError") is True, f"secretfile body was returned: {res}"
    assert payload.get("code") == "PERMISSION_DENIED", payload
    assert "hunter2-zzz" not in json.dumps(res), "secret content leaked through MCP"
    res, payload = call_tool("set_sensitivity", {"path": "/notes/mcp.md", "level": "secret"})
    assert payload["to"] == "secret", payload
    res, payload = call_tool("set_sensitivity", {"path": "/notes/mcp.md", "level": "normal"})
    assert res.get("isError") is True and payload["code"] == "SENSITIVITY_DOWNGRADE_FORBIDDEN", (res, payload)
    # asking for the level a secret file already has must never weaken it
    res, payload = call_tool("set_sensitivity", {"path": "/notes/hidden.md", "level": "normal"})
    assert res.get("isError") is True and payload["code"] == "SENSITIVITY_DOWNGRADE_FORBIDDEN", (res, payload)
    res, payload = call_tool("list_folder", {"path": "/notes"})
    levels = {e["name"]: e["sensitivity"] for e in payload["entries"]}
    assert levels.get("hidden.md") == "secret", f"secret level changed: {levels}"
    res, payload = call_tool("request_open_secret", {"path": "/secrets/creds.md"})
    assert payload["status"] == "pending" and "hunter2-zzz" not in json.dumps(res), payload
    res, payload = call_tool("search_filenames", {"query": "creds"})
    assert payload["results"], payload
    res, payload = call_tool("search_text", {"query": "hidden-body-marker"})
    assert not payload["results"], payload
    # resources
    r = send({"jsonrpc": "2.0", "id": 11, "method": "resources/list"})
    uris = {x["uri"] for x in r["result"]["resources"]}
    assert "vault://status" in uris, uris
    r = send({"jsonrpc": "2.0", "id": 12, "method": "resources/templates/list"})
    assert len(r["result"]["resourceTemplates"]) >= 3, r
    r = send({"jsonrpc": "2.0", "id": 13, "method": "resources/read", "params": {"uri": "vault://status"}})
    assert r["result"]["contents"][0]["text"], r
    r = send({"jsonrpc": "2.0", "id": 14, "method": "resources/read", "params": {"uri": "vault://note/secrets/creds.md"}})
    assert "error" in r and r["error"].get("data", {}).get("code") == "PERMISSION_DENIED", r
    # protocol errors
    r = send({"jsonrpc": "2.0", "id": 15, "method": "no/such/method"})
    assert r["error"]["code"] == -32601, r
    r = send({"jsonrpc": "2.0", "id": 16, "method": "tools/call", "params": {"name": "nope"}})
    assert r["error"]["code"] == -32602, r
    # raw invalid json
    proc.stdin.write("this is not json\n"); proc.stdin.flush()
    line = proc.stdout.readline(); r = json.loads(line)
    assert r["error"]["code"] == -32700, r
    # every stdout line must be valid JSON (no stray prints on stdout)
    state["mcp_lines"] = lines
check("05 MCP stdio protocol, tools, resources, error codes", t05_mcp_stdio_protocol)

def t06_locked_daemon():
    env2 = dict(env, XDG_RUNTIME_DIR=str(rt_locked))
    p, sock, rundir = start_daemon(env2, unlock=False)
    tok = token_of(rundir)
    def call(method, **params):
        return raw_call(sock, {"id": 6, "token": tok, "method": method, "params": params})
    r = call("vault.status"); assert r["ok"] and r["result"]["locked"] is True, r
    r = call("vault.list_folder", path="/"); assert r["ok"], r
    r = call("vault.read_file", path="/notes/hello.md")
    assert r["ok"] is False and r["error"]["code"] == "VAULT_LOCKED", r
    r = call("vault.search_filenames", query="hello")
    assert r["ok"] is True, f"filename search should work while locked: {r}"
    r = call("vault.search_text", query="body")
    assert r["ok"] is False and r["error"]["code"] == "VAULT_LOCKED", r
    p.send_signal(signal.SIGTERM); rc = p.wait(timeout=30)
    assert rc == 0, f"locked daemon exit code {rc}"
    assert not sock.exists(), "socket left behind"
check("06 locked daemon: metadata yes, content no, clean SIGTERM", t06_locked_daemon)

def t07_mcp_when_daemon_down():
    proc = state["mcp"]
    # stop the main daemon, then ask the bridge for content
    state["p"].send_signal(signal.SIGTERM); assert state["p"].wait(timeout=30) == 0
    assert not state["sock"].exists(), "socket left behind after SIGTERM"
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 30, "method": "tools/call",
                                 "params": {"name": "list_folder", "arguments": {"path": "/"}}}) + "\n")
    proc.stdin.flush()
    r = json.loads(proc.stdout.readline())
    assert "error" in r, r
    assert r["error"].get("data", {}).get("code") == "VAULT_NOT_RUNNING", r
    proc.stdin.close(); proc.terminate(); proc.wait(timeout=20)
    # every line the bridge ever wrote on stdout must be JSON
    for line in state.get("mcp_lines", []):
        json.loads(line)
check("07 VAULT_NOT_RUNNING when the daemon is down; stdout stays pure JSON", t07_mcp_when_daemon_down)

def t08_client_errors():
    from vault.api.client import VaultClient
    c = VaultClient(socket_path=Path("/tmp/definitely-not-there.sock"), token="x", timeout=3)
    try:
        c.call("vault.status")
    except Exception as e:
        assert getattr(e, "code", None) == "VAULT_NOT_RUNNING", f"got {type(e).__name__}: {e}"
    else:
        raise AssertionError("client did not raise for a missing daemon")
check("08 client maps a missing daemon to VAULT_NOT_RUNNING", t08_client_errors)

print(f"\n==== SUMMARY: {len(PASS)} passed, {len(FAIL)} failed ====")
for n, e in FAIL: print("FAILED:", n, "->", e)
sys.exit(1 if FAIL else 0)
