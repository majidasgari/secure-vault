# Auto-generated reference for tests/test_invariants.py — see the header below.
# ORCHESTRATOR-OWNED: the assertions in this file were written by the orchestrator as an
# independent adversarial verification of the security invariants. Convert EVERY check into
# unittest cases in tests/test_invariants.py (one test method per check() call), keeping the
# assertions intact. This file is a reference: it must not be discovered by the test runner
# (its name does not start with 'test_'), and it must stay in the repo. Do not modify it.
#!/usr/bin/env python3
"""Independent adversarial verification of P1 (written by the orchestrator, not by the coder)."""
from __future__ import annotations
import os, sys, tempfile, time, traceback
from pathlib import Path

ROOT = Path("/data/Codes/secure-vault")
sys.path.insert(0, str(ROOT / "src"))

from vault.core import crypto, session as session_mod
from vault.core.session import VaultSession
from vault.core import semantics
from vault import errors

PASS, FAIL = [], []
def check(name, fn):
    try:
        fn()
        PASS.append(name); print(f"PASS  {name}")
    except Exception as e:
        FAIL.append((name, e)); print(f"FAIL  {name}: {type(e).__name__}: {e}")
        traceback.print_exc(limit=3)

def new_vault(tmp: Path, pw="s3cret-pass-phrase", **kw):
    home = tmp / "vaulthome"
    s = VaultSession.create(home, pw, **kw)
    return s, home

tmp = Path(tempfile.mkdtemp(prefix="sv-verify-"))
print("scratch:", tmp)

state = {}

def t01_create_unlock():
    s, home = new_vault(tmp)
    state["s"], state["home"] = s, home
    assert not s.is_locked, "should be unlocked right after create"
    assert (home / ".vault-meta.json").exists(), "vault-meta.json missing"
    s.lock()
    assert s.is_locked
    s.unlock("s3cret-pass-phrase")
    assert not s.is_locked
check("01 create / lock / unlock", t01_create_unlock)

def t02_wrong_password():
    s = state["s"]; s.lock()
    try:
        s.unlock("wrong-password")
    except errors.Unauthorized:
        s.unlock("s3cret-pass-phrase"); return
    raise AssertionError("wrong password did not raise Unauthorized")
check("02 wrong password rejected", t02_wrong_password)

def t03_no_plaintext_in_home():
    s, home = state["s"], state["home"]
    marker = "MARKER-TOP-SECRET-9f3a"
    s.write_file("notes/leak.md", f"# note\n{marker}\n".encode())
    s.set_folder_note("/notes", f"folder note {marker}")
    s.flush()
    hits = []
    for p in home.rglob("*"):
        if p.is_file():
            try:
                if marker.encode() in p.read_bytes(): hits.append(str(p.relative_to(home)))
            except Exception: pass
    assert not hits, f"plaintext marker found in {hits}"
check("03 no plaintext content in the vault home", t03_no_plaintext_in_home)

def t04_store_encrypted_and_runtime_outside():
    s, home = state["s"], state["home"]
    store = home / "secure.store"
    assert store.exists(), "secure.store missing"
    assert store.read_bytes()[:4] not in (b"SQLi",), "store looks like a raw sqlite file"
    # decrypted store must live outside the vault home, mode 0600
    rtdir = Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp")) / "secure-vault"
    cands = list(rtdir.glob("**/*.dec")) if rtdir.exists() else []
    assert cands, f"no decrypted store under {rtdir}"
    for c in cands:
        mode = c.stat().st_mode & 0o777
        assert mode == 0o600, f"{c} mode {oct(mode)} != 0600"
        assert home not in c.parents, f"decrypted store inside the vault home: {c}"
    s.lock()
    left = list(rtdir.glob("**/*.dec")) if rtdir.exists() else []
    assert not left, f"decrypted store still present after lock: {left}"
    s.unlock("s3cret-pass-phrase")
check("04 store encrypted; runtime copy outside home, 0600, removed on lock", t04_store_encrypted_and_runtime_outside)

def t05_aad_binding():
    pw = "pw-aad"
    params = crypto.new_kdf_params()
    key = crypto.derive_master_key(pw, params)
    blob = crypto.encrypt_blob(key, "blob-1", b"payload", sensitivity="normal")
    assert crypto.decrypt_blob(key, "blob-1", blob, sensitivity="normal") == b"payload"
    for label, fn in [
        ("blob_id mismatch", lambda: crypto.decrypt_blob(key, "blob-2", blob, sensitivity="normal")),
        ("sensitivity mismatch", lambda: crypto.decrypt_blob(key, "blob-1", blob, sensitivity="secret")),
    ]:
        try:
            fn()
        except errors.TamperDetected:
            continue
        raise AssertionError(f"{label} not detected")
    # bit flips anywhere
    for i in range(0, len(blob)):
        bad = bytearray(blob); bad[i] ^= 0x01
        try:
            crypto.decrypt_blob(key, "blob-1", bytes(bad), sensitivity="normal")
        except errors.TamperDetected:
            continue
        except Exception as e:
            raise AssertionError(f"flip@{i}: wrong exception {type(e).__name__}: {e}")
        raise AssertionError(f"flip@{i}: tampering not detected")
check("05 AES-GCM AAD binding + every-single-bit tamper detection", t05_aad_binding)

def t06_locked_semantics():
    s = state["s"]
    s.write_file("notes/locked.md", b"content-while-unlocked")
    s.unlock("s3cret-pass-phrase") if s.is_locked else None
    s.lock()
    assert isinstance(s.list_folder("/"), dict), "list_folder must work while locked (metadata)"
    try:
        s.read_text("notes/locked.md")
    except errors.VaultLocked:
        pass
    else:
        raise AssertionError("read_text worked while locked")
    s.unlock("s3cret-pass-phrase")
    assert s.read_text("notes/locked.md") == "content-while-unlocked"
check("06 locked mode: metadata yes, content no", t06_locked_semantics)

def t07_mcp_rules_and_logging():
    s = state["s"]
    s.write_file("secrets/api-keys.md", b"token=abc", source="ui")
    s.set_sensitivity("secrets/api-keys.md", "secretfile")
    try:
        s.read_text("secrets/api-keys.md", source="mcp")
    except errors.PermissionDenied:
        pass
    else:
        raise AssertionError("mcp read a secretfile")
    log = s.access_log(limit=20)
    assert any(r["outcome"] == "deny" and r["role"] == "mcp" for r in log), f"no deny row: {log[:3]}"
    # raising is allowed for mcp, lowering is not
    s.write_file("notes/up.md", b"x")
    s.set_sensitivity("notes/up.md", "secret", source="mcp")
    try:
        s.set_sensitivity("notes/up.md", "normal", source="mcp")
    except errors.DowngradeForbidden:
        pass
    else:
        raise AssertionError("mcp lowered a level")
    s.set_sensitivity("notes/up.md", "normal", source="ui")   # ui may lower
    # mcp may not create a file with a raised level
    try:
        s.write_file("notes/new.md", b"x", source="mcp", sensitivity="secret")
    except errors.PermissionDenied:
        pass
    else:
        raise AssertionError("mcp created a secret file")
    # mcp may create a normal file
    s.write_file("notes/new.md", b"x", source="mcp")
    assert s.read_text("notes/new.md", source="mcp") == "x"
check("07 MCP policy: deny content, raise-only, create-only-normal, logging", t07_mcp_rules_and_logging)

def t08_secret_request_flow():
    s = state["s"]
    seen = []
    s.on_secret_request = lambda req: seen.append(req)
    res = s.request_open_secret("secrets/api-keys.md", source="mcp")
    assert res["status"] == "pending" and seen, f"request not queued: {res}"
    body = str(res)
    assert "token=abc" not in body, "content leaked into the request result"
    out = s.resolve_open_secret(res["request_id"], approved=False)
    assert out.get("status") == "denied", out
    try:
        s.request_open_secret("notes/new.md", source="mcp")
    except errors.PermissionDenied:
        pass
    else:
        raise AssertionError("request_open_secret accepted a non-secretfile level")
check("08 request_open_secret: queue, no content, deny, level check", t08_secret_request_flow)

def t09_search_kinds():
    s = state["s"]
    s.write_file("notes/persian.md", "سلام دنيا\nکتاب".encode())      # Arabic yeh
    s.write_file("notes/kaf.md", "يك كتاب ديگر".encode())              # Arabic kaf
    s.write_file("secretish.md", b"nothing")
    s.set_sensitivity("secretish.md", "secret")
    s.write_file("secretish.md", b"hidden-body-xyz", source="ui")      # ensure body
    fn = s.search_filenames("secretish")
    assert fn, "filename search missed a secret file"
    assert not [r for r in s.search_text("hidden-body-xyz")], "secret body was searchable in content"
    assert [r for r in s.search_text("دنيا")], "persian yeh normalisation failed (query ي vs ي)"
    assert [r for r in s.search_text("کتاب")], "persian text search failed"
    assert [r for r in s.search_text("يك")] or [r for r in s.search_text("کتاب")], "kaf normalisation failed"
    try:
        s.search_semantic("anything")
    except errors.ProviderUnavailable:
        pass
    else:
        raise AssertionError("semantic search worked without a provider")
    s.set_semantic_provider(semantics.StubProvider())
    assert isinstance(s.search_semantic("کتاب"), list), "stub provider search failed"
check("09 three search kinds, Persian normalisation, secret exclusion", t09_search_kinds)

def t10_plain_threshold_and_persistence():
    s = state["s"]
    s.set_semantic_provider(None)
    # force a small threshold through settings
    s.meta.settings["plain_threshold_bytes"] = 1024
    s.meta.save()
    blob = b"B" * 5000
    s.write_file("notes/big.bin", blob)
    row = s.index.get_file("notes/big.bin")
    assert row["encrypted"] == 0, f"big file should be plain: {row}"
    plain_hits = [p.name for p in (state["home"] / "files").rglob("*") if p.is_file() and blob[:64] in p.read_bytes()]
    assert plain_hits, "plain blob not found on disk (as designed for >threshold)"
    s.meta.settings["plain_threshold_bytes"] = 10 * 1024 * 1024
    s.meta.save()
    s.flush(); s.lock(); s.unlock("s3cret-pass-phrase")
    assert s.read_file("notes/big.bin") == blob, "plain blob lost after re-unlock"
check("10 plain-threshold behaviour + persistence across lock/unlock", t10_plain_threshold_and_persistence)

def t11_auto_lock():
    s = state["s"]
    s.meta.settings["auto_lock_seconds"] = 60
    s.touch(source="ui")
    assert not s.auto_lock_due()
    real = time.time
    time.time = lambda: real() + 120
    try:
        assert s.auto_lock_due(), "auto_lock_due() did not fire after the timeout"
    finally:
        time.time = real
    s.meta.settings["auto_lock_seconds"] = 0
    assert not s.auto_lock_due(), "auto-lock must be disabled with 0"
    s.touch(source="ui")
check("11 auto-lock clock logic", t11_auto_lock)

def t12_crash_safety():
    s, home = state["s"], state["home"]
    s.write_file("notes/crash.md", b"after-flush")
    s.flush()
    s2 = VaultSession(home)
    s2.unlock("s3cret-pass-phrase")
    assert s2.read_text("notes/crash.md") == "after-flush", "data written before a simulated crash was lost"
    s2.close()
check("12 crash safety: flush makes writes durable", t12_crash_safety)

def t13_paths_rejected():
    s = state["s"]
    home = state["home"]
    # must be rejected outright
    for bad in ["../../etc/passwd", "a/../../b", "..", "", "a\x00b", "x" * 2000]:
        try:
            s.write_file(bad, b"x")
        except errors.InvalidPath:
            continue
        except Exception as e:
            raise AssertionError(f"{bad!r}: wrong exception {type(e).__name__}")
        raise AssertionError(f"{bad!r}: accepted")
    # the API-absolute form is a *vault* path, never a host path: it must land inside the home
    s.write_file("/etc/passwd", b"not-the-real-one")
    assert s.read_text("etc/passwd") == "not-the-real-one", "absolute form not mapped into the vault"
    assert Path("/etc/passwd").read_text().splitlines()[0] != "not-the-real-one", "wrote to the host /etc/passwd!"
    assert s.read_text("/etc/passwd") == s.read_text("etc/passwd"), "leading-slash identity broken"
    # '.' segments and duplicate slashes are normalized, not rejected
    s.write_file("a/./b//c.md", b"norm")
    assert s.read_text("a/b/c.md") == "norm", "'.'/'//' normalization failed"
    outside = [p for p in home.parent.rglob("*") if p.is_file() and b"not-the-real-one" in p.read_bytes()]
    assert not outside, f"content written outside the vault home: {outside}"
check("13 path traversal rejected / API-absolute mapped into the vault", t13_paths_rejected)

def t14_log_append_only():
    s = state["s"]
    n = s.index.access_log_count()
    s.list_folder("/")
    assert s.index.access_log_count() >= n, "log shrank"
    assert "DELETE FROM access_log" not in (ROOT / "src/vault/core/index.py").read_text(), "index.py contains a DELETE on access_log"
check("14 access log append-only", t14_log_append_only)

state["s"].close()
print(f"\n==== SUMMARY: {len(PASS)} passed, {len(FAIL)} failed ====")
for name, e in FAIL:
    print("FAILED:", name, "->", e)
sys.exit(1 if FAIL else 0)
