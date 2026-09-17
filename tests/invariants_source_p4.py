# ORCHESTRATOR-OWNED verification of P4 against the REAL Joplin mirror (opt-in, slow).
# Reference script; run via tests/test_real_mirror_invariants.py with SECURE_VAULT_REAL_MIRROR=1.

#!/usr/bin/env python3
"""Independent verification of P4 against the REAL Joplin mirror (orchestrator-written).

Imports the whole mirror into a throw-away vault, then checks counts, fidelity, idempotency,
search, stray handling, attachments and that the mirror itself was never touched.
"""
from __future__ import annotations
import json, os, re, subprocess, sys, tempfile, traceback
from pathlib import Path

ROOT = Path("/data/Codes/secure-vault")
MIRROR = Path("/data/Cloud/Documents/Notes/joplin-mirror")
PY = ROOT / ".venv" / "bin" / "python"
sys.path.insert(0, str(ROOT / "src"))

PASS, FAIL = [], []
def check(name, fn):
    try:
        fn(); PASS.append(name); print(f"PASS  {name}")
    except Exception as e:
        FAIL.append((name, e)); print(f"FAIL  {name}: {type(e).__name__}: {e}")
        traceback.print_exc(limit=4)

tmp = Path(tempfile.mkdtemp(prefix="sv-p4-"))
home = tmp / "vault"
pwfile = tmp / "pw"; pwfile.write_text("p4-verify-passphrase"); os.chmod(pwfile, 0o600)
report = tmp / "report.md"

def mirror_manifest() -> dict:
    out = {}
    for p in MIRROR.rglob("*"):
        if p.is_file():
            st = p.stat()
            out[str(p.relative_to(MIRROR))] = (st.st_size, int(st.st_mtime))
    return out

def vault_manifest() -> dict:
    out = {}
    for p in home.rglob("*"):
        if p.is_file():
            st = p.stat()
            out[str(p.relative_to(home))] = (st.st_size, int(st.st_mtime))
    return out

def run_cli(*extra, expect_rc=0):
    cmd = [str(PY), str(ROOT / "tools" / "import_joplin.py"),
           "--home", str(home), "--unlock-file", str(pwfile), "--mirror", str(MIRROR),
           "--report", str(report), *extra]
    p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=1800,
                       env=dict(os.environ, PYTHONPATH=str(ROOT / "src")))
    if p.returncode != expect_rc:
        raise AssertionError(f"CLI rc={p.returncode} (expected {expect_rc})\n{p.stdout[-1500:]}\n{p.stderr[-1500:]}")
    return p

state = {}

def t00_setup():
    from vault.core.session import VaultSession
    s = VaultSession.create(home, "p4-verify-passphrase")
    s.close()
    state["mirror_before"] = mirror_manifest()
    assert len(state["mirror_before"]) > 1000, "mirror manifest looks wrong"
check("00 scratch vault + mirror manifest", t00_setup)

def t01_dry_run_writes_nothing():
    before = vault_manifest()
    p = run_cli("--dry-run", "--json")
    after = vault_manifest()
    assert set(before) == set(after), f"dry run changed the vault: {set(after) - set(before)}"
    changed = [k for k in before if k in after and before[k] != after[k]]
    assert not changed, f"dry run rewrote {changed}"
    payload = json.loads(p.stdout[p.stdout.index("{"):]) if "{" in p.stdout else None
    assert payload, f"no JSON report on stdout: {p.stdout[-600:]}"
    assert payload["notes_created"] >= 800, payload
    assert payload.get("dry_run") is True, f"report does not flag the dry run: {payload.get('dry_run')!r}"
check("01 --dry-run imports nothing", t01_dry_run_writes_nothing)

def t02_real_import():
    p = run_cli("--json")
    payload = json.loads(p.stdout[p.stdout.index("{"):])
    state["report"] = payload
    assert payload["notes_created"] >= 870, f"only {payload['notes_created']} notes created"
    assert payload["folders_created"] >= 100, f"only {payload['folders_created']} folders"
    assert payload["errors"] == [], f"import errors: {payload['errors'][:3]}"
    assert report.exists(), "no markdown report written"
check("02 real import: ~876 notes + folders, no errors", t02_real_import)

def t03_mirror_untouched():
    after = mirror_manifest()
    before = state["mirror_before"]
    added = set(after) - set(before)
    removed = set(before) - set(after)
    changed = [k for k in before if k in after and before[k] != after[k]]
    assert not added and not removed and not changed, f"mirror modified: +{list(added)[:3]} -{list(removed)[:3]} ~{changed[:3]}"
check("03 the real mirror was never modified", t03_mirror_untouched)

def t04_content_fidelity():
    from vault.core.session import VaultSession
    manifest = json.loads((MIRROR / "_meta" / "index.json").read_text(encoding="utf-8"))
    s = VaultSession(home); s.unlock("p4-verify-passphrase")
    state["session"] = s
    checked = 0
    for note in manifest["notes"][:400]:
        rel = note["path"]
        src = MIRROR / rel
        if not src.exists():
            continue
        raw = src.read_text(encoding="utf-8", errors="replace")
        if raw.startswith("---"):
            end = raw.find("\n---", 3)
            body = raw[end + 4:].lstrip("\n") if end > 0 else raw
        else:
            body = raw
        try:
            got = s.read_text(rel)
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"cannot read imported note {rel}: {e}")
        if got.strip() != body.strip():
            raise AssertionError(f"body mismatch for {rel}:\n--vault--\n{got[:200]}\n--mirror--\n{body[:200]}")
        checked += 1
        if checked >= 25:
            break
    assert checked >= 20, f"only {checked} notes compared"
    # frontmatter must not be duplicated into the body
    sample = s.read_text(manifest["notes"][0]["path"])
    assert not sample.lstrip().startswith("---"), "frontmatter leaked into the imported body"
check("04 bodies match the mirror (frontmatter stripped)", t04_content_fidelity)

def t05_tags_and_stray():
    from vault import errors
    s = state["session"]
    tagged = 0
    manifest = json.loads((MIRROR / "_meta" / "index.json").read_text(encoding="utf-8"))
    for note in manifest["notes"]:
        if note["tags"]:
            row = s.index.require_file(note["path"])
            tags = s.index.get_tags(note["path"])
            assert tags, f"tags lost for {note['path']}"
            tagged += 1
    assert tagged >= 5, f"only {tagged} tagged notes verified"
    stray = "کاری/ایده‌ها/secure-vault/DESIGN.md"
    try:
        text = s.read_text(stray)
    except errors.NotFound:
        raise AssertionError(f"stray markdown not imported: {stray}")
    assert "Secure Vault" in text, "stray import content looks wrong"
    stray_list = state["report"]["extra"].get("stray_imported") or []
    assert any(str(x).endswith("secure-vault/DESIGN.md") for x in stray_list), stray_list[:3]
check("05 tags preserved + stray DESIGN.md imported", t05_tags_and_stray)

def t06_attachments():
    s = state["session"]
    manifest = json.loads((MIRROR / "_meta" / "index.json").read_text(encoding="utf-8"))
    listing = s.list_folder("/attachments")
    names = {str(e["logical_path"]).rsplit("/", 1)[-1] for e in listing["entries"]}
    expected = len(manifest["assets"])
    assert len(names) >= expected - 5, f"only {len(names)} of {expected} attachments imported"
    # every asset must be readable back byte-for-byte
    checked = 0
    for rid, filename in list(manifest["assets"].items())[:12]:
        src = MIRROR / "assets" / filename
        got = s.read_file(f"/attachments/{filename}")
        assert got == src.read_bytes(), f"attachment {filename} differs from the mirror"
        checked += 1
    assert checked >= 10, f"only {checked} attachments compared"
    # link rewriting: every note whose mirror body references a *known* resource must be rewritten
    resolve = {rid for rid in manifest["assets"]}
    rewrite_expected, rewrite_ok = 0, 0
    for note in manifest["notes"]:
        src = MIRROR / note["path"]
        if not src.exists():
            continue
        body = src.read_text(encoding="utf-8", errors="replace")
        ids = set(re.findall(r":/([0-9a-fA-F]{32})", body)) & resolve
        if not ids:
            continue
        rewrite_expected += 1
        imported = s.read_text(note["path"])
        if "vault:/attachments/" in imported and ":/" + next(iter(ids)) not in imported:
            rewrite_ok += 1
    print(f"      notes with resolvable refs: {rewrite_expected}, rewritten: {rewrite_ok}")
    assert rewrite_ok == rewrite_expected, f"{rewrite_expected - rewrite_ok} note(s) kept raw :/<id> links"
check("06 all attachments imported + links rewritten where resolvable", t06_attachments)

def t07_idempotent_second_run():
    p = run_cli("--json")
    payload = json.loads(p.stdout[p.stdout.index("{"):])
    assert payload["notes_created"] == 0, f"second run created {payload['notes_created']} notes"
    assert payload["notes_updated"] == 0, f"second run updated {payload['notes_updated']} notes"
    assert payload["notes_skipped"] >= 870, f"second run skipped only {payload['notes_skipped']}"
    assert payload["assets_imported"] == 0, f"second run re-imported {payload['assets_imported']} assets"
check("07 a second run is a no-op (idempotent)", t07_idempotent_second_run)

def t08_search_on_imported_content():
    s = state["session"]
    names = s.search_filenames("DESIGN")
    assert any("secure-vault" in r["logical_path"] for r in names), names[:3]
    hit = s.search_text("جلسه")
    assert hit, "literal Persian content search returned nothing for a common word"
    assert s.search_text("پرپلکسیتی") or s.search_text("نجم"), "search found nothing for expected words"
check("08 search works on the imported corpus", t08_search_on_imported_content)

def t09_no_plaintext_of_note_bodies():
    s = state["session"]
    manifest = json.loads((MIRROR / "_meta" / "index.json").read_text(encoding="utf-8"))
    needle = None
    for note in manifest["notes"]:
        if note["path"].startswith("شخصی/"):
            body = s.read_text(note["path"]).strip()
            if len(body) > 200:
                needle = body[:120].encode()
                break
    assert needle, "no sample note found"
    hits = []
    for p in home.rglob("*"):
        if p.is_file():
            try:
                if needle in p.read_bytes():
                    hits.append(str(p.relative_to(home)))
            except Exception:  # noqa: BLE001
                pass
    assert not hits, f"note body found in cleartext inside the vault home: {hits}"
check("09 imported note bodies are encrypted at rest", t09_no_plaintext_of_note_bodies)

def t10_mark_secret():
    home2 = tmp / "vault-secret"
    from vault.core.session import VaultSession
    VaultSession.create(home2, "p4-verify-passphrase").close()
    cmd = [str(PY), str(ROOT / "tools" / "import_joplin.py"), "--home", str(home2),
           "--unlock-file", str(pwfile), "--mirror", str(MIRROR), "--json",
           "--report", str(tmp / "report2.md"), "--mark-secret", "*DESIGN*"]
    p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=1800,
                       env=dict(os.environ, PYTHONPATH=str(ROOT / "src")))
    assert p.returncode == 0, p.stderr[-800:]
    s2 = VaultSession(home2); s2.unlock("p4-verify-passphrase")
    row = s2.index.require_file("کاری/ایده‌ها/secure-vault/DESIGN.md")
    assert row["sensitivity"] == "secret", f"--mark-secret did not apply: {row['sensitivity']}"
    try:
        s2.read_text("کاری/ایده‌ها/secure-vault/DESIGN.md", source="mcp")
    except Exception as e:  # noqa: BLE001
        assert getattr(e, "code", "") == "PERMISSION_DENIED", e
    else:
        raise AssertionError("a secret-marked imported note was readable by mcp")
    s2.close()
check("10 --mark-secret marks imports and blocks agent access", t10_mark_secret)

state.get("session") and state["session"].close()
print(f"\n==== SUMMARY: {len(PASS)} passed, {len(FAIL)} failed ====")
if state.get("report"):
    r = state["report"]
    print(f"REPORT: created={r['notes_created']} updated={r['notes_updated']} skipped={r['notes_skipped']} "
          f"folders={r['folders_created']} assets={r['assets_imported']} errors={len(r['errors'])} extra={r.get('extra')}")
for n, e in FAIL: print("FAILED:", n, "->", e)
sys.exit(1 if FAIL else 0)
