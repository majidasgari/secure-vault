# ORCHESTRATOR-OWNED headless verification of the P3 UI rules (secret/secretfile handling, i18n).
# Reference script; run via tests/test_ui_invariants.py. Do not weaken the assertions.

#!/usr/bin/env python3
"""Independent adversarial verification of P3 (Qt UI), orchestrator-written, headless.

Assertions focus on the security-relevant UI rules and the i18n contract — the things a
reviewer would check by hand:
  * a 'secret' file never enables the markdown preview (no web engine),
  * a 'secretfile' file is shown ONLY in the native plain-text viewer, never in the editor,
  * opening a confidential file without confirmation does nothing,
  * the editor content for a normal file is fine, and the preview is created then,
  * i18n: language switch flips every label and the layout direction, catalogues match,
  * no user-visible literal strings in the UI modules,
  * locking from the controller returns to the unlock screen and locks the session.
"""
from __future__ import annotations
import os, sys, tempfile, traceback
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path("/data/Codes/secure-vault")
sys.path.insert(0, str(ROOT / "src"))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from vault.core.session import VaultSession
from vault.ui import editor as editor_mod
from vault.ui import viewer as viewer_mod
from vault.ui import i18n
from vault.ui.app import VaultApplication

PW = "p3-verify-passphrase"
tmp = Path(tempfile.mkdtemp(prefix="sv-p3-"))
home = tmp / "home"
session = VaultSession.create(home, PW)
session.write_file("/notes/normal.md", b"# normal title\nnormal-body-marker")
session.write_file("/notes/secret.md", b"secret-body-marker")
session.set_sensitivity("/notes/secret.md", "secret")
session.write_file("/secrets/creds.md", b"password: hunter2-zzz")
session.set_sensitivity("/secrets/creds.md", "secretfile")
session.write_file("/notes/pics.md", b"![a](x.png)")
session.close()

qapp = QApplication.instance() or QApplication([])
app = VaultApplication(qapp, home=home, language="fa", no_tray=True, self_test=True)
session = VaultSession(home)
session.unlock(PW)
window = app.attach_session(session)

PASS, FAIL = [], []
def check(name, fn):
    try:
        fn(); PASS.append(name); print(f"PASS  {name}")
    except Exception as e:
        FAIL.append((name, e)); print(f"FAIL  {name}: {type(e).__name__}: {e}")
        traceback.print_exc(limit=4)

def t01_normal_file_preview_ok():
    assert app.open_path("/notes/normal.md") is True
    assert window.editor.preview_enabled is True, "normal file must have the preview enabled"
    assert "normal-body-marker" in window.editor.source.toPlainText(), "normal content not loaded in the editor"
check("01 normal file -> editor + preview", t01_normal_file_preview_ok)

def t02_secret_needs_confirmation():
    seen = []
    app.confirm_hook = lambda level, path: (seen.append((level, path)), False)[1]
    before = editor_mod.web_views_created
    assert app.open_path("/notes/secret.md") is False, "opening a secret file must require confirmation"
    assert seen and seen[0][0] == "secret", f"confirmation not requested: {seen}"
    assert editor_mod.web_views_created == before, "a web view was created for a refused secret file"
    assert "secret-body-marker" not in window.editor.source.toPlainText(), "refused secret content reached the editor"
check("02 'secret' file refuses to open without confirmation", t02_secret_needs_confirmation)

def t03_secret_preview_disabled():
    app.confirm_hook = lambda level, path: True
    before = editor_mod.web_views_created
    assert app.open_path("/notes/secret.md") is True, "confirmed secret file should open"
    assert window.editor.preview_enabled is False, "preview must be disabled for a secret file"
    assert editor_mod.web_views_created == before, "web view created for a secret file"
check("03 'secret' file -> editor with the preview DISABLED and no web view", t03_secret_preview_disabled)

def t04_secretfile_native_viewer_only():
    before = editor_mod.web_views_created
    editor_before = window.editor.source.toPlainText()
    assert app.open_path("/secrets/creds.md") is True, "secretfile should open in the native viewer"
    assert viewer_mod.last_text == "password: hunter2-zzz", f"native viewer got {viewer_mod.last_text!r}"
    assert editor_mod.web_views_created == before, "web view created for a secretfile"
    assert "hunter2-zzz" not in window.editor.source.toPlainText(), "secretfile content reached the editor"
    assert window.editor.source.toPlainText() == editor_before, "editor content changed for a secretfile"
check("04 'secretfile' -> native viewer only, never the editor/web view", t04_secretfile_native_viewer_only)

def t05_i18n_switch_and_rtl():
    app.set_language("en")
    title_en = window.windowTitle()
    assert qapp.layoutDirection() == Qt.LeftToRight, "en must be LTR"
    app.set_language("fa")
    title_fa = window.windowTitle()
    assert qapp.layoutDirection() == Qt.RightToLeft, "fa must be RTL"
    assert title_en and title_fa and title_en != title_fa, f"titles did not change: {title_en!r} vs {title_fa!r}"
    # the low-level translator switch must also retranslate bound widgets (unlock screen path)
    app.set_language("en")
    en_value = i18n.tr("editor.placeholder")
    app.set_language("fa")
    fa_value = i18n.tr("editor.placeholder")
    assert en_value != fa_value and en_value and fa_value, f"catalogue switch failed: {en_value!r} {fa_value!r}"
check("05 live language switch + RTL/LTR flip", t05_i18n_switch_and_rtl)

def t06_catalogues_complete():
    import json
    fa = json.loads((ROOT / "i18n" / "fa.json").read_text(encoding="utf-8"))
    en = json.loads((ROOT / "i18n" / "en.json").read_text(encoding="utf-8"))
    assert set(fa) == set(en), f"catalogue key mismatch: {sorted(set(fa) ^ set(en))[:10]}"
    sys.path.insert(0, str(ROOT))
    from vault import errors
    codes = {c for c in dir(errors) if c[0].isupper()}
    missing = []
    for name in codes:
        obj = getattr(errors, name)
        code = getattr(obj, "code", None)
        if isinstance(code, str) and f"error.{code}" not in fa:
            missing.append(code)
    assert not missing, f"missing translations for error codes: {missing}"
    assert len(fa) > 120, f"catalogue suspiciously small: {len(fa)} entries"
check("06 fa/en catalogues complete (incl. every error code)", t06_catalogues_complete)

def t07_no_literal_ui_strings():
    import re
    pat = re.compile(r"""(setText|setWindowTitle|setToolTip|setPlaceholderText|addTab|setTabText)\(\s*(?:QtCore\.)?["']([^"']+)["']""")
    offenders = []
    for path in (ROOT / "src" / "vault" / "ui").glob("*.py"):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = pat.search(line)
            if m:
                offenders.append(f"{path.name}:{i}: {line.strip()[:90]}")
    assert not offenders, "literal UI strings bypassing i18n:\n" + "\n".join(offenders[:10])
check("07 no literal UI strings outside the catalogues", t07_no_literal_ui_strings)

def t08_search_panel_three_kinds():
    panel = window.search_panel
    assert panel.last_results("filename") == [], "panel should start empty"
    panel.set_query("filename", "normal")
    res = panel.run_search("filename", "normal")
    assert any("normal" in r["logical_path"] for r in res), res
    res = panel.run_search("text", "normal-body-marker")
    assert res, "literal content search failed from the panel"
    res = panel.run_search("text", "secret-body-marker")
    assert not res, "the panel returned secret content"
    try:
        panel.run_search("semantic", "anything")
    except Exception as e:
        assert "PROVIDER_UNAVAILABLE" in str(e) or getattr(e, "code", "") == "PROVIDER_UNAVAILABLE", e
check("08 search panel exposes the three separate kinds", t08_search_panel_three_kinds)

def t09_lock_returns_to_unlock():
    app.lock()
    assert session.is_locked, "controller lock() did not lock the session"
    assert app.current_screen == "unlock", f"screen after lock: {app.current_screen}"
    assert app.window is None or not app.window.isVisible(), "main window still visible after lock"
check("09 lock() returns to the unlock screen", t09_lock_returns_to_unlock)

print(f"\n==== SUMMARY: {len(PASS)} passed, {len(FAIL)} failed ====")
for n, e in FAIL: print("FAILED:", n, "->", e)
sys.exit(1 if FAIL else 0)
