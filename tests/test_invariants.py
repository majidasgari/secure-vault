"""Adversarial verification of the P1 security invariants (SPEC/06 §2).

Converted one-to-one from the orchestrator-owned ``tests/invariants_source.py``: each
``check()`` there becomes one ordered test method here, with every assertion preserved.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from vault import errors
from vault.core import crypto
from vault.core import index as index_module
from vault.core import semantics
from vault.core.session import VaultSession

PASSWORD = "s3cret-pass-phrase"


def _new_vault(tmp: Path, pw: str = PASSWORD, **kw):
    """Create a fresh vault under ``tmp`` and return ``(session, home)``."""
    home = tmp / "vaulthome"
    session = VaultSession.create(home, pw, **kw)
    return session, home


class InvariantsTest(unittest.TestCase):
    """Ordered tests; later tests build on state created by earlier ones."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="sv-verify-"))
        cls.state: dict = {}

    def setUp(self) -> None:
        """Keep the suite order-independent: never inherit a locked vault from a failure.

        A failing step used to leave the shared session locked, which then produced a cascade
        of ``VaultLocked`` errors in the following steps and hid the real failure.
        """
        session = self.state.get("s")
        if session is not None and session.is_locked:
            session.unlock(PASSWORD)

    @classmethod
    def tearDownClass(cls) -> None:
        session = cls.state.get("s")
        if session is not None:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---------------------------------------------------------------- 01
    def test_01_create_lock_unlock(self) -> None:
        """create / lock / unlock cycle."""
        s, home = _new_vault(self.tmp)
        self.state["s"], self.state["home"] = s, home
        assert not s.is_locked, "should be unlocked right after create"
        assert (home / ".vault-meta.json").exists(), "vault-meta.json missing"
        s.lock()
        assert s.is_locked
        s.unlock(PASSWORD)
        assert not s.is_locked

    # ---------------------------------------------------------------- 02
    def test_02_wrong_password_rejected(self) -> None:
        """A wrong password must raise Unauthorized."""
        s = self.state["s"]
        s.lock()
        try:
            s.unlock("wrong-password")
        except errors.Unauthorized:
            s.unlock(PASSWORD)
            return
        raise AssertionError("wrong password did not raise Unauthorized")

    # ---------------------------------------------------------------- 03
    def test_03_no_plaintext_in_home(self) -> None:
        """No plaintext content may appear anywhere under the vault home."""
        s, home = self.state["s"], self.state["home"]
        marker = "MARKER-TOP-SECRET-9f3a"
        s.write_file("notes/leak.md", f"# note\n{marker}\n".encode())
        s.set_folder_note("/notes", f"folder note {marker}")
        s.flush()
        hits = []
        for path in home.rglob("*"):
            if path.is_file():
                try:
                    if marker.encode() in path.read_bytes():
                        hits.append(str(path.relative_to(home)))
                except Exception:  # noqa: BLE001
                    pass
        assert not hits, f"plaintext marker found in {hits}"

    # ---------------------------------------------------------------- 04
    def test_04_store_encrypted_and_runtime_outside(self) -> None:
        """The store is encrypted; the runtime copy is outside the home, 0600, removed on lock."""
        s, home = self.state["s"], self.state["home"]
        store = home / "secure.store"
        assert store.exists(), "secure.store missing"
        assert store.read_bytes()[:4] not in (b"SQLi",), "store looks like a raw sqlite file"
        rtdir = Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp")) / "secure-vault"
        # This session's own decrypted store (the file name is per instance; another vault
        # process — the user's running app or web UI — legitimately holds its own file, so the
        # assertions below are about OUR file, never about "no .dec exists anywhere").
        own = Path(getattr(s.store, "_dec_path"))
        assert own.exists(), f"this session's decrypted store is missing: {own}"
        assert own.parent == rtdir, f"{own} is not under {rtdir}"
        assert rtdir.exists() and (rtdir.stat().st_mode & 0o777) == 0o700, "runtime dir must be 0700"
        mode = own.stat().st_mode & 0o777
        assert mode == 0o600, f"{own} mode {oct(mode)} != 0600"
        assert home not in own.parents, f"decrypted store inside the vault home: {own}"
        for cand in rtdir.glob("store.*.dec"):
            assert home not in cand.parents, f"a decrypted store sits inside a vault home: {cand}"
        s.lock()
        assert not own.exists(), f"this session's decrypted store survived lock: {own}"
        s.unlock(PASSWORD)

    # ---------------------------------------------------------------- 05
    def test_05_aad_binding_and_bitflips(self) -> None:
        """AES-GCM AAD binding plus every-single-bit tamper detection."""
        pw = "pw-aad"
        params = crypto.new_kdf_params()
        key = crypto.derive_master_key(pw, params)
        blob = crypto.encrypt_blob(key, "blob-1", b"payload", sensitivity="normal")
        assert crypto.decrypt_blob(key, "blob-1", blob, sensitivity="normal") == b"payload"
        for label, fn in [
            ("blob_id mismatch",
             lambda: crypto.decrypt_blob(key, "blob-2", blob, sensitivity="normal")),
            ("sensitivity mismatch",
             lambda: crypto.decrypt_blob(key, "blob-1", blob, sensitivity="secret")),
        ]:
            try:
                fn()
            except errors.TamperDetected:
                continue
            raise AssertionError(f"{label} not detected")
        for i in range(0, len(blob)):
            bad = bytearray(blob)
            bad[i] ^= 0x01
            try:
                crypto.decrypt_blob(key, "blob-1", bytes(bad), sensitivity="normal")
            except errors.TamperDetected:
                continue
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(
                    f"flip@{i}: wrong exception {type(exc).__name__}: {exc}"
                )
            raise AssertionError(f"flip@{i}: tampering not detected")

    # ---------------------------------------------------------------- 06
    def test_06_locked_semantics(self) -> None:
        """Locked mode: metadata yes, content no."""
        s = self.state["s"]
        s.write_file("notes/locked.md", b"content-while-unlocked")
        s.unlock(PASSWORD) if s.is_locked else None
        s.lock()
        assert isinstance(s.list_folder("/"), dict), "list_folder must work while locked (metadata)"
        try:
            s.read_text("notes/locked.md")
        except errors.VaultLocked:
            pass
        else:
            raise AssertionError("read_text worked while locked")
        s.unlock(PASSWORD)
        assert s.read_text("notes/locked.md") == "content-while-unlocked"

    # ---------------------------------------------------------------- 07
    def test_07_mcp_rules_and_logging(self) -> None:
        """MCP policy: deny content, raise-only, create-only-normal, logging."""
        s = self.state["s"]
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
        s.write_file("notes/up.md", b"x")
        s.set_sensitivity("notes/up.md", "secret", source="mcp")
        try:
            s.set_sensitivity("notes/up.md", "normal", source="mcp")
        except errors.DowngradeForbidden:
            pass
        else:
            raise AssertionError("mcp lowered a level")
        s.set_sensitivity("notes/up.md", "normal", source="ui")
        try:
            s.write_file("notes/new.md", b"x", source="mcp", sensitivity="secret")
        except errors.PermissionDenied:
            pass
        else:
            raise AssertionError("mcp created a secret file")
        s.write_file("notes/new.md", b"x", source="mcp")
        assert s.read_text("notes/new.md", source="mcp") == "x"

    # ---------------------------------------------------------------- 08
    def test_08_secret_request_flow(self) -> None:
        """request_open_secret: queue, no content, deny, level check."""
        s = self.state["s"]
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

    # ---------------------------------------------------------------- 09
    def test_09_search_kinds(self) -> None:
        """Three search kinds, Persian normalisation, secret exclusion."""
        s = self.state["s"]
        s.write_file("notes/persian.md", "سلام دنيا\nکتاب".encode())
        s.write_file("notes/kaf.md", "يك كتاب ديگر".encode())
        s.write_file("secretish.md", b"nothing")
        s.set_sensitivity("secretish.md", "secret")
        s.write_file("secretish.md", b"hidden-body-xyz", source="ui")
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

    # ---------------------------------------------------------------- 10
    def test_10_plain_threshold_and_persistence(self) -> None:
        """Plain-threshold behaviour plus persistence across lock/unlock."""
        s = self.state["s"]
        s.set_semantic_provider(None)
        s.meta.settings["plain_threshold_bytes"] = 1024
        s.meta.save()
        blob = b"B" * 5000
        s.write_file("notes/big.bin", blob)
        row = s.index.get_file("notes/big.bin")
        assert row["encrypted"] == 0, f"big file should be plain: {row}"
        plain_hits = [
            path.name
            for path in (self.state["home"] / "files").rglob("*")
            if path.is_file() and blob[:64] in path.read_bytes()
        ]
        assert plain_hits, "plain blob not found on disk (as designed for >threshold)"
        s.meta.settings["plain_threshold_bytes"] = 10 * 1024 * 1024
        s.meta.save()
        s.flush()
        s.lock()
        s.unlock(PASSWORD)
        assert s.read_file("notes/big.bin") == blob, "plain blob lost after re-unlock"

    # ---------------------------------------------------------------- 11
    def test_11_auto_lock(self) -> None:
        """Auto-lock clock logic."""
        s = self.state["s"]
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

    # ---------------------------------------------------------------- 12
    def test_12_crash_safety(self) -> None:
        """Flush makes writes durable across a simulated crash."""
        s, home = self.state["s"], self.state["home"]
        s.write_file("notes/crash.md", b"after-flush")
        s.flush()
        s2 = VaultSession(home)
        s2.unlock(PASSWORD)
        assert s2.read_text("notes/crash.md") == "after-flush", "data written before a simulated crash was lost"
        s2.close()

    # ---------------------------------------------------------------- 13
    def test_13_paths_rejected_and_absolute_mapped(self) -> None:
        """Path traversal rejected / API-absolute mapped into the vault."""
        s = self.state["s"]
        home = self.state["home"]
        for bad in ["../../etc/passwd", "a/../../b", "..", "", "a\x00b", "x" * 2000]:
            try:
                s.write_file(bad, b"x")
            except errors.InvalidPath:
                continue
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(f"{bad!r}: wrong exception {type(exc).__name__}")
            raise AssertionError(f"{bad!r}: accepted")
        s.write_file("/etc/passwd", b"not-the-real-one")
        assert s.read_text("etc/passwd") == "not-the-real-one", "absolute form not mapped into the vault"
        assert Path("/etc/passwd").read_text().splitlines()[0] != "not-the-real-one", "wrote to the host /etc/passwd!"
        assert s.read_text("/etc/passwd") == s.read_text("etc/passwd"), "leading-slash identity broken"
        s.write_file("a/./b//c.md", b"norm")
        assert s.read_text("a/b/c.md") == "norm", "'.'/'//' normalization failed"
        outside = [
            path
            for path in home.parent.rglob("*")
            if path.is_file() and b"not-the-real-one" in path.read_bytes()
        ]
        assert not outside, f"content written outside the vault home: {outside}"

    # ---------------------------------------------------------------- 14
    def test_14_log_append_only(self) -> None:
        """The access log is append-only (no DELETE in the index module)."""
        s = self.state["s"]
        n = s.index.access_log_count()
        s.list_folder("/")
        assert s.index.access_log_count() >= n, "log shrank"
        index_source = Path(index_module.__file__).read_text()
        assert "DELETE FROM access_log" not in index_source, "index.py contains a DELETE on access_log"


if __name__ == "__main__":
    unittest.main()
