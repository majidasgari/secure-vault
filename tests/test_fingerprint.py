"""Tests for vault.core.fingerprint (fingerprint quick unlock).

The sensor itself is never touched: ``_spawn`` (the ``fprintd`` client runner) and the
machine identifier are patched, so the suite is deterministic and CI-safe.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from support import DEFAULT_PASSWORD, assert_private_mode, scratch_home
from vault.core import fingerprint
from vault.core.session import VaultSession
from vault.errors import Unauthorized

LISTING = """found 1 devices
Device at /net/reactivated/Fprint/Device/0
Using device /net/reactivated/Fprint/Device/0
Fingerprints for user tester on Goodix Fingerprint Sensor 550A (press):
 - #0: right-index-finger
 - #1: left-index-finger
"""

MATCH_OUTPUT = f"""{LISTING}
Verify started!
Verifying: right-index-finger

Verify result: verify-match (done)
"""

NO_MATCH_OUTPUT = f"""{LISTING}
Verify started!
Verifying: right-index-finger

Verify result: verify-no-match
"""

#: An unreadable scan: fprintd says "try again" and keeps waiting. Taken verbatim from
#: `fprintd-verify -f right-index-finger` on a Goodix 550A — it must never unlock anything.
RETRY_OUTPUT = f"""{LISTING}
Verify started!
Verifying: right-index-finger

Verify result: verify-retry-scan (done)
"""


class FingerprintTestBase(unittest.TestCase):
    """A scratch vault with XDG dirs redirected, so no real record is touched."""

    def setUp(self) -> None:
        self.base = scratch_home()
        self.env = mock.patch.dict(
            os.environ,
            {
                "XDG_DATA_HOME": str(self.base / "data"),
                "XDG_RUNTIME_DIR": str(self.base / "runtime"),
                "SECURE_VAULT_MACHINE_ID": "test-machine",
            },
        )
        self.env.start()
        (self.base / "runtime").mkdir(parents=True, exist_ok=True)
        self.home = self.base / "vault"
        self.session = VaultSession.create(self.home, DEFAULT_PASSWORD)
        self.session._runtime = self.base / "runtime"
        self.session.write_file("notes/a.md", b"# hello\n")

    def tearDown(self) -> None:
        try:
            self.session.close()
        except Exception:  # noqa: BLE001 - teardown must not fail the test
            pass
        self.env.stop()

    @staticmethod
    def matched(fingers: tuple[str, ...] = ("right-index-finger",)) -> fingerprint.VerifyResult:
        """A verification result as a successful scan would produce it."""
        return fingerprint.VerifyResult(True, "match", "0.4s", fingers)

    @property
    def master(self) -> bytes:
        """The vault's master key (a test-only peek at the open session)."""
        key = getattr(self.session, "_master_key", None)
        assert key is not None, "the session must be unlocked"
        return bytes(key)


class RecordTest(FingerprintTestBase):
    """Wrap / unwrap, gating and the record's tamper resistance."""

    def test_disabled_by_default(self) -> None:
        """Without a record, state reports disabled and release refuses."""
        state = fingerprint.quick_unlock_state(self.home)
        self.assertFalse(state["enabled"])
        with self.assertRaises(Unauthorized):
            fingerprint.release_master_key(self.home, self.matched())

    def test_enable_requires_a_matched_verification(self) -> None:
        """A scan that did not match can never write a record."""
        with self.assertRaises(Unauthorized):
            fingerprint.enable_quick_unlock(
                self.home, self.master, fingerprint.VerifyResult(False, "timeout")
            )
        self.assertFalse(fingerprint.record_path(self.home).exists())

    def test_enable_then_release_round_trip(self) -> None:
        """The released key is the vault's master key and opens the vault again."""
        master = bytes(self.master)
        state = fingerprint.enable_quick_unlock(self.home, master, self.matched())
        self.assertTrue(state["enabled"])
        self.assertEqual(state["fingers"], ["right-index-finger"])

        record = fingerprint.record_path(self.home)
        assert_private_mode(record)
        assert_private_mode(fingerprint.device_key_path())
        self.assertNotIn(base64.b64encode(master).decode(), record.read_text())

        self.session.close()
        released = fingerprint.release_master_key(self.home, self.matched())
        self.assertEqual(bytes(released), master)
        fresh = VaultSession(self.home)
        fresh._runtime = self.base / "runtime"
        fresh.unlock_with_master_key(released)
        self.assertFalse(fresh.is_locked)
        self.assertEqual(fresh.read_file("notes/a.md"), b"# hello\n")
        fresh.close()

    def test_release_records_usage(self) -> None:
        """Each successful release bumps the record's counter and timestamp."""
        fingerprint.enable_quick_unlock(self.home, self.master, self.matched())
        self.session.close()
        fingerprint.release_master_key(self.home, self.matched())
        record = fingerprint.load_record(self.home)
        self.assertEqual(record["uses"], 1)
        self.assertIsNotNone(record["last_used_at"])

    def test_tampered_record_is_refused(self) -> None:
        """Editing the wrapped key in place fails authentication."""
        fingerprint.enable_quick_unlock(self.home, self.master, self.matched())
        self.session.close()
        path = fingerprint.record_path(self.home)
        document = json.loads(path.read_text(encoding="utf-8"))
        wrapped = bytearray(base64.b64decode(document["wrapped_b64"]))
        wrapped[0] ^= 0x01
        document["wrapped_b64"] = base64.b64encode(bytes(wrapped)).decode("ascii")
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(Unauthorized) as caught:
            fingerprint.release_master_key(self.home, self.matched())
        self.assertEqual(caught.exception.details["reason"], "authentication_failed")

    def test_record_is_bound_to_the_machine(self) -> None:
        """A record copied to another machine/account cannot be unwrapped there."""
        fingerprint.enable_quick_unlock(self.home, self.master, self.matched())
        self.session.close()
        with mock.patch.dict(os.environ, {"SECURE_VAULT_MACHINE_ID": "another-machine"}):
            with self.assertRaises(Unauthorized):
                fingerprint.release_master_key(self.home, self.matched())

    def test_missing_device_key_disables_the_feature(self) -> None:
        """Without the device secret the state reports disabled and release refuses."""
        fingerprint.enable_quick_unlock(self.home, self.master, self.matched())
        fingerprint.device_key_path().unlink()
        state = fingerprint.quick_unlock_state(self.home)
        self.assertFalse(state["enabled"])
        self.assertEqual(state["reason"], "device_key_missing")
        with self.assertRaises(Unauthorized):
            fingerprint.release_master_key(self.home, self.matched())

    def test_disable_removes_the_record(self) -> None:
        """Disable is idempotent and drops the record."""
        fingerprint.enable_quick_unlock(self.home, self.master, self.matched())
        self.assertTrue(fingerprint.disable_quick_unlock(self.home))
        self.assertFalse(fingerprint.quick_unlock_state(self.home)["enabled"])
        self.assertFalse(fingerprint.disable_quick_unlock(self.home))

    def test_record_of_another_vault_home_is_ignored(self) -> None:
        """The record carries the vault path, so a copied record does not match here."""
        fingerprint.enable_quick_unlock(self.home, self.master, self.matched())
        other = self.base / "vault-copy"
        other.mkdir()
        for name in (".vault-meta.json", "meta.sqlite"):
            source = self.home / name
            if source.exists():
                (other / name).write_bytes(source.read_bytes())
        self.assertIsNone(fingerprint.load_record(other))

    def test_state_keeps_the_enrolment_list(self) -> None:
        """The state reports the fingers from the record, not the live sensor."""
        fingerprint.enable_quick_unlock(
            self.home, self.master, self.matched(("right-thumb",))
        )
        state = fingerprint.quick_unlock_state(self.home)
        self.assertEqual(state["fingers"], ["right-thumb"])
        self.assertEqual(state["protection"], fingerprint.PROTECTION_FILE)


class SessionQuickUnlockTest(FingerprintTestBase):
    """The session-level helpers used by the desktop app and the web API."""

    def test_enable_requires_an_unlocked_session(self) -> None:
        """A locked session has no key to wrap."""
        from vault.errors import VaultLocked

        self.session.lock()
        with self.assertRaises(VaultLocked):
            self.session.quick_unlock_enable(self.matched())

    def test_session_enable_and_status(self) -> None:
        """Enabling through the session stores a record the session can report."""
        state = self.session.quick_unlock_enable(self.matched())
        self.assertTrue(state["enabled"])
        self.assertTrue(self.session.quick_unlock_status()["enabled"])
        rows = self.session.index.access_log(limit=5)
        tools = [row["tool"] for row in rows]
        self.assertIn("vault.quick_unlock_enable", tools)
        self.assertTrue(self.session.quick_unlock_disable())
        self.assertFalse(self.session.quick_unlock_status()["enabled"])

    def test_unlock_with_master_key_rejects_a_foreign_key(self) -> None:
        """A wrong key is refused exactly like a wrong password."""
        self.session.close()
        fresh = VaultSession(self.home)
        with self.assertRaises(Unauthorized) as caught:
            fresh.unlock_with_master_key(bytes(32))
        self.assertEqual(caught.exception.details["reason"], "canary_mismatch")
        self.assertTrue(fresh.is_locked)

    def test_unlock_with_master_key_opens_the_vault(self) -> None:
        """The real key unlocks and reads like a password unlock."""
        master = bytes(self.master)
        self.session.close()
        fresh = VaultSession(self.home)
        fresh._runtime = self.base / "runtime"
        fresh.unlock_with_master_key(master)
        self.assertFalse(fresh.is_locked)
        self.assertEqual(fresh.read_file("notes/a.md"), b"# hello\n")
        # Unlocking an already-open session is a no-op, not an error.
        fresh.unlock_with_master_key(master)
        fresh.close()


class VerifyTest(unittest.TestCase):
    """Parsing of the ``fprintd`` client output (no sensor involved)."""

    def setUp(self) -> None:
        """Pretend the ``fprintd`` CLI is installed.

        ``verify()``/``device_info()`` refuse to spawn anything when the CLI tools are
        missing, so without this the suite would depend on the developer's machine having
        a fingerprint reader (and fail on any CI box that does not, Windows included).
        ``_spawn`` is mocked in every test here, so nothing is ever executed.
        """
        self._available = mock.patch.object(fingerprint, "fprintd_available", return_value=True)
        self._available.start()

    def tearDown(self) -> None:
        """Restore the real availability probe."""
        self._available.stop()

    def test_match_output_is_a_match(self) -> None:
        with mock.patch.object(
            fingerprint, "_spawn", return_value=fingerprint.SpawnResult(0, MATCH_OUTPUT)
        ):
            result = fingerprint.verify()
        self.assertTrue(result.matched)
        self.assertEqual(result.reason, "match")
        self.assertIn("right-index-finger", result.fingers)

    def test_no_match_output_is_a_failure(self) -> None:
        with mock.patch.object(
            fingerprint, "_spawn", return_value=fingerprint.SpawnResult(1, NO_MATCH_OUTPUT)
        ):
            result = fingerprint.verify()
        self.assertFalse(result.matched)
        self.assertEqual(result.reason, "no_match")

    def test_retry_scan_is_never_a_match(self) -> None:
        """`verify-retry-scan` means "unreadable, try again" — exit 0 included.

        A real fprintd prints this while it keeps waiting, so treating it as success would
        unlock the vault without a finger.
        """
        for code in (0, 1, None):
            with self.subTest(returncode=code), mock.patch.object(
                fingerprint, "_spawn", return_value=fingerprint.SpawnResult(code, RETRY_OUTPUT)
            ):
                result = fingerprint.verify()
                self.assertFalse(result.matched)
                self.assertEqual(result.reason, "no_match")

    def test_retry_then_match_is_a_match(self) -> None:
        """The normal partial-read flow still ends in a match."""
        output = RETRY_OUTPUT + "Verify result: verify-match (done)\n"
        with mock.patch.object(
            fingerprint, "_spawn", return_value=fingerprint.SpawnResult(0, output)
        ):
            self.assertTrue(fingerprint.verify().matched)

    def test_timeout_and_cancel_and_busy(self) -> None:
        """Timeout, cancellation and a claimed device are ordinary results."""
        with mock.patch.object(
            fingerprint,
            "_spawn",
            return_value=fingerprint.SpawnResult(None, "", "", timed_out=True),
        ):
            self.assertEqual(fingerprint.verify().reason, "timeout")
        with mock.patch.object(
            fingerprint,
            "_spawn",
            return_value=fingerprint.SpawnResult(None, "", "", cancelled=True),
        ):
            self.assertEqual(fingerprint.verify().reason, "cancelled")
        self.assertTrue(fingerprint._SCAN_LOCK.acquire(blocking=False))
        try:
            self.assertEqual(fingerprint.verify(timeout=0.5).reason, "busy")
        finally:
            fingerprint._SCAN_LOCK.release()

    def test_errors_are_reported_not_raised(self) -> None:
        """A spawn error and a missing sensor produce reasons, never exceptions."""
        with mock.patch.object(
            fingerprint,
            "_spawn",
            return_value=fingerprint.SpawnResult(None, "", "Failed to open device"),
        ):
            result = fingerprint.verify()
        self.assertFalse(result.matched)
        self.assertEqual(result.reason, "error")
        self.assertIn("Failed to open device", result.message)
        with mock.patch.object(fingerprint, "fprintd_available", return_value=False):
            self.assertEqual(fingerprint.verify().reason, "unavailable")

    def test_device_info_reads_the_listing(self) -> None:
        """The sensor line, the device and the enrolled fingers are parsed."""
        with mock.patch.object(
            fingerprint,
            "_spawn",
            return_value=fingerprint.SpawnResult(0, LISTING),
        ):
            info = fingerprint.device_info("tester")
        self.assertTrue(info["available"])
        self.assertEqual(info["device"], "/net/reactivated/Fprint/Device/0")
        self.assertEqual(info["fingers"], ["right-index-finger", "left-index-finger"])

    def test_device_info_reports_missing_enrolment(self) -> None:
        """A device without an enrolled finger is not 'available'."""
        listing = f"Device at /dev/0\nFingerprints for user tester on X (press):\n"
        with mock.patch.object(
            fingerprint, "_spawn", return_value=fingerprint.SpawnResult(0, listing)
        ):
            info = fingerprint.device_info("tester")
        self.assertFalse(info["available"])
        self.assertEqual(info["reason"], "no_enrolled_finger")


class SpawnTest(unittest.TestCase):
    """The real ``_spawn`` (short-lived interpreter commands, no fprintd)."""

    def test_spawn_captures_output_and_code(self) -> None:
        result = fingerprint._spawn(
            [sys.executable, "-c", "print('verify-match')"], timeout=15
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("verify-match", result.stdout)

    def test_spawn_times_out_and_terminates(self) -> None:
        result = fingerprint._spawn([sys.executable, "-c", "import time; time.sleep(30)"], 1)
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.returncode)

    def test_spawn_honours_cancel(self) -> None:
        cancel = threading.Event()
        threading.Timer(0.4, cancel.set).start()
        result = fingerprint._spawn(
            [sys.executable, "-c", "import time; time.sleep(30)"], 30, cancel
        )
        self.assertTrue(result.cancelled)

    def test_spawn_reports_a_missing_binary(self) -> None:
        missing = str(Path(tempfile.gettempdir()) / "sv-no-such-dir" / "fprintd-verify")
        result = fingerprint._spawn([missing], timeout=5)
        self.assertIsNone(result.returncode)
        self.assertIn("FileNotFoundError", result.stderr)


if __name__ == "__main__":
    unittest.main()
