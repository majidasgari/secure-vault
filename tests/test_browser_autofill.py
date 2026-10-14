"""Tests for the browser-autofill bridge (``core/credentials.py`` + ``api/browser.py``).

Three layers:

* pure helpers — body parsing, host normalisation, registrable domain and match ranking;
* the bridge itself — the credential index, the reveal rules (path containment, host match,
  switch, lock, rate limit) and the "scan is silent, reveal is audited" contract;
* the loopback HTTP surface — the two tokens stay separate, ``/api/autofill/*`` answers only the
  browser token, and every reveal lands in the access log with ``source="browser"``.

The credential bodies below are data under test (the same shape
``tools/keepass-migration/apply.py`` writes); a separate test asserts that shape has not drifted.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import unittest
from pathlib import Path

from support import assert_private_mode, tmp_vault
from vault.api.browser import BrowserBridge
from vault.api.service import Service
from vault.core import credentials as creds
from vault.core import semantics
from vault.core.credentials import BROWSER_CATEGORY, CREDENTIAL_ROOT
from vault.core.security import BROWSER_CREATABLE_LEVELS, SOURCE_BROWSER, Policy
from vault.core.session import VaultSession
from vault.errors import BadRequest, PermissionDenied, VaultLocked
from vault.web.server import WebServer

REPO_ROOT = Path(__file__).resolve().parents[1]
IMPORTER = REPO_ROOT / "tools" / "keepass-migration" / "apply.py"

GITHUB_BODY = """# GitHub

سایت: github.com | دسته: برنامه‌نویسی

نام کاربری: max@example.com
گذرواژه: github-pass-1
آدرس: https://github.com/login
کد یکبارمصرف (otp): JBSWY3DPEHPK3PXP
برچسب‌ها: dev, code

## یادداشت
این یادداشت است، نه فیلد.
password: do-not-parse
"""

GIST_BODY = """# Gist mirror

سایت: گیت‌هاب گیست | دسته: برنامه‌نویسی

نام کاربری: gist-user
گذرواژه: gist-pass
آدرس: https://gist.github.com/
"""

BANK_BODY = """# بانک نمونه

سایت: bank.example | دسته: بانکی

نام کاربری: 1234567890
گذرواژه: bank-pass
شماره کارت: 6037-0000-0000-0000
"""

EMPTY_PASSWORD_BODY = """# No password here

سایت: notes.example | دسته: متفرقه

نام کاربری: someone
گذرواژه: —
"""


def seed(session: VaultSession, path: str, body: str, *, level: str = "secretfile") -> str:
    """Write one credential file (creating parents) and return its logical path."""
    logical = path.strip("/")
    parts = logical.split("/")
    for index in range(1, len(parts)):
        try:
            session.mkdir("/".join(parts[:index]), source="ui")
        except Exception:  # noqa: BLE001 - the folder may already exist
            pass
    session.write_file(logical, body.encode("utf-8"), source="ui", sensitivity=level)
    return "/" + logical


class ParseBodyTest(unittest.TestCase):
    """The credential body parser."""

    def test_full_body(self) -> None:
        """Every documented field is parsed and the notes section is ignored."""
        parsed = creds.parse_body(GITHUB_BODY)
        self.assertEqual(parsed["title"], "GitHub")
        self.assertEqual(parsed["site"], "github.com")
        self.assertEqual(parsed["category"], "برنامه‌نویسی")
        self.assertEqual(parsed["username"], "max@example.com")
        self.assertEqual(parsed["password"], "github-pass-1")
        self.assertEqual(parsed["url"], "https://github.com/login")
        self.assertTrue(parsed["has_otp"])
        self.assertEqual(parsed["otp"], "JBSWY3DPEHPK3PXP")
        self.assertIn("github.com", parsed["hosts"])
        self.assertTrue(parsed["has_password"])

    def test_notes_are_not_fields(self) -> None:
        """A ``label: value`` line inside the notes section is never a field."""
        parsed = creds.parse_body(GITHUB_BODY)
        self.assertNotIn("do-not-parse", json.dumps(parsed, ensure_ascii=False))

    def test_empty_password_marker(self) -> None:
        """The em-dash empty marker means "no password"."""
        parsed = creds.parse_body(EMPTY_PASSWORD_BODY)
        self.assertEqual(parsed["password"], "")
        self.assertFalse(parsed["has_password"])
        self.assertEqual(parsed["username"], "someone")

    def test_persian_site_name_still_matches_by_url(self) -> None:
        """A Persian site folder with a real URL still yields a host candidate."""
        parsed = creds.parse_body(GIST_BODY, fallback_site="گیت‌هاب گیست")
        self.assertEqual(parsed["site"], "گیت‌هاب گیست")
        self.assertEqual(parsed["hosts"], ["gist.github.com"])

    def test_fallbacks(self) -> None:
        """Missing title/site fall back to the file name and its parent folder."""
        parsed = creds.parse_body("نام کاربری: u\nگذرواژه: p\n", fallback_title="entry.md", fallback_site="arusha.dev")
        self.assertEqual(parsed["title"], "entry.md")
        self.assertEqual(parsed["site"], "arusha.dev")
        self.assertEqual(parsed["hosts"], ["arusha.dev"])

    def test_heading_wins_over_the_file_name(self) -> None:
        """The entry's own heading names it — the file name must not shadow a real title."""
        parsed = creds.parse_body(GITHUB_BODY, fallback_title="github-login.md", fallback_site="برنامه‌نویسی")
        self.assertEqual(parsed["title"], "GitHub")
        self.assertIn("github.com", parsed["hosts"])

    def test_the_file_name_stays_a_host_candidate(self) -> None:
        """A file named after its site still matches that site, heading or not."""
        # The index passes the file *stem* (extension already stripped) as the fallback title.
        parsed = creds.parse_body("# نام دلخواه\n\nنام کاربری: u\nگذرواژه: p\n", fallback_title="github.com")
        self.assertEqual(parsed["title"], "نام دلخواه")
        self.assertIn("github.com", parsed["hosts"])


class HostHelpersTest(unittest.TestCase):
    """Host normalisation, registrable domains and match ranking."""

    def test_normalize_host(self) -> None:
        """Schemes, paths, ports, userinfo and a leading ``www.`` are stripped."""
        cases = {
            "https://www.GitHub.com/login?x=1": "github.com",
            "github.com:443": "github.com",
            "https://user:pw@panel.iranicard.ir/x": "panel.iranicard.ir",
            "  Example.COM.  ": "example.com",
            "localhost": "localhost",
            "127.0.0.1:8788": "127.0.0.1",
            "بانک ملت": "",
            "": "",
            "Bitbarg": "",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(creds.normalize_host(raw), expected)

    def test_registrable_domain(self) -> None:
        """Two-label suffixes are handled without a public-suffix list."""
        cases = {
            "accounts.google.com": "google.com",
            "mail.najm.ac": "najm.ac",
            "student.iust.ac.ir": "iust.ac.ir",
            "panel.iranicard.ir": "iranicard.ir",
            "localhost": "localhost",
            "127.0.0.1": "127.0.0.1",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(creds.registrable_domain(raw), expected)

    def test_match_ranking(self) -> None:
        """Exact beats parent-domain beats same-registrable beats candidate subdomain."""
        exact = creds.match_score("github.com", "github.com")
        parent = creds.match_score("accounts.google.com", "google.com")
        same_registrable = creds.match_score("github.com", "gist.github.com")
        self.assertEqual(exact, 100)
        self.assertGreater(parent, same_registrable)
        self.assertGreater(same_registrable, 0)
        self.assertEqual(creds.match_score("github.com", "example.com"), 0)
        self.assertEqual(creds.match_score("", "github.com"), 0)
        self.assertEqual(creds.match_score("github.com", "not-a-host"), 0)

    def test_case_and_scheme_insensitive(self) -> None:
        """A URL candidate matches a bare page host."""
        self.assertEqual(creds.match_score("GitHub.com", "https://github.com/login"), 100)


class IndexTest(unittest.TestCase):
    """The credential index built over a scratch vault."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        seed(self.session, "/رمزها/برنامه‌نویسی/github.com/GitHub.md", GITHUB_BODY)
        seed(self.session, "/رمزها/برنامه‌نویسی/gist.github.com/Gist mirror.md", GIST_BODY)
        seed(self.session, "/رمزها/بانکی/bank.example/بانک نمونه.md", BANK_BODY)
        seed(self.session, "/رمزها/متفرقه/notes.example/No password here.md", EMPTY_PASSWORD_BODY)
        seed(self.session, "/رمزها/برنامه‌نویسی/github.com/normal.md", "just a note\n", level="normal")

    def tearDown(self) -> None:
        self.session.close()

    def test_build_counts(self) -> None:
        """Every file under the credential root is parsed, whatever its level."""
        index = creds.CredentialIndex(self.session)
        status = index.build()
        self.assertTrue(status["ready"])
        self.assertEqual(status["entries"], 5)
        self.assertEqual(status["passwords"], 3)
        self.assertEqual(status["usernames"], 4)
        self.assertEqual(status["files"], 5)

    def test_match_exact_first(self) -> None:
        """An exact host match outranks a same-registrable cousin."""
        index = creds.CredentialIndex(self.session)
        results = index.match("github.com")
        self.assertGreaterEqual(len(results), 2)
        self.assertEqual(results[0]["path"], "/رمزها/برنامه‌نویسی/github.com/GitHub.md")
        self.assertEqual(results[0]["score"], 100)
        self.assertEqual(results[0]["username"], "max@example.com")

    def test_match_payload_has_no_password(self) -> None:
        """Matching is metadata only: no candidate ever carries a password value."""
        index = creds.CredentialIndex(self.session)
        blob = json.dumps(index.match("github.com"), ensure_ascii=False)
        for secret in ("github-pass-1", "gist-pass", "bank-pass"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, blob)
        self.assertNotIn('"password"', blob)
        self.assertNotIn('"otp"', blob)

    def test_match_unknown_host_is_empty(self) -> None:
        """An unrelated host matches nothing; a junk host is refused by the bridge."""
        index = creds.CredentialIndex(self.session)
        self.assertEqual(index.match("totally-other.example"), [])
        self.assertEqual(index.match(""), [])

    def test_rebuild_after_write(self) -> None:
        """The cache notices a newly written entry (signature-based, no TTL guess)."""
        index = creds.CredentialIndex(self.session)
        self.assertEqual(len(index.match("bank.example")), 1)
        seed(self.session, "/رمزها/بانکی/bank.example/دوم.md", BANK_BODY.replace("bank-pass", "bank-pass-2"))
        self.assertEqual(len(index.match("bank.example")), 2)


class BridgeTest(unittest.TestCase):
    """The bridge rules: containment, host match, switch, lock, rate limit, auditing."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.service = Service(self.session)
        self.path = seed(self.session, "/رمزها/برنامه‌نویسی/github.com/GitHub.md", GITHUB_BODY)
        seed(self.session, "/رمزها/بانکی/bank.example/بانک نمونه.md", BANK_BODY)
        seed(self.session, "/notes/plain.md", "a normal note\n", level="normal")
        self.bridge = BrowserBridge(self.service, runtime_dir=self.session._runtime)
        self.service.attach_browser(self.bridge)
        self.bridge.start()
        self.activity: list[dict] = []
        self.session.on_activity = self.activity.append

    def tearDown(self) -> None:
        self.bridge.stop()
        self.session.close()

    def logs(self) -> list[dict]:
        """Return the access-log rows, newest first."""
        return self.session.access_log(limit=200)

    def test_token_file_written_and_removed(self) -> None:
        """The token file lives in the runtime dir with mode 0600 and goes away on stop."""
        self.assertTrue(self.bridge.token_file.exists())
        assert_private_mode(self.bridge.token_file)
        document = json.loads(self.bridge.token_file.read_text(encoding="utf-8"))
        self.assertEqual(document["token"], self.bridge.token)
        self.bridge.stop()
        self.assertFalse(self.bridge.token_file.exists())

    def test_reveal_returns_fields(self) -> None:
        """A reveal returns the fields of exactly that entry."""
        data = self.bridge.reveal(self.path, host="github.com")
        self.assertEqual(data["username"], "max@example.com")
        self.assertEqual(data["password"], "github-pass-1")
        self.assertEqual(data["otp"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(data["url"], "https://github.com/login")

    def test_reveal_requires_a_matching_host(self) -> None:
        """A page can only receive an entry that actually belongs to it."""
        with self.assertRaises(PermissionDenied) as ctx:
            self.bridge.reveal(self.path, host="evil.example")
        self.assertEqual(ctx.exception.message, "host_mismatch")

    def test_reveal_outside_the_credential_root_is_refused(self) -> None:
        """No path outside ``/رمزها`` can be revealed, whatever the level."""
        for path in ("/notes/plain.md", "/", "/رمزها"):
            with self.subTest(path=path):
                with self.assertRaises(PermissionDenied) as ctx:
                    self.bridge.reveal(path, host="github.com")
                self.assertIn(ctx.exception.message, ("path_outside_credentials", "is_directory"))

    def test_disabled_switch_refuses_everything(self) -> None:
        """Turning the setting off refuses match and reveal alike."""
        settings = self.session.meta.settings
        settings.setdefault("browser", {})["enabled"] = False
        self.session.meta.save()
        with self.assertRaises(PermissionDenied):
            self.bridge.match("github.com")
        with self.assertRaises(PermissionDenied):
            self.bridge.reveal(self.path, host="github.com")
        status = self.bridge.status()
        self.assertFalse(status["enabled"])
        self.assertNotIn("index", status)

    def test_locked_vault_refuses(self) -> None:
        """A locked vault refuses a match with VAULT_LOCKED (the add-on shows "unlock it")."""
        self.session.lock()
        with self.assertRaises(VaultLocked):
            self.bridge.match("github.com")
        status = self.bridge.status()
        self.assertTrue(status["locked"])
        self.assertNotIn("index", status)

    def test_match_needs_a_host(self) -> None:
        """A request without a usable host is a bad request, not an empty answer."""
        with self.assertRaises(BadRequest):
            self.bridge.match("")
        self.assertIn("github.com", self.bridge.match("https://github.com/login")["host"])

    def test_rate_limit(self) -> None:
        """The rolling per-minute reveal limit refuses a runaway caller."""
        bridge = BrowserBridge(
            self.service, runtime_dir=self.session._runtime, reveal_limit=3
        )
        self.service.attach_browser(bridge)
        for _ in range(3):
            bridge.reveal(self.path, host="github.com")
        with self.assertRaises(PermissionDenied) as ctx:
            bridge.reveal(self.path, host="github.com")
        self.assertEqual(ctx.exception.message, "too_many_reveals")
        self.assertEqual(bridge.reveals_last_minute(), 3)

    def test_scan_is_silent_but_the_reveal_is_audited(self) -> None:
        """Building the index writes no per-file row, and neither scan nor match emit an event;
        the audited path is the dispatched reveal (one row with ``source=browser``)."""
        self.activity.clear()
        self.service.dispatch(
            "vault.browser_match",
            {"host": "github.com"},
            role="browser",
            session_id="brw-1",
            source="browser",
        )
        self.assertEqual(self.activity, [])
        tools = [row["tool"] for row in self.logs()]
        self.assertIn("vault.browser_match", tools)
        self.assertNotIn("read_file", tools)

        result = self.service.dispatch(
            "vault.browser_reveal",
            {"path": self.path, "host": "github.com"},
            role="browser",
            session_id="brw-2",
            source="browser",
        )
        self.assertEqual(result["password"], "github-pass-1")
        rows = [row for row in self.logs() if row["tool"] == "vault.browser_reveal"]
        self.assertTrue(rows, "the reveal must be audited")
        self.assertEqual(rows[0]["target_path"], self.path)
        self.assertEqual(rows[0]["source"], "browser")
        self.assertEqual(rows[0]["role"], "browser")
        self.assertEqual(rows[0]["outcome"], "allow")
        reads = [event for event in self.activity if event.get("kind") == "read"]
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0]["source"], "browser")
        self.assertEqual(reads[0]["path"], self.path.lstrip("/"))
        self.assertEqual(reads[0]["outcome"], "allow")

    def test_activity_is_not_flooded_by_the_scan(self) -> None:
        """A rebuild over many entries emits no allowed-read events at all."""
        for index in range(5):
            seed(self.session, f"/رمزها/بانکی/bank.example/ورودی {index}.md", BANK_BODY)
        self.activity.clear()
        self.service.dispatch(
            "vault.browser_match",
            {"host": "bank.example", "limit": 50},
            role="browser",
            session_id="brw-1",
        )
        self.assertEqual([e for e in self.activity if e.get("outcome") == "allow"], [])

    # -------------------------------------------------------------------- saving
    def test_save_check_reports_same_changed_and_new(self) -> None:
        """The verdict is the whole point: an unchanged password must write nothing."""
        same = self.bridge.save_check(
            "github.com", username="max@example.com", password="github-pass-1"
        )
        self.assertEqual(same["state"], "same")
        self.assertEqual(same["path"], self.path)
        changed = self.bridge.save_check(
            "github.com", username="max@example.com", password="something-else"
        )
        self.assertEqual(changed["state"], "changed")
        self.assertEqual(changed["path"], self.path)
        fresh = self.bridge.save_check(
            "newsite.example", username="someone@newsite.example", password="pw"
        )
        self.assertEqual(fresh["state"], "new")
        self.assertEqual(
            fresh["path"],
            f"/{creds.CREDENTIAL_ROOT}/{creds.BROWSER_CATEGORY}/newsite.example/newsite.example.md",
        )

    def test_a_same_verdict_writes_nothing_at_all(self) -> None:
        """A successful sign-in with the stored password leaves no trace in the vault."""
        before = self.session.read_file(self.path, source="ui")
        rows_before = len(self.logs())
        verdict = self.bridge.save(
            "github.com", username="max@example.com", password="github-pass-1"
        )
        self.assertEqual(verdict["state"], "same")
        self.assertFalse(verdict["saved"])
        fresh = self.logs()[: len(self.logs()) - rows_before]
        self.assertEqual([row["tool"] for row in fresh], [], "a `same` verdict must not write")
        self.assertEqual(self.session.read_file(self.path, source="ui"), before)

    def test_a_changed_password_rewrites_only_that_one_line(self) -> None:
        """The update keeps the heading, the meta line, the OTP and the notes section."""
        verdict = self.bridge.save(
            "github.com", username="max@example.com", password="github-pass-2"
        )
        self.assertEqual(verdict["state"], "updated")
        self.assertTrue(verdict["saved"])
        self.assertEqual(verdict["path"], self.path)
        body = self.session.read_file(self.path, source="ui").decode("utf-8")
        self.assertIn("گذرواژه: github-pass-2", body)
        self.assertNotIn("github-pass-1", body)
        for kept in ("# GitHub", "سایت: github.com | دسته: برنامه‌نویسی", "نام کاربری: max@example.com"):
            with self.subTest(kept=kept):
                self.assertIn(kept, body)
        self.assertIn("کد یکبارمصرف (otp): JBSWY3DPEHPK3PXP", body)
        self.assertIn("## یادداشت", body)
        self.assertIn("این یادداشت است، نه فیلد.", body)
        self.assertIn("password: do-not-parse", body)          # the notes' own text is data
        row = self.session.index.require_file(self.path.lstrip("/"))
        self.assertEqual(row["sensitivity"], "secretfile")

    def test_a_new_credential_is_created_like_the_treasure_writes_them(self) -> None:
        """A brand-new login lands as a `secretfile` in the browser category, with notes."""
        verdict = self.bridge.save(
            "mail.example",
            username="someone@mail.example",
            password="fresh-pass",
            url="https://mail.example/login",
            title="Mail Example",
        )
        self.assertEqual(verdict["state"], "created")
        self.assertTrue(verdict["saved"])
        expected = f"/{creds.CREDENTIAL_ROOT}/{creds.BROWSER_CATEGORY}/mail.example/mail.example.md"
        self.assertEqual(verdict["path"], expected)
        row = self.session.index.require_file(expected.lstrip("/"))
        self.assertEqual(row["sensitivity"], "secretfile")
        body = self.session.read_file(expected, source="ui").decode("utf-8")
        for line in (
            "# Mail Example",
            f"سایت: mail.example | دسته: {creds.BROWSER_CATEGORY}",
            "نام کاربری: someone@mail.example",
            "گذرواژه: fresh-pass",
            "آدرس: https://mail.example/login",
        ):
            with self.subTest(line=line):
                self.assertIn(line, body)
        self.assertTrue(self.session.file_note(expected))
        self.assertTrue(
            self.session.store.get_folder_note(
                f"{creds.CREDENTIAL_ROOT}/{creds.BROWSER_CATEGORY}/mail.example"
            )
        )
        # …and the vault's own matching now offers it for that host.
        entries = self.bridge.entries(force=True)
        self.assertTrue(any(entry.path == expected for entry in entries))

    def test_a_second_account_gets_its_own_file(self) -> None:
        """Two user names for one host are two entries, named the way the category already is."""
        first = self.bridge.save("mail.example", username="a@mail.example", password="pw-a")
        second = self.bridge.save("mail.example", username="b@mail.example", password="pw-b")
        self.assertNotEqual(first["path"], second["path"])
        self.assertEqual(
            second["path"],
            f"/{creds.CREDENTIAL_ROOT}/{creds.BROWSER_CATEGORY}/mail.example/mail.example (2).md",
        )

    def test_save_refuses_a_path_that_is_not_this_host_s(self) -> None:
        """The add-on may name an entry, but only one that really belongs to the page's host."""
        with self.assertRaises(PermissionDenied) as ctx:
            self.bridge.save(
                "evil.example",
                username="max@example.com",
                password="pw",
                path=self.path,
            )
        self.assertEqual(ctx.exception.message, "path_not_for_host")
        with self.assertRaises(PermissionDenied):
            self.bridge.save(
                "github.com", username="max@example.com", password="pw", path="/notes/plain.md"
            )

    def test_save_refuses_a_value_a_credential_body_cannot_hold(self) -> None:
        """A newline in a password would silently split the label line, so it is refused."""
        with self.assertRaises(BadRequest) as ctx:
            self.bridge.save("mail.example", username="a", password="one\ntwo")
        self.assertEqual(ctx.exception.message, "unstorable_value")
        with self.assertRaises(BadRequest):
            self.bridge.save("mail.example", username="a" * 300, password="pw")
        with self.assertRaises(BadRequest):
            self.bridge.save("mail.example", username="a", password="")
        with self.assertRaises(BadRequest):
            self.bridge.save("", username="a", password="pw")

    def test_saving_can_be_switched_off_without_touching_filling(self) -> None:
        """``save_enabled`` off refuses the two save calls and leaves match/reveal alone."""
        settings = self.session.meta.settings
        settings.setdefault("browser", {})["save_enabled"] = False
        self.session.meta.save()
        with self.assertRaises(PermissionDenied) as ctx:
            self.bridge.save_check("github.com", username="max@example.com", password="x")
        self.assertEqual(ctx.exception.message, "browser_save_disabled")
        with self.assertRaises(PermissionDenied):
            self.bridge.save("github.com", username="max@example.com", password="x")
        self.assertEqual(self.bridge.reveal(self.path, host="github.com")["password"], "github-pass-1")
        self.assertFalse(self.bridge.status()["save_enabled"])

    def test_a_locked_vault_refuses_a_save(self) -> None:
        """Nothing may be written while locked (the add-on offers to unlock instead)."""
        self.session.lock()
        with self.assertRaises(VaultLocked):
            self.bridge.save("mail.example", username="a", password="pw")
        with self.assertRaises(VaultLocked):
            self.bridge.save_check("mail.example", username="a", password="pw")

    def test_the_save_limit_stops_a_runaway_caller(self) -> None:
        """A page cannot write into the credential folder over and over in one minute."""
        bridge = BrowserBridge(self.service, runtime_dir=self.session._runtime, save_limit=2)
        self.service.attach_browser(bridge)
        bridge.save("one.example", username="a", password="pw")
        bridge.save("two.example", username="a", password="pw")
        with self.assertRaises(PermissionDenied) as ctx:
            bridge.save("three.example", username="a", password="pw")
        self.assertEqual(ctx.exception.message, "too_many_saves")
        self.assertEqual(bridge.saves_last_minute(), 2)

    def test_a_save_is_audited_once_and_writes_no_read_rows(self) -> None:
        """The dispatch row is the whole audit trail; the internal compare reads stay silent."""
        self.activity.clear()
        result = self.service.dispatch(
            "vault.browser_save",
            {"host": "github.com", "username": "max@example.com", "password": "github-pass-9"},
            role="browser",
            session_id="brw-9",
            source="browser",
        )
        self.assertEqual(result["state"], "updated")
        rows = [row for row in self.logs() if row["tool"] == "vault.browser_save"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "browser")
        self.assertEqual(rows[0]["role"], "browser")
        self.assertEqual(rows[0]["outcome"], "allow")
        self.assertNotIn("read_file", [row["tool"] for row in self.logs()][:3])
        writes = [event for event in self.activity if event.get("kind") == "write"]
        self.assertTrue(writes)
        self.assertTrue(all(event["source"] == SOURCE_BROWSER for event in writes))


class BrowserPolicyTest(unittest.TestCase):
    """The one permission the read-only bridge gained, and everything it must not gain."""

    def test_the_bridge_may_create_a_credential_and_nothing_else(self) -> None:
        """`normal → secretfile` only: no `secret`, no raising an existing file, no lowering."""
        self.assertTrue(Policy.can_raise("normal", "secretfile", SOURCE_BROWSER))
        for pair in (("normal", "secret"), ("normal", "normal"), ("secretfile", "secretfile")):
            with self.subTest(pair=pair):
                self.assertFalse(Policy.can_raise(pair[0], pair[1], SOURCE_BROWSER))
        with self.assertRaises(BadRequest):
            Policy.can_lower("secretfile", "normal", SOURCE_BROWSER)

    def test_the_bridge_levels_are_the_credential_level(self) -> None:
        """The level a browser-saved credential is born at is the treasure's own."""
        self.assertEqual(BROWSER_CREATABLE_LEVELS, ("secretfile",))
        self.assertEqual(Policy.can_read_content("secretfile", SOURCE_BROWSER), True)


class AutofillHttpTest(unittest.TestCase):
    """The loopback HTTP surface and the two-token separation."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.session.set_semantic_provider(semantics.StubProvider())
        self.service = Service(self.session)
        self.path = seed(self.session, "/رمزها/برنامه‌نویسی/github.com/GitHub.md", GITHUB_BODY)
        self.server = WebServer(
            self.service,
            host="127.0.0.1",
            port=0,
            runtime_dir=self.session._runtime,
            keepalive=1.0,
        )
        self.server.start()
        self.port = self.server.port
        self.web_token = self.server.token
        self.browser_token = self.server.browser.token

    def tearDown(self) -> None:
        self.server.stop()
        self.session.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict]:
        """Perform one HTTP request and return ``(status, parsed_json)``."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5.0)
        send = dict(headers or {})
        if token is not None:
            send["X-Vault-Token"] = token
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        try:
            conn.request(method, path, body=payload, headers=send)
            response = conn.getresponse()
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8") or "{}")
        finally:
            conn.close()

    def claim(self, scope: str | None = None) -> tuple[int, dict]:
        """Ask for a token the way the add-on does (loopback + X-Vault-Claim)."""
        body = {"scope": scope} if scope else {}
        return self.request(
            "POST", "/api/session/claim", body=body, headers={"X-Vault-Claim": "1"}
        )

    def test_claim_scopes_are_separate_secrets(self) -> None:
        """The browser scope returns the browser token and never the web one."""
        status, payload = self.claim("browser")
        self.assertEqual(status, 200)
        self.assertEqual(payload["scope"], "browser")
        self.assertEqual(payload["token"], self.browser_token)
        self.assertNotEqual(payload["token"], self.web_token)
        status, payload = self.claim()
        self.assertEqual(status, 200)
        self.assertEqual(payload["scope"], "vault")
        self.assertEqual(payload["token"], self.web_token)

    def test_claim_without_the_header_is_forbidden(self) -> None:
        """The claim endpoint still requires the loopback-only ``X-Vault-Claim`` marker."""
        status, payload = self.request("POST", "/api/session/claim", body={"scope": "browser"})
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "FORBIDDEN")

    def test_autofill_requires_the_browser_token(self) -> None:
        """Neither an absent token nor the web token opens ``/api/autofill/*``."""
        for token in (None, self.web_token, "deadbeef"):
            with self.subTest(token=token):
                status, payload = self.request("GET", "/api/autofill/status", token=token)
                self.assertEqual(status, 401)
                self.assertEqual(payload["error"]["code"], "UNAUTHORIZED")

    def test_browser_token_cannot_call_the_web_api(self) -> None:
        """The browser token is refused everywhere else, including ``/api/call``."""
        status, _ = self.request("GET", "/api/session", token=self.browser_token)
        self.assertEqual(status, 401)
        status, _ = self.request(
            "POST",
            "/api/call",
            token=self.browser_token,
            body={"method": "vault.read_file", "params": {"path": self.path}},
        )
        self.assertEqual(status, 401)

    def test_web_token_is_refused_by_the_browser_role(self) -> None:
        """The generic API cannot reach the browser methods, even with the vault token."""
        status, payload = self.request(
            "POST",
            "/api/call",
            token=self.web_token,
            body={"method": "vault.browser_reveal", "params": {"path": self.path}},
        )
        self.assertEqual(status, 200)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "PERMISSION_DENIED")

    def test_status_match_and_reveal_over_http(self) -> None:
        """The full add-on round trip works and every reveal is logged with source=browser."""
        status, payload = self.request("GET", "/api/autofill/status", token=self.browser_token)
        self.assertEqual(status, 200)
        self.assertTrue(payload["result"]["enabled"])
        self.assertFalse(payload["result"]["locked"])
        self.assertEqual(payload["result"]["index"]["entries"], 1)

        status, payload = self.request(
            "GET", "/api/autofill/status", token=self.web_token
        )
        self.assertEqual(status, 401)

        status, payload = self.request(
            "POST",
            "/api/autofill/match",
            token=self.browser_token,
            body={"host": "accounts.github.com"},
        )
        self.assertEqual(status, 200)
        candidates = payload["result"]["candidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["path"], self.path)
        self.assertNotIn("github-pass-1", json.dumps(candidates, ensure_ascii=False))
        self.assertNotIn('"password"', json.dumps(candidates, ensure_ascii=False))

        status, payload = self.request(
            "POST",
            "/api/autofill/reveal",
            token=self.browser_token,
            body={"path": self.path, "host": "accounts.github.com"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["password"], "github-pass-1")

        rows = [
            row
            for row in self.session.access_log(limit=100)
            if row["tool"] == "vault.browser_reveal"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "browser")
        self.assertEqual(rows[0]["role"], "browser")
        self.assertEqual(rows[0]["outcome"], "allow")
        self.assertEqual(rows[0]["target_path"], self.path)
        self.assertTrue(str(rows[0]["session"]).startswith("brw-"))

    def test_reveal_failures_are_logged_as_deny(self) -> None:
        """A refused reveal writes one deny row and answers 403."""
        status, payload = self.request(
            "POST",
            "/api/autofill/reveal",
            token=self.browser_token,
            body={"path": self.path, "host": "evil.example"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["message"], "host_mismatch")
        rows = [
            row
            for row in self.session.access_log(limit=100)
            if row["tool"] == "vault.browser_reveal"
        ]
        self.assertEqual([row["outcome"] for row in rows], ["deny"])

    def test_locked_vault_answers_423(self) -> None:
        """A locked vault answers 423 with VAULT_LOCKED so the add-on can say why."""
        self.session.lock()
        status, payload = self.request("GET", "/api/autofill/status", token=self.browser_token)
        self.assertEqual(status, 200)
        self.assertTrue(payload["result"]["locked"])
        status, payload = self.request(
            "POST",
            "/api/autofill/match",
            token=self.browser_token,
            body={"host": "github.com"},
        )
        self.assertEqual(status, 423)
        self.assertEqual(payload["error"]["code"], "VAULT_LOCKED")

    def test_save_check_and_save_over_http(self) -> None:
        """The whole save round trip works over the bridge and lands in the credential folder."""
        status, payload = self.request(
            "POST",
            "/api/autofill/save-check",
            token=self.browser_token,
            body={
                "host": "github.com",
                "username": "max@example.com",
                "password": "github-pass-1",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["state"], "same")

        status, payload = self.request(
            "POST",
            "/api/autofill/save-check",
            token=self.browser_token,
            body={
                "host": "github.com",
                "username": "max@example.com",
                "password": "a-new-one",
            },
        )
        self.assertEqual(payload["result"]["state"], "changed")
        self.assertEqual(payload["result"]["path"], self.path)
        self.assertNotIn('"password"', json.dumps(payload["result"], ensure_ascii=False))

        status, payload = self.request(
            "POST",
            "/api/autofill/save",
            token=self.browser_token,
            body={
                "host": "github.com",
                "username": "max@example.com",
                "password": "a-new-one",
                "path": self.path,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["state"], "updated")
        self.assertTrue(payload["result"]["saved"])
        stored = self.session.read_file(self.path, source="ui").decode("utf-8")
        self.assertIn("گذرواژه: a-new-one", stored)

        status, payload = self.request(
            "POST",
            "/api/autofill/save",
            token=self.browser_token,
            body={
                "host": "fresh.example",
                "username": "someone@fresh.example",
                "password": "pw",
                "title": "Fresh",
                "unknown_field": "ignored",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["state"], "created")
        self.assertEqual(
            payload["result"]["path"],
            f"/{CREDENTIAL_ROOT}/{BROWSER_CATEGORY}/fresh.example/fresh.example.md",
        )
        rows = [
            row
            for row in self.session.access_log(limit=100)
            if row["tool"].startswith("vault.browser_save")
        ]
        self.assertEqual(len(rows), 4)                 # two checks, two saves
        self.assertTrue(all(row["source"] == "browser" for row in rows))
        self.assertTrue(all(row["outcome"] == "allow" for row in rows))

    def test_the_web_token_cannot_save(self) -> None:
        """Saving needs the browser token: the vault's own token is refused on the same route."""
        status, payload = self.request(
            "POST",
            "/api/autofill/save",
            token=self.web_token,
            body={"host": "github.com", "username": "max@example.com", "password": "x"},
        )
        self.assertEqual(status, 401)
        self.assertNotIn(
            "گذرواژه: x", self.session.read_file(self.path, source="ui").decode("utf-8")
        )

    def test_an_oversized_or_broken_save_payload_is_a_bad_request(self) -> None:
        """A page cannot push an unbounded value (or a non-string) into the vault."""
        for body in (
            {"host": "github.com", "username": "max@example.com", "password": "x" * 900},
            {"host": "github.com", "username": "m" * 900, "password": "x"},
            {"host": "github.com", "username": "max@example.com"},
            {"username": "max@example.com", "password": "x"},
            {"host": "github.com", "username": "max@example.com", "password": "one\ntwo"},
        ):
            with self.subTest(body={key: str(value)[:20] for key, value in body.items()}):
                status, payload = self.request(
                    "POST", "/api/autofill/save", token=self.browser_token, body=body
                )
                self.assertEqual(status, 400)
                self.assertEqual(payload["error"]["code"], "BAD_REQUEST")
        rows = [
            row
            for row in self.session.access_log(limit=100)
            if row["tool"] == "vault.browser_save"
        ]
        self.assertEqual([row["outcome"] for row in rows], ["error"] * 5)


class SaveLoopbackTest(unittest.TestCase):
    """A save has to come from this machine, even for a client holding the browser token.

    The other autofill calls are fine from anywhere the listener is reachable (they only read, and
    every one is audited); saving writes, so ``web/server.py`` refuses it off loopback.
    """

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.service = Service(self.session)
        # Bound beyond loopback on purpose: this is the configuration the guard exists for.
        self.server = WebServer(
            self.service, host="0.0.0.0", port=0, runtime_dir=self.session._runtime, keepalive=1.0
        )
        self.server.start()
        self.browser_token = self.server.browser.token

    def tearDown(self) -> None:
        self.server.stop()
        self.session.close()

    @staticmethod
    def lan_address() -> str:
        """Return a non-loopback address of this machine (``""`` when there is none)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError:  # pragma: no cover - no IPv4 at all
            return ""
        try:
            # Nothing is sent: a UDP connect only asks the routing table which source to use.
            sock.connect(("192.0.2.1", 9))
            address = str(sock.getsockname()[0])
        except OSError:
            return ""
        finally:
            sock.close()
        return "" if not address or address.startswith("127.") else address

    def test_a_remote_client_cannot_save_but_may_still_read(self) -> None:
        """403 on the save route, 200 on the read routes — from the same non-loopback client."""
        address = self.lan_address()
        if not address:
            self.skipTest("this machine has no non-loopback IPv4 address to connect from")
        connection = http.client.HTTPConnection(address, self.server.port, timeout=5.0)
        try:
            body = json.dumps(
                {"host": "github.com", "username": "a", "password": "pw"}
            ).encode("utf-8")
            connection.request(
                "POST",
                "/api/autofill/save",
                body=body,
                headers={"X-Vault-Token": self.browser_token, "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            payload = json.loads(response.read().decode("utf-8") or "{}")
            self.assertEqual(response.status, 403)
            self.assertEqual(payload["error"]["message"], "loopback_only")
            connection.close()
            connection = http.client.HTTPConnection(address, self.server.port, timeout=5.0)
            connection.request(
                "GET", "/api/autofill/status", headers={"X-Vault-Token": self.browser_token}
            )
            response = connection.getresponse()
            payload = json.loads(response.read().decode("utf-8") or "{}")
            self.assertEqual(response.status, 200)
            self.assertTrue(payload["result"]["enabled"])
        finally:
            connection.close()
        denied = [
            row
            for row in self.session.access_log(limit=50)
            if row["tool"] == "/api/autofill/save" and row["outcome"] == "deny"
        ]
        self.assertTrue(denied, "the refusal must be in the access log")


class WriterDriftTest(unittest.TestCase):
    """The field labels this module parses must be the ones the importer writes."""

    def test_labels_match_the_importer(self) -> None:
        """``apply.py``'s ``build_body`` writes the labels ``credentials.py`` looks for."""
        source = IMPORTER.read_text(encoding="utf-8")
        for label in ("نام کاربری", "گذرواژه", "آدرس", "سایت", "دسته", "کد یکبارمصرف"):
            with self.subTest(label=label):
                self.assertIn(label, source, f"{label} is no longer written by the importer")
        for label in ("نام کاربری", "گذرواژه", "آدرس"):
            with self.subTest(label=label):
                self.assertIn(
                    label,
                    creds.USERNAME_LABELS + creds.PASSWORD_LABELS + creds.URL_LABELS,
                    f"{label} is no longer parsed by credentials.py",
                )

    def test_reveal_labels_are_the_parsed_ones(self) -> None:
        """The OTP label written by the importer is recognised by the parser."""
        parsed = creds.parse_body(GITHUB_BODY)
        self.assertTrue(re.search("کد یکبارمصرف", GITHUB_BODY))
        self.assertTrue(parsed["has_otp"])


if __name__ == "__main__":
    unittest.main()
