"""Tests for the web UI (SPEC/07 §6).

Black-box tests against a real :class:`~vault.web.server.WebServer` on a scratch vault
and an ephemeral port, driven with ``http.client``. No browser is needed.
"""

from __future__ import annotations

import http.client
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

from support import DEFAULT_PASSWORD, tmp_vault
from vault.api.service import Service
from vault.core import semantics
from vault.web.auth import LoginThrottle
from vault.web.server import WebServer

REPO_ROOT = Path(__file__).resolve().parents[1]
WEBUI_DIR = REPO_ROOT / "src" / "vault" / "webui"
I18N_DIR = REPO_ROOT / "i18n"


class _WebTestCase(unittest.TestCase):
    """Shared fixture: a scratch vault, a server on port 0 and an HTTP helper."""

    def setUp(self) -> None:
        self.session = tmp_vault()
        self.session.set_semantic_provider(semantics.StubProvider())
        self.service = Service(self.session)
        self.sleeps: list[float] = []
        self.throttle = LoginThrottle(sleep=self.sleeps.append)
        self.server = WebServer(
            self.service,
            host="127.0.0.1",
            port=0,
            runtime_dir=self.session._runtime,
            throttle=self.throttle,
            keepalive=1.0,
        )
        self.server.start()
        self.port = self.server.port
        self.token = self.server.token

    def tearDown(self) -> None:
        self.server.stop()
        self.session.close()

    # ------------------------------------------------------------------ helpers
    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None | bool = True,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
    ) -> tuple[int, dict[str, str], bytes]:
        """Perform one HTTP request and return ``(status, headers, body)``."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        send_headers = dict(headers or {})
        if token is True:
            send_headers["X-Vault-Token"] = self.token
        elif isinstance(token, str):
            send_headers["X-Vault-Token"] = token
        payload = None
        if body is not None:
            send_headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")
        try:
            conn.request(method, path, body=payload, headers=send_headers)
            response = conn.getresponse()
            data = response.read()
            return response.status, dict(response.getheaders()), data
        finally:
            conn.close()

    def json_request(self, method: str, path: str, **kwargs) -> tuple[int, dict]:
        """Perform a request and decode the JSON body."""
        status, _headers, body = self.request(method, path, **kwargs)
        try:
            return status, json.loads(body.decode("utf-8"))
        except ValueError:
            self.fail(f"{method} {path} did not return JSON: {body[:200]!r}")

    def call(self, method: str, params: dict | None = None, **kwargs) -> tuple[int, dict]:
        """POST one ``/api/call`` and decode the envelope."""
        return self.json_request(
            "POST", "/api/call", body={"method": method, "params": params or {}}, **kwargs
        )

    def unlock(self) -> None:
        """Unlock the scratch vault through the session endpoint."""
        status, data = self.json_request(
            "POST", "/api/session/unlock", body={"password": DEFAULT_PASSWORD}
        )
        self.assertEqual(status, 200, data)
        self.assertTrue(data.get("ok"))


class StaticTest(_WebTestCase):
    """Static assets are served without a token."""

    def test_index(self) -> None:
        """GET / returns the SPA HTML."""
        status, headers, body = self.request("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"<html", body.lower())

    def test_app_js(self) -> None:
        """GET /static/app.js returns JavaScript."""
        status, headers, _body = self.request("GET", "/static/app.js", token=False)
        self.assertEqual(status, 200)
        self.assertIn("javascript", headers["Content-Type"])

    def test_styles_css(self) -> None:
        """GET /static/styles.css returns CSS."""
        status, headers, _body = self.request("GET", "/static/styles.css", token=False)
        self.assertEqual(status, 200)
        self.assertIn("text/css", headers["Content-Type"])

    def test_unknown_static(self) -> None:
        """An unknown static path is a 404."""
        status, _headers, _body = self.request("GET", "/static/nope.js", token=False)
        self.assertEqual(status, 404)


class AuthTest(_WebTestCase):
    """The token contract (SPEC/07 §2)."""

    def test_no_token(self) -> None:
        """An API call without a token is 401."""
        status, _headers, body = self.request("GET", "/api/session", token=False)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"]["code"], "UNAUTHORIZED")

    def test_wrong_token(self) -> None:
        """A wrong token is 401 and leaves a deny row with source web."""
        status, _headers, body = self.request("GET", "/api/session", token="0" * 64)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"]["code"], "UNAUTHORIZED")
        rows = self.session.access_log(limit=20, source="web")
        self.assertTrue(any(row["outcome"] == "deny" for row in rows))

    def test_query_token_sets_cookie_and_redirects(self) -> None:
        """GET /?token=… sets the cookie and 302-redirects to /."""
        status, headers, _body = self.request(
            "GET", f"/?token={self.token}", token=False
        )
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Location"), "/")
        self.assertTrue(headers.get("Set-Cookie", "").startswith("vault_token="))
        self.assertIn("HttpOnly", headers.get("Set-Cookie", ""))

    def test_query_token_wrong_is_401(self) -> None:
        """GET /?token=<wrong> does not set a cookie."""
        status, headers, _body = self.request("GET", "/?token=bad", token=False)
        self.assertEqual(status, 401)
        self.assertNotIn("Set-Cookie", headers)

    def test_login_sets_cookie(self) -> None:
        """POST /api/session/login with the right token succeeds."""
        status, headers, body = self.request(
            "POST", "/api/session/login", token=False, body={"token": self.token}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})
        self.assertTrue(headers.get("Set-Cookie", "").startswith("vault_token="))

    def test_login_wrong_token(self) -> None:
        """POST /api/session/login with a wrong token is 401."""
        status, _headers, body = self.request(
            "POST", "/api/session/login", token=False, body={"token": "nope"}
        )
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"]["code"], "UNAUTHORIZED")

    def test_cookie_alone_does_not_authorise(self) -> None:
        """The cookie alone must never authorise an API call (CSRF defence)."""
        status, _headers, body = self.request(
            "GET",
            "/api/session",
            token=False,
            headers={"Cookie": f"vault_token={self.token}"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"]["code"], "UNAUTHORIZED")

    def test_api_no_store(self) -> None:
        """Every API response is ``Cache-Control: no-store``."""
        status, headers, _body = self.request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Cache-Control"), "no-store")


class SessionTest(_WebTestCase):
    """The session snapshot and unlock/lock flow."""

    def test_session_locked_hides_counts(self) -> None:
        """While locked the snapshot reports locked and no counts."""
        self.json_request("POST", "/api/session/lock")
        status, data = self.json_request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertTrue(data["locked"])
        self.assertIsNone(data["counts"])
        self.assertIn("version", data)
        self.assertIn("ui", data)

    def test_unlock_wrong_password_and_throttle(self) -> None:
        """A wrong password is 401 bad_password, logs a deny and throttles at 5."""
        for attempt in range(5):
            status, data = self.json_request(
                "POST", "/api/session/unlock", body={"password": "wrong"}
            )
            self.assertEqual(status, 401)
            self.assertEqual(data["error"]["code"], "UNAUTHORIZED")
            self.assertEqual(data["error"]["details"]["reason"], "bad_password")
            if attempt < 4:
                self.assertEqual(self.sleeps, [])
        self.assertTrue(self.throttle.is_throttled("127.0.0.1"))
        self.assertEqual(self.sleeps, [5.0])
        rows = self.session.access_log(limit=50, source="web")
        denied = [
            row
            for row in rows
            if row["tool"] == "vault.unlock" and row["outcome"] == "deny"
        ]
        self.assertEqual(len(denied), 5)
        self.assertTrue(all(row["code"] == "UNAUTHORIZED" for row in denied))
        # The password must never appear in the access log.
        for row in rows:
            self.assertNotIn("wrong", json.dumps(row, ensure_ascii=False))

    def test_unlock_success_resets_throttle(self) -> None:
        """The right password unlocks and clears the failure counter."""
        for _ in range(5):
            self.json_request(
                "POST", "/api/session/unlock", body={"password": "wrong"}
            )
        self.unlock()
        self.assertFalse(self.throttle.is_throttled("127.0.0.1"))
        status, data = self.json_request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertFalse(data["locked"])
        self.assertIsNotNone(data["counts"])

    def test_lock(self) -> None:
        """POST /api/session/lock locks the vault."""
        self.unlock()
        status, data = self.json_request("POST", "/api/session/lock")
        self.assertEqual(status, 200)
        self.assertTrue(data["locked"])
        status, session = self.json_request("GET", "/api/session")
        self.assertTrue(session["locked"])


class CallTest(_WebTestCase):
    """The ``/api/call`` round-trip and its allow-list."""

    def setUp(self) -> None:
        super().setUp()
        self.unlock()

    def test_round_trip(self) -> None:
        """The documented methods work through /api/call with role ui."""
        status, data = self.call(
            "vault.write_file", {"path": "/notes/a.md", "content": "alpha beta"}
        )
        self.assertEqual(status, 200, data)
        self.assertTrue(data["result"]["created"])

        status, data = self.call("vault.list_folder", {"path": "/"})
        names = [entry["name"] for entry in data["result"]["entries"]]
        self.assertIn("notes", names)

        status, data = self.call("vault.read_file", {"path": "/notes/a.md"})
        self.assertEqual(data["result"]["content"], "alpha beta")

        status, data = self.call(
            "vault.write_lines",
            {"path": "/notes/a.md", "text": "gamma", "mode": "append"},
        )
        self.assertIn("lines", data["result"])

        status, data = self.call("vault.mkdir", {"path": "/notes/sub"})
        self.assertTrue(data["result"]["created"])

        status, data = self.call(
            "vault.file_ops",
            {"op": "copy", "src": "/notes/a.md", "dst": "/notes/copy.md"},
        )
        self.assertEqual(data["result"]["op"], "copy")

        status, data = self.call(
            "vault.set_tags", {"path": "/notes/a.md", "tags": ["x", "y"]}
        )
        self.assertEqual(data["result"]["tags"], ["x", "y"])

        status, data = self.call(
            "vault.set_folder_note", {"path": "/notes", "text": "a note"}
        )
        self.assertTrue(data["result"]["updated"])
        status, data = self.call("vault.folder_note", {"path": "/notes"})
        self.assertEqual(data["result"]["note"], "a note")

        status, data = self.call(
            "vault.search_filenames", {"query": "a.md"}
        )
        self.assertGreaterEqual(data["result"]["count"], 1)
        status, data = self.call("vault.search_text", {"query": "alpha"})
        self.assertGreaterEqual(data["result"]["count"], 1)
        self.call("vault.semantic_index", {})
        status, data = self.call("vault.search_semantic", {"query": "alpha"})
        self.assertGreaterEqual(data["result"]["count"], 1)

        status, data = self.call("vault.stats", {})
        self.assertIn("by_level", data["result"])
        status, data = self.call("vault.access_log", {"limit": 5})
        self.assertIn("entries", data["result"])

    def test_sensitivity_raise_and_downgrade(self) -> None:
        """The UI may raise and lower levels through /api/call."""
        self.call("vault.write_file", {"path": "/notes/s.md", "content": "body"})
        status, data = self.call(
            "vault.set_sensitivity", {"path": "/notes/s.md", "level": "secret"}
        )
        self.assertEqual(data["result"]["to"], "secret")
        status, data = self.call(
            "vault.set_sensitivity", {"path": "/notes/s.md", "level": "normal"}
        )
        self.assertEqual(data["result"]["to"], "normal")

    def test_forbidden_methods(self) -> None:
        """unlock/lock are not reachable through /api/call."""
        for method in ("vault.unlock", "vault.lock"):
            with self.subTest(method=method):
                status, data = self.call(method, {"path": "/notes/a.md"})
                self.assertEqual(status, 400)
                self.assertEqual(data["error"]["code"], "BAD_REQUEST")

    def test_unknown_method(self) -> None:
        """An unknown method is a 400 BAD_REQUEST."""
        status, data = self.call("vault.nope", {})
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "BAD_REQUEST")

    def test_traversal_is_rejected(self) -> None:
        """A traversal path is rejected with INVALID_PATH and reads nothing."""
        status, data = self.call(
            "vault.list_folder", {"path": "../../etc/passwd"}
        )
        self.assertEqual(data["error"]["code"], "INVALID_PATH")

    def test_locked_content_denied_metadata_allowed(self) -> None:
        """After locking, content calls fail with VAULT_LOCKED but metadata works."""
        self.json_request("POST", "/api/session/lock")
        status, data = self.call("vault.read_file", {"path": "/notes/a.md"})
        self.assertEqual(data["error"]["code"], "VAULT_LOCKED")
        status, data = self.call("vault.search_filenames", {"query": "a"})
        self.assertTrue(data["ok"])
        status, data = self.call("vault.list_folder", {"path": "/"})
        self.assertTrue(data["ok"])


class BlobTest(_WebTestCase):
    """``/api/blob`` returns raw bytes for normal files only."""

    def setUp(self) -> None:
        super().setUp()
        self.unlock()
        self.call("vault.write_file", {"path": "/notes/a.txt", "content": "hello"})
        self.call(
            "vault.write_file",
            {"path": "/notes/s.txt", "content": "hidden", "sensitivity": "secret"},
        )

    def test_normal_blob(self) -> None:
        """A normal file's bytes come back verbatim."""
        status, headers, body = self.request(
            "GET", "/api/blob?path=/notes/a.txt"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello")
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_secret_blob_forbidden(self) -> None:
        """A secret file is 403 (never returned to an HTML-rendering path)."""
        status, _headers, body = self.request(
            "GET", "/api/blob?path=/notes/s.txt"
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"]["code"], "PERMISSION_DENIED")

    def test_blob_traversal(self) -> None:
        """A traversal path is rejected."""
        status, _headers, body = self.request(
            "GET", "/api/blob?path=../../etc/passwd"
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"]["code"], "INVALID_PATH")


class ExportTest(_WebTestCase):
    """The access-log CSV export."""

    def test_export_csv(self) -> None:
        """GET /api/export/access-log.csv is text/csv with a header row."""
        status, headers, body = self.request("GET", "/api/export/access-log.csv")
        self.assertEqual(status, 200)
        self.assertIn("text/csv", headers["Content-Type"])
        first_line = body.split(b"\n", 1)[0].decode("utf-8")
        self.assertTrue(first_line.startswith("id,ts,source,role,tool"))


class EventsTest(_WebTestCase):
    """The SSE stream."""

    def test_first_event_within_two_seconds(self) -> None:
        """The first SSE line arrives quickly and is valid JSON with an event."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2.0)
        try:
            conn.request("GET", "/api/events", headers={"X-Vault-Token": self.token})
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn("text/event-stream", response.getheader("Content-Type", ""))
            line = response.fp.readline()
            self.assertTrue(line.startswith(b"data: "), line)
            payload = json.loads(line[len(b"data: "):].decode("utf-8"))
            self.assertIn("event", payload)
        finally:
            conn.close()


class I18nTest(_WebTestCase):
    """The catalogue endpoint and the SPA's ``data-i18n`` attributes."""

    @staticmethod
    def _catalogue(lang: str) -> dict:
        return json.loads((I18N_DIR / f"{lang}.json").read_text(encoding="utf-8"))

    def test_i18n_endpoint_matches_catalogue(self) -> None:
        """GET /api/i18n?lang=fa returns exactly the file's key set."""
        status, data = self.json_request("GET", "/api/i18n?lang=fa")
        self.assertEqual(status, 200)
        self.assertEqual(set(data), set(self._catalogue("fa")))

    def test_i18n_en(self) -> None:
        """GET /api/i18n?lang=en returns exactly the file's key set."""
        status, data = self.json_request("GET", "/api/i18n?lang=en")
        self.assertEqual(status, 200)
        self.assertEqual(set(data), set(self._catalogue("en")))

    def test_data_i18n_keys_exist(self) -> None:
        """Every data-i18n attribute in index.html exists in both catalogues."""
        html = (WEBUI_DIR / "index.html").read_text(encoding="utf-8")
        keys = set(
            re.findall(r'data-i18n(?:-placeholder|-title)?="([^"]+)"', html)
        )
        self.assertTrue(keys)
        for lang in ("fa", "en"):
            catalogue = self._catalogue(lang)
            missing = sorted(key for key in keys if key not in catalogue)
            self.assertEqual(missing, [], f"{lang} is missing {missing}")

    def test_no_literal_ui_strings_in_js(self) -> None:
        """The SPA has no http(s) literal and uses the catalogue for UI text."""
        js = (WEBUI_DIR / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("http://", js)
        self.assertNotIn("https://", js)
        self.assertIn("/api/i18n", js)


class SecretApprovalTest(_WebTestCase):
    """The web secret gate (SPEC/09 §5)."""

    def setUp(self) -> None:
        super().setUp()
        self.unlock()
        self.call("vault.write_file", {"path": "/notes/plain.md", "content": "plain body"})
        self.call(
            "vault.write_file",
            {"path": "/secrets/hidden.md", "content": "secret body", "sensitivity": "secret"},
        )

    def test_read_file_secret_requires_approval(self) -> None:
        """A plain read of a secret file is gated, then read_secret succeeds."""
        status, data = self.call("vault.read_file", {"path": "/secrets/hidden.md"})
        self.assertEqual(status, 200)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"]["code"], "PERMISSION_DENIED")
        self.assertTrue(data["error"]["details"]["requires_approval"])
        self.assertNotIn("secret body", json.dumps(data))

        status, data = self.call("vault.read_secret", {"path": "/secrets/hidden.md"})
        self.assertTrue(data["ok"])
        self.assertEqual(data["result"]["content"], "secret body")

        rows = self.session.access_log(limit=100)
        pairs = {(row["tool"], row["outcome"]) for row in rows}
        self.assertIn(("vault.read_file", "deny"), pairs)
        self.assertIn(("vault.read_secret", "allow"), pairs)

    def test_normal_read_is_not_gated(self) -> None:
        """A normal file still reads through vault.read_file."""
        status, data = self.call("vault.read_file", {"path": "/notes/plain.md"})
        self.assertTrue(data["ok"])
        self.assertEqual(data["result"]["content"], "plain body")
        self.assertIn("mtime", data["result"])
        self.assertIn("tags", data["result"])


class ActivitySseTest(_WebTestCase):
    """Activity events reach the SSE stream (SPEC/09 §9)."""

    def test_activity_event_within_two_seconds(self) -> None:
        """A read triggers an ``activity`` frame on an open stream."""
        self.unlock()
        self.call("vault.write_file", {"path": "/notes/a.md", "content": "alpha"})
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2.0)
        try:
            conn.request("GET", "/api/events", headers={"X-Vault-Token": self.token})
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.call("vault.read_file", {"path": "/notes/a.md"})
            found = None
            for _ in range(60):
                line = response.fp.readline()
                if not line:
                    break
                if not line.startswith(b"data: "):
                    continue
                payload = json.loads(line[len(b"data: "):].decode("utf-8"))
                if payload.get("event") == "activity":
                    found = payload
                    break
            self.assertIsNotNone(found, "no activity event on the stream")
            self.assertEqual(found.get("source"), "web")
            self.assertNotIn("content", found)
        finally:
            conn.close()


class ParityTest(_WebTestCase):
    """The Joplin-mirror parity surface (SPEC/07b)."""

    def setUp(self) -> None:
        super().setUp()
        self.unlock()
        self.call("vault.write_file", {"path": "/notes/alpha-title.md", "content": "nothing here"})
        self.call("vault.write_file", {"path": "/notes/body.md", "content": "unique-body-token appears"})
        self.call("vault.write_file", {"path": "/notes/tagged.md", "content": "tagged note"})
        self.call("vault.set_tags", {"path": "/notes/tagged.md", "tags": ["mytag"]})
        self.call("vault.mkdir", {"path": "/notes/sub"})
        self.call("vault.write_file", {"path": "/notes/sub/deep.md", "content": "deep"})
        self.call(
            "vault.write_file",
            {"path": "/secrets/hidden.md", "content": "secretbodytoken", "sensitivity": "secret"},
        )
        self.call("vault.set_tags", {"path": "/secrets/hidden.md", "tags": ["mytag"]})

    def test_index_tree_and_tags(self) -> None:
        """GET /api/index returns the tree with counts and tags with counts."""
        status, data = self.json_request("GET", "/api/index")
        self.assertEqual(status, 200)
        roots = {node["name"]: node for node in data["tree"]}
        self.assertIn("notes", roots)
        self.assertTrue(roots["notes"]["is_dir"])
        self.assertGreaterEqual(roots["notes"]["note_count"], 2)
        sub = [child for child in roots["notes"]["children"] if child["name"] == "sub"]
        self.assertTrue(sub and sub[0]["note_count"] >= 1)
        tags = {tag["name"]: tag["count"] for tag in data["tags"]}
        self.assertEqual(tags.get("mytag"), 2)
        self.assertIn("files", data["counts"])

    def test_search_matches_name_tag_body(self) -> None:
        """The parity search finds name, tag and body matches with snippets."""
        status, data = self.json_request("GET", "/api/search?q=alpha-title")
        self.assertEqual(status, 200)
        hit = next(r for r in data["results"] if r["path"] == "/notes/alpha-title.md")
        self.assertEqual(hit["match"], "name")

        status, data = self.json_request("GET", "/api/search?q=unique-body-token")
        hit = next(r for r in data["results"] if r["path"] == "/notes/body.md")
        self.assertEqual(hit["match"], "body")
        self.assertIn("unique-body-token", hit["snippet"])
        self.assertLessEqual(len(hit["snippet"]), 220)

        status, data = self.json_request("GET", "/api/search?tag=mytag")
        paths = {r["path"] for r in data["results"]}
        self.assertIn("/notes/tagged.md", paths)

        status, data = self.json_request("GET", "/api/search?q=tag%3Amytag")
        self.assertEqual(data["tag"], "mytag")
        paths = {r["path"] for r in data["results"]}
        self.assertIn("/secrets/hidden.md", paths)

    def test_read_payload_carries_both_dates(self) -> None:
        """The note view needs the updated and created timestamps."""
        status, data = self.call("vault.read_file", {"path": "/notes/alpha-title.md"})
        self.assertTrue(data["ok"])
        self.assertIn("mtime", data["result"])
        self.assertIn("created", data["result"])

    def test_search_never_leaks_secret_body(self) -> None:
        """A secret file may match by name/tag but never by body."""
        status, data = self.json_request("GET", "/api/search?q=secretbodytoken")
        self.assertFalse(
            any(r["path"] == "/secrets/hidden.md" and r["match"] == "body" for r in data["results"])
        )
        status, data = self.json_request("GET", "/api/search?q=hidden")
        hit = next(r for r in data["results"] if r["path"] == "/secrets/hidden.md")
        self.assertEqual(hit["match"], "name")

    def test_raw_normal_secret_and_traversal(self) -> None:
        """GET /api/raw is text/plain for normal files, 403 for secrets."""
        status, headers, body = self.request("GET", "/api/raw?path=/notes/body.md")
        self.assertEqual(status, 200)
        self.assertIn("text/plain", headers["Content-Type"])
        self.assertIn(b"unique-body-token", body)

        for path in ("/notes/tagged.md", "/secrets/hidden.md"):
            if path == "/notes/tagged.md":
                self.call("vault.set_sensitivity", {"path": path, "level": "secretfile"})
            status, _headers, body = self.request("GET", f"/api/raw?path={path}")
            self.assertEqual(status, 403, path)
            self.assertEqual(json.loads(body)["error"]["code"], "PERMISSION_DENIED")

        status, _headers, body = self.request("GET", "/api/raw?path=../../etc/passwd")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"]["code"], "INVALID_PATH")


class ParitySpaTest(unittest.TestCase):
    """Static assertions over the SPA for the parity features (SPEC/07b §7)."""

    def test_spa_markers(self) -> None:
        """The SPA contains the toolbar actions, counts, dir=auto and no network."""
        js = (WEBUI_DIR / "app.js").read_text(encoding="utf-8")
        html = (WEBUI_DIR / "index.html").read_text(encoding="utf-8")
        for action in ("bold", "italic", "strike", "code", "heading", "quote",
                       "ul", "ol", "link", "image", "hr"):
            self.assertIn(f'"{action}"', js, f"toolbar action {action} missing")
        self.assertIn("note_count", js)
        self.assertIn("count", js)
        self.assertIn("subtreeNoteCounts", js)
        self.assertIn('dir="auto"', html)
        self.assertIn('setAttribute("dir"', js)
        for endpoint in ("/api/index", "/api/search", "/api/raw", "/api/blob"):
            self.assertIn(endpoint, js)
        self.assertNotIn("http://", js)
        self.assertNotIn("https://", js)
        self.assertNotIn("localStorage", js)


class NetworkFreeTest(unittest.TestCase):
    """The SPA must never reference the network (SPEC/07 §5)."""

    def test_webui_has_no_external_urls(self) -> None:
        """No ``http://`` or ``https://`` literal anywhere under webui/."""
        for path in sorted(WEBUI_DIR.glob("*")):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("http://", text, str(path))
            self.assertNotIn("https://", text, str(path))


class HostGuardTest(unittest.TestCase):
    """A non-loopback bind requires ``--allow-lan`` (SPEC/07 §1)."""

    def test_non_loopback_without_allow_lan_exits_nonzero(self) -> None:
        """``--host 0.0.0.0`` without ``--allow-lan`` exits non-zero with a message."""
        import os

        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT / "src")
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "vault.web",
                "--host",
                "0.0.0.0",
                "--port",
                "0",
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("allow-lan", proc.stderr)
        self.assertNotIn("Access token", proc.stdout)


if __name__ == "__main__":  # pragma: no cover - manual run
    unittest.main()
