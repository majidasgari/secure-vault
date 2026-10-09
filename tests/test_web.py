"""Tests for the web UI (SPEC/07 §6).

Black-box tests against a real :class:`~vault.web.server.WebServer` on a scratch vault
and an ephemeral port, driven with ``http.client``. No browser is needed.
"""

from __future__ import annotations

import http.client
import json
import re
import shutil
import subprocess
import sys
import tempfile
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

        status, data = self.call("vault.set_emoji", {"path": "/notes", "emoji": "🗂️"})
        self.assertEqual(data["result"]["emoji"], "🗂️")
        self.assertEqual(data["result"]["name"], "notes")
        status, data = self.call("vault.emoji_palette", {})
        self.assertTrue(data["result"]["groups"])
        status, data = self.call("vault.set_emoji", {"path": "/notes", "emoji": ""})
        self.assertIsNone(data["result"]["emoji"])

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
        """GET /api/i18n?lang=fa returns the file's key set plus the private `_languages` hint."""
        status, data = self.json_request("GET", "/api/i18n?lang=fa")
        self.assertEqual(status, 200)
        self.assertEqual({k for k in data if not k.startswith("_")}, set(self._catalogue("fa")))
        self.assertIn("_languages", data)

    def test_i18n_en(self) -> None:
        """GET /api/i18n?lang=en returns the file's key set plus the private `_languages` hint."""
        status, data = self.json_request("GET", "/api/i18n?lang=en")
        self.assertEqual(status, 200)
        self.assertEqual({k for k in data if not k.startswith("_")}, set(self._catalogue("en")))
        self.assertIn("_languages", data)

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
        # The log records the tool name the call arrived under ("read_file" for the agent role).
        self.assertIn(("read_file", "deny"), pairs)
        self.assertIn(("vault.read_secret", "allow"), pairs)

    def test_normal_read_is_not_gated(self) -> None:
        """A normal file still reads through vault.read_file."""
        status, data = self.call("vault.read_file", {"path": "/notes/plain.md"})
        self.assertTrue(data["ok"])
        self.assertEqual(data["result"]["content"], "plain body")
        self.assertIn("mtime", data["result"])
        self.assertIn("tags", data["result"])


class FolderDeleteTest(_WebTestCase):
    """Deleting a folder through the web API, recursively (the web UI's 🗑 row action)."""

    def _tree(self) -> None:
        """A folder tree whose leaves include a secretfile."""
        self.unlock()
        for folder in ("/tree", "/tree/sub", "/tree/sub/deep"):
            self.call("vault.mkdir", {"path": folder})
        self.call("vault.write_file", {"path": "/tree/plain.md", "content": "plain"})
        self.call("vault.write_file", {"path": "/tree/sub/note.md", "content": "note"})
        self.call(
            "vault.write_file",
            {"path": "/tree/sub/deep/hidden.md", "content": "hidden", "sensitivity": "secretfile"},
        )

    def test_recursive_delete_removes_the_whole_subtree(self) -> None:
        """``recursive`` takes the folder, its folders and its secretfiles out in one call."""
        self._tree()
        status, data = self.call(
            "vault.file_ops", {"op": "delete", "src": "/tree", "recursive": True}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["result"]["affected"], 6)
        status, data = self.call("vault.list_folder", {"path": "/"})
        self.assertNotIn("tree", [entry["name"] for entry in data["result"]["entries"]])
        status, data = self.call("vault.read_file", {"path": "/tree/sub/deep/hidden.md"})
        self.assertEqual(data["error"]["code"], "NOT_FOUND")

    def test_non_recursive_delete_refuses_a_folder_with_children(self) -> None:
        """Without ``recursive`` a folder that still has children is refused, not emptied."""
        self._tree()
        status, data = self.call("vault.file_ops", {"op": "delete", "src": "/tree/sub"})
        self.assertEqual(data["error"]["code"], "BAD_REQUEST")
        status, data = self.call("vault.list_folder", {"path": "/tree/sub"})
        self.assertEqual(
            sorted(entry["name"] for entry in data["result"]["entries"]), ["deep", "note.md"]
        )

    def test_root_can_never_be_deleted(self) -> None:
        """``/`` itself is not deletable, recursive or not, and nothing under it is touched."""
        self._tree()
        for payload in (
            {"op": "delete", "src": "/", "recursive": True},
            {"op": "delete", "src": "/", "recursive": False},
        ):
            status, data = self.call("vault.file_ops", payload)
            self.assertFalse(data["ok"], payload)
            self.assertIn(data["error"]["code"], ("BAD_REQUEST", "NOT_FOUND"), payload)
        status, data = self.call("vault.list_folder", {"path": "/"})
        names = sorted(entry["name"] for entry in data["result"]["entries"])
        self.assertIn("tree", names)


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
        for endpoint in ("/api/index", "/api/call", "/api/raw", "/api/blob"):
            self.assertIn(endpoint, js)
        self.assertNotIn("http://", js)
        self.assertNotIn("https://", js)
        self.assertNotIn("localStorage", js)


class FolderDeleteSpaTest(unittest.TestCase):
    """Every folder listing carries the folder delete action (web UI)."""

    def setUp(self) -> None:
        self.js = (WEBUI_DIR / "app.js").read_text(encoding="utf-8")

    def _function(self, name: str) -> str:
        """Return the source of ``function <name>(…​) { … }`` by brace matching."""
        start = self.js.index(f"function {name}(")
        index = self.js.index("{", start)
        depth = 0
        for offset in range(index, len(self.js)):
            if self.js[offset] == "{":
                depth += 1
            elif self.js[offset] == "}":
                depth -= 1
                if depth == 0:
                    return self.js[start : offset + 1]
        raise AssertionError(f"unbalanced braces in {name}")

    def test_folder_tree_rows_have_the_delete_action(self) -> None:
        """A tree row — the only listing of a folder under ``/`` — carries 🗑."""
        body = self._function("buildTreeRow")
        self.assertIn("rowDeleteButton(node)", body)
        self.assertIn("bindRowMenu(li, node)", body)

    def test_notebook_rows_have_the_delete_action(self) -> None:
        """The centre folder list keeps its own 🗑 plus the row menu."""
        body = self._function("renderFolderView")
        self.assertIn("rowDeleteButton(entry)", body)
        self.assertIn("bindRowMenu(li, entry)", body)

    def test_folder_delete_is_labelled_and_recursive(self) -> None:
        """The action and the confirmation both speak about a folder and its contents."""
        self.assertIn('entry.is_dir ? t("menu.delete_folder")', self.js)
        self.assertIn('t("dialog.delete_folder_confirm"', self.js)
        self.assertIn("recursive: isDir", self._function("performDelete"))

    def test_context_menu_offers_the_folder_actions(self) -> None:
        """Right-clicking a folder lists open / rename / delete / copy path — never note-only items."""
        body = self._function("showContextMenu")
        self.assertIn('item(t("menu.delete_folder")', body)
        self.assertLess(body.index("if (entry.is_dir)"), body.index('t("menu.tags")'))


NODE_RENDER = r'''
const fs = require("fs");
const payload = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const src = fs.readFileSync(payload.appjs, "utf8");
const code = src.slice(src.indexOf("  function escapeHtml(text) {"),
                       src.indexOf("  function hydrateImages(root) {"));
const build = new Function("window", "TextEncoder", "Blob", "URL", "navigator",
  code + "\nreturn { renderMarkdown };");
const api = build({}, TextEncoder, Blob,
  { createObjectURL: () => "blob:x", revokeObjectURL: () => {} }, {});
process.stdout.write(JSON.stringify(payload.cases.map((c) => api.renderMarkdown(c, "/note.md"))));
'''


def render_markdown(*sources: str) -> list[str]:
    """Render each markdown source through the real ``renderMarkdown`` in Node.

    Skips the calling test when Node is unavailable; the SPA functions are sliced out of
    ``app.js`` (see the harness note in the ops skill) so no browser is needed.
    """
    node = shutil.which("node")
    if not node:
        raise unittest.SkipTest("node is not installed")
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "render.js"
        payload = Path(tmp) / "payload.json"
        script.write_text(NODE_RENDER, encoding="utf-8")
        payload.write_text(
            json.dumps({"appjs": str(WEBUI_DIR / "app.js"), "cases": list(sources)}),
            encoding="utf-8",
        )
        proc = subprocess.run(
            [node, str(script), str(payload)], capture_output=True, text=True, timeout=60
        )
    if proc.returncode != 0:
        raise AssertionError(f"node failed: {proc.stderr[-800:]}")
    return json.loads(proc.stdout)


class MarkdownCodeBlockTest(unittest.TestCase):
    """Fenced code renders as a code block — the real ``renderMarkdown`` driven in Node.

    ``tools/ui_probe.py`` proves the pixels in a browser; this proves the function itself, so a
    fence that is indented under a list item (the common way to write one) cannot regress into
    literal ``` text again.
    """

    def _render(self, *sources: str) -> list[str]:
        """Render each source through app.js (skipping when node is missing)."""
        return render_markdown(*sources)

    def test_indented_fence_inside_a_list_item(self) -> None:
        """A fence indented under a step loses its ``` lines and its extra indentation."""
        (html,) = self._render(
            "1.  **تنظیم:** فایل را بساز:\n"
            "        ```\n"
            "        /srv/shared_folder   IP_CLIENT(rw,sync)\n"
            "        ```\n"
            "        ادامهٔ متن.\n"
        )
        self.assertNotIn("```", html)
        self.assertIn('<div class="code-block"><pre><code dir="ltr">', html)
        self.assertIn("/srv/shared_folder   IP_CLIENT(rw,sync)", html)
        self.assertIn("</code></pre></div>", html)
        self.assertIn("ادامهٔ متن.", html)

    def test_language_from_the_info_string(self) -> None:
        """```bash becomes a data-lang + language-bash class (the header badge reads it)."""
        (html,) = self._render("    ```bash\n    sudo mount /mnt/x\n    ```\n")
        self.assertIn('<div class="code-block" data-lang="bash">', html)
        self.assertIn('class="language-bash"', html)
        self.assertIn("sudo mount /mnt/x", html)
        self.assertNotIn("    sudo", html)

    def test_tilde_fence_and_unterminated_block(self) -> None:
        """~~~ closes like ``` and a fence left open at the end still closes its markup."""
        tilde, open_end = self._render("~~~python\nprint(1)\n~~~\n", "```\nlast line\n")
        self.assertIn('data-lang="python"', tilde)
        self.assertNotIn("~~~", tilde)
        self.assertTrue(open_end.rstrip().endswith("</code></pre></div>"), open_end[-60:])

    def test_code_content_is_escaped_not_executed(self) -> None:
        """Markup inside a code block stays text."""
        (html,) = self._render("```html\n<script>alert(1)</script>\n```\n")
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>", html)

    def test_block_starts_with_its_first_line(self) -> None:
        """No newline right after <code>: <pre> would paint it as an empty first line."""
        (html,) = self._render("```bash\nsudo mount /mnt/x\nsudo mount -a\n```\n")
        self.assertIn(
            '<pre><code dir="ltr" class="language-bash">sudo mount /mnt/x\nsudo mount -a</code>',
            html,
        )

    def test_inline_code_is_untouched(self) -> None:
        """A single backtick pair is still inline code, not a block."""
        (html,) = self._render("متن با `inline code` ادامه.\n")
        self.assertNotIn("code-block", html)
        self.assertIn('<code dir="ltr">inline code</code>', html)


class MarkdownDirectionTest(unittest.TestCase):
    """Per-block direction: any Persian/Arabic letter makes the block RTL *and* right-aligned.

    Max's rule (Sep 2026): «هر جایی اعم از enum ها یا سلولهای جدول یا شمارهگذاریها حتی یک کاراکتر
    فارسی یا عربی بود کلا هم direction بشه RTL هم alignment بشه right to left». So every block —
    paragraph, heading, list item, table cell, quote — carries its own explicit ``dir`` decided from
    its own text; a block without a single RTL letter is LTR and left-aligned. ``dir="auto"`` cannot
    express this: it follows the *first strong* character (a Latin-first line inside a Persian note
    stayed left-aligned) and it ignores the direction of descendants. The alignment itself comes
    from the stylesheet's ``[dir="rtl"]``/``[dir="ltr"]`` rules; here the markup is asserted.
    """

    def test_persian_list_is_rtl_english_list_is_ltr(self) -> None:
        """Bullets follow the content, and each item carries its own direction."""
        persian, english = render_markdown(
            "- مستنداتش همه استاندارد و تیمزند (TASK_SPEC, AGENTS.md)\n- نحوهی حرف زدنش\n",
            "- file entries and English first item\n- attachments\n",
        )
        self.assertIn('<ul dir="rtl">', persian)
        self.assertIn('<li dir="rtl">مستنداتش', persian)
        self.assertIn('<ul dir="ltr">', english)
        self.assertIn('<li dir="ltr">file entries', english)
        self.assertNotIn('<ul dir="rtl">', english)

    def test_mixed_list_keeps_the_persian_item_rtl(self) -> None:
        """One Persian line is enough for a right-hand marker; the Latin item keeps its own LTR."""
        (html,) = render_markdown("- file entries first\n- مستنداتش فارسی است\n")
        self.assertIn('<ul dir="rtl">', html)
        self.assertIn('<li dir="ltr">file entries first</li>', html)
        self.assertIn('<li dir="rtl">مستنداتش فارسی است</li>', html)

    def test_numbered_and_task_items_carry_dir(self) -> None:
        """Ordered lists and task lists are per-line too."""
        numbered, tasks = render_markdown("1. یک\n2. دو\n", "- [x] انجام شد\n- [ ] باقی\n")
        self.assertIn('<ol dir="rtl">', numbered)
        self.assertIn('<li dir="rtl">یک</li>', numbered)
        self.assertIn('<ul dir="rtl">', tasks)
        self.assertIn('<li dir="rtl" class="task done">', tasks)

    def test_table_direction_follows_its_cells(self) -> None:
        """A Persian table starts its first column on the right; an English one on the left."""
        persian, english = render_markdown(
            "| ستون اول | ستون دوم |\n| --- | --- |\n| خانهٔ یک | خانهٔ دو |\n",
            "| first | second |\n| --- | --- |\n| alpha | beta |\n",
        )
        self.assertIn('<table dir="rtl"><tbody>', persian)
        self.assertIn('<td dir="rtl">ستون اول</td>', persian)
        self.assertIn('<table dir="ltr"><tbody>', english)

    def test_english_cell_inside_a_persian_table_stays_ltr(self) -> None:
        """The cell's own text wins: an English model name is LTR *inside* an RTL table."""
        (html,) = render_markdown(
            "| گزینه | مدلها |\n| --- | --- |\n| فعلی | RotatE + ComplEx |\n"
        )
        self.assertIn('<table dir="rtl"><tbody>', html)
        self.assertIn('<td dir="rtl">گزینه</td>', html)
        self.assertIn('<td dir="ltr">RotatE + ComplEx</td>', html)

    def test_quote_direction_follows_its_lines(self) -> None:
        """The quote's border side follows its own content, not the note body."""
        persian, english = render_markdown("> نقل قول فارسی\n", "> quoted in english\n")
        self.assertIn('<blockquote dir="rtl">', persian)
        self.assertIn('<blockquote dir="ltr">', english)

    def test_paragraphs_and_headings_follow_their_own_text(self) -> None:
        """A Latin-first mixed line is RTL — the case ``dir="auto"`` got wrong."""
        html, english_only = render_markdown(
            "# عنوان\n\nمتن انگلیسی mixed with فارسی\n\nQuality over quantity: 3 نتایج\n",
            "# English heading\n\nplain english paragraph\n",
        )
        self.assertIn('<h1 dir="rtl">عنوان</h1>', html)
        self.assertIn('<p dir="rtl">متن انگلیسی mixed with فارسی</p>', html)
        self.assertIn('<p dir="rtl">Quality over quantity: 3 نتایج</p>', html)
        self.assertIn('<h1 dir="ltr">English heading</h1>', english_only)
        self.assertIn('<p dir="ltr">plain english paragraph</p>', english_only)

    def test_no_block_is_left_to_the_browser(self) -> None:
        """``dir="auto"`` must not come back: it is what the rule replaced."""
        (html,) = render_markdown(
            "# عنوان\n\n- یک\n- two\n\n> نقل\n\n| a |\n| --- |\n| ب |\n\n```\ncode\n```\n"
        )
        self.assertNotIn('dir="auto"', html)
        self.assertIn('<code dir="ltr"', html)



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


class EmojiTest(_WebTestCase):
    """The emoji label surface (SPEC/07 §9)."""

    def setUp(self) -> None:
        super().setUp()
        self.session.mkdir("notes")
        self.session.write_file("notes/a.md", b"# a\n")

    def test_palette_is_quiet_and_readable_before_unlocking(self) -> None:
        """The picker list is static metadata: no unlock, no content, no state change."""
        status, data = self.call("vault.emoji_palette")
        self.assertEqual(status, 200, data)
        groups = data["result"]["groups"]
        self.assertTrue(groups)
        self.assertTrue(all(group["items"] for group in groups))
        self.assertTrue(all(str(g["group"]).startswith("emoji.group.") for g in groups))

    def test_set_label_on_a_folder_and_read_it_back(self) -> None:
        """The label reaches the listing row the browser renders."""
        self.unlock()
        status, data = self.call("vault.set_emoji", {"path": "/notes", "emoji": "🗂️"})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["result"]["emoji"], "🗂️")
        self.assertEqual(data["result"]["name"], "notes")

        status, data = self.call("vault.list_folder", {"path": "/"})
        entry = next(e for e in data["result"]["entries"] if e["name"] == "notes")
        self.assertEqual(entry["emoji"], "🗂️")

    def test_set_label_on_a_file_and_read_it_back(self) -> None:
        """The note payload carries it too, so the note head can show it."""
        self.unlock()
        status, data = self.call("vault.set_emoji", {"path": "/notes/a.md", "emoji": "📝"})
        self.assertEqual(status, 200, data)
        status, data = self.call("vault.read_file", {"path": "/notes/a.md"})
        self.assertEqual(data["result"]["emoji"], "📝")
        status, data = self.call("vault.search_filenames", {"query": "a.md"})
        hits = data["result"]["results"]
        self.assertEqual(hits[0]["emoji"], "📝")

    def test_clearing_a_label(self) -> None:
        """An empty string clears it and the listing stops showing a prefix."""
        self.unlock()
        self.call("vault.set_emoji", {"path": "/notes", "emoji": "🗂️"})
        status, data = self.call("vault.set_emoji", {"path": "/notes", "emoji": ""})
        self.assertEqual(status, 200, data)
        self.assertIsNone(data["result"]["emoji"])

    def test_labels_are_refused_when_they_are_not_glyphs(self) -> None:
        """A word and an over-long value are both BAD_REQUEST."""
        self.unlock()
        for bad in ("notes", "📁" * 20):
            status, data = self.call("vault.set_emoji", {"path": "/notes", "emoji": bad})
            self.assertEqual(status, 400, data)
            self.assertEqual(data["error"]["code"], "BAD_REQUEST")

    def test_unknown_path_is_not_found(self) -> None:
        """Labelling a path that does not exist is NOT_FOUND."""
        self.unlock()
        status, data = self.call("vault.set_emoji", {"path": "/ghost", "emoji": "⭐"})
        self.assertEqual(data["error"]["code"], "NOT_FOUND")

    def test_a_locked_browser_cannot_relabel(self) -> None:
        """It is a write: a locked vault refuses it rather than queueing it."""
        self.unlock()
        self.session.lock()
        status, data = self.call("vault.set_emoji", {"path": "/notes", "emoji": "🗂️"})
        self.assertEqual(data["error"]["code"], "VAULT_LOCKED")


class EmojiSpaTest(unittest.TestCase):
    """Both listings of the browser render the label beside the name (web UI)."""

    def setUp(self) -> None:
        self.js = (WEBUI_DIR / "app.js").read_text(encoding="utf-8")

    def _function(self, name: str) -> str:
        """Return the source of ``function <name>(…​) { … }`` by brace matching."""
        start = self.js.index(f"function {name}(")
        index = self.js.index("{", start)
        depth = 0
        for offset in range(index, len(self.js)):
            if self.js[offset] == "{":
                depth += 1
            elif self.js[offset] == "}":
                depth -= 1
                if depth == 0:
                    return self.js[start : offset + 1]
        raise AssertionError(f"unbalanced braces in {name}")

    def test_the_folder_list_uses_the_label_with_a_folder_fallback(self) -> None:
        """A labelled folder shows its glyph, an unlabelled one shows 📁."""
        body = self._function("renderFolderView")
        self.assertIn('entry.emoji || "📁"', body)

    def test_the_note_and_tree_rows_carry_the_label(self) -> None:
        """Files and tree nodes render it as their own span, beside the name."""
        self.assertIn("emojiSpan(entry)", self._function("renderFolderView"))
        self.assertIn("emojiSpan(node)", self._function("buildTreeRow"))
        self.assertIn("emojiSpan(hit)", self._function("renderSearchResults"))
        self.assertIn("state.file.emoji", self._function("renderNoteView"))

    def test_the_picker_posts_the_label_and_refreshes(self) -> None:
        """Saving calls ``vault.set_emoji`` and re-renders the surfaces on screen."""
        body = self._function("editEmoji")
        self.assertIn('call("vault.set_emoji"', body)
        self.assertLess(body.index("EMOJI_MAX"), body.index('call("vault.set_emoji"'))
        self.assertIn("refreshAfterEmoji()", body)

    def test_the_context_menu_offers_the_picker(self) -> None:
        """Right-clicking any row offers the emoji action."""
        body = self._function("showContextMenu")
        self.assertIn('t("menu.emoji")', body)
        self.assertIn("editEmoji(entry)", body)

    def test_the_palette_comes_from_the_service(self) -> None:
        """The SPA never hard-codes the groups, and a failed fetch still opens the dialog."""
        body = self._function("loadEmojiPalette")
        self.assertIn('call("vault.emoji_palette"', body)
        self.assertIn(".catch(", body)


class EmojiUiTest(unittest.TestCase):
    """The desktop picker reads the same palette and keeps the name untouched."""

    def test_display_name_prefixes_only_when_labelled(self) -> None:
        """``display_name`` is a pure prefix helper; no label means no change at all."""
        from vault.ui.models import display_name

        self.assertEqual(display_name("notes"), "notes")
        self.assertEqual(display_name("notes", ""), "notes")
        self.assertEqual(display_name("notes", None), "notes")
        self.assertEqual(display_name("notes", "🗂️"), "🗂️ notes")
        self.assertEqual(display_name("notes", "  🗂️ "), "🗂️ notes")

    def test_the_dialog_offers_the_palette_and_an_explicit_clearing(self) -> None:
        """The picker carries the hint and a "no emoji" action; its value can be empty."""
        import inspect

        from vault.ui import emoji_dialog

        source = inspect.getsource(emoji_dialog)
        self.assertIn("emoji.clear", source)
        self.assertIn("emoji.hint", source)
        self.assertTrue(callable(emoji_dialog.EmojiDialog.value))

    def test_the_controller_reads_the_palette_from_the_service(self) -> None:
        """``edit_emoji`` never hard-codes glyphs: it asks the service, then posts the label."""
        import inspect

        from vault.ui import app as app_module

        source = inspect.getsource(app_module.VaultApplication.edit_emoji)
        self.assertIn("vault.emoji_palette", source)
        self.assertIn("vault.set_emoji", source)


class PrintSpaTest(unittest.TestCase):
    """Printing a note: only the document reaches paper, in full, and the paper can be turned.

    The layout claims of the print block are measured in a real browser (headless Chrome, print
    media) during the change that added them; these tests pin the rules that make it work, so a
    later edit cannot quietly put the header back on the page or clip a long note at the fold.
    """

    def setUp(self) -> None:
        self.js = (WEBUI_DIR / "app.js").read_text(encoding="utf-8")
        self.css = (WEBUI_DIR / "styles.css").read_text(encoding="utf-8")
        self.html = (WEBUI_DIR / "index.html").read_text(encoding="utf-8")
        self.print_block = self.css[self.css.index("@media print {") :]

    def _function(self, name: str) -> str:
        """Return the source of ``function <name>(…) { … }`` by brace matching."""
        start = self.js.index(f"function {name}(")
        index = self.js.index("{", start)
        depth = 0
        for offset in range(index, len(self.js)):
            if self.js[offset] == "{":
                depth += 1
            elif self.js[offset] == "}":
                depth -= 1
                if depth == 0:
                    return self.js[start : offset + 1]
        raise AssertionError(f"unbalanced braces in {name}")

    def test_the_print_block_repaints_the_page_for_paper(self) -> None:
        """Paper is white with dark text, whatever theme the interface is wearing."""
        for selector in (
            ".app-header", ".statusbar", ".panel-left", ".note-actions", ".note-input",
            "#note-crumbs", "#note-tags", "#note-source", "#modal-root", "#toast-root",
            ".view-pane:not(#view-note)",
        ):
            self.assertIn(selector, self.print_block, selector)
        for rule in ("--bg: #ffffff", "--text: #111111", "background: #fff !important",
                     "color: #111 !important"):
            self.assertIn(rule, self.print_block, rule)

    def test_the_shell_stops_clipping_the_document_at_one_viewport(self) -> None:
        """`#app-view` is a `100dvh` column with scrolling panels on screen — not on paper."""
        self.assertIn(
            "#app-view { display: block !important; height: auto !important; "
            "overflow: visible !important; }",
            self.print_block,
        )
        self.assertIn(".panel { overflow: visible !important", self.print_block)
        self.assertIn(".layout { display: block !important", self.print_block)
        # a long code line must wrap instead of being clipped by `overflow: auto`
        self.assertIn("white-space: pre-wrap !important", self.print_block)
        self.assertIn("@page { margin:", self.print_block)
        for rule in ("break-inside: avoid", "break-after: avoid", "display: table-header-group"):
            self.assertIn(rule, self.print_block, rule)
        # the file note is metadata on paper, and only when the file has one
        self.assertIn("#file-note-print:not([hidden]) { display: block !important; }",
                      self.print_block)

    def test_the_note_view_carries_the_print_controls(self) -> None:
        """A print button, and the paper orientation next to it — both in the note's own row."""
        self.assertIn('id="btn-note-print"', self.html)
        self.assertIn('data-i18n="web.print"', self.html)
        self.assertIn('id="print-orientation"', self.html)
        self.assertIn('<option value="portrait" data-i18n="web.print_portrait">', self.html)
        self.assertIn('<option value="landscape" data-i18n="web.print_landscape">', self.html)
        self.assertIn('id="file-note-print"', self.html)

    def test_the_button_hands_over_to_the_browser_dialog(self) -> None:
        """No export endpoint and no server round-trip: the page *is* the document."""
        self.assertIn("window.print()", self.js)

    def test_the_paper_orientation_is_written_into_the_document(self) -> None:
        """Ctrl+P must honour the choice too, so it goes in as an `@page` rule, not a button state."""
        body = self._function("applyPrintOrientation")
        self.assertIn('"@media print { @page { size: A4 " + value', body)
        # session storage, like the language and the theme: this interface writes nothing to disk
        self.assertIn("sessionStorage.setItem(PRINT_KEY", body)
        self.assertIn("sessionStorage.getItem(PRINT_KEY", self._function("savedPrintOrientation"))
        self.assertIn('mode === "landscape" ? "landscape" : "portrait"', body)
        self.assertIn("applyPrintOrientation(savedPrintOrientation())", self.js)
        self.assertIn('"#print-orientation"', self.js)

    def test_printing_is_offered_only_when_there_is_something_to_print(self) -> None:
        """A secret's text never reaches the browser, and a non-image blob has only a placeholder."""
        body = self._function("renderNoteView")
        self.assertIn('state.file.sensitivity === "normal"', body)
        self.assertIn('"#btn-note-print"', body)
        self.assertIn('"#print-orientation"', body)
        self.assertIn("fileNotePrint", body)
        # a file note is mirrored for paper only when the file has one — otherwise the print block
        # would leave an empty line of metadata on the page
        self.assertIn("fileNotePrint.hidden = !notePrintText", body)
        self.assertIn('"#file-note-print"', body)

    def test_the_print_labels_exist_in_every_language(self) -> None:
        keys = ("web.print", "web.print_title", "web.print_orientation",
                "web.print_portrait", "web.print_landscape")
        languages = sorted(I18N_DIR.glob("*.json"))
        self.assertTrue(languages, "no interface languages found")
        for path in languages:
            data = json.loads(path.read_text(encoding="utf-8"))
            for key in keys:
                self.assertIn(key, data, f"{key} missing in {path.name}")
                self.assertTrue(str(data[key]).strip(), f"{key} empty in {path.name}")
