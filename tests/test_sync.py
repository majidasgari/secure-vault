"""S3 folder-sync tests (lock, read-only gating, two-way mirror).

Everything runs against an in-memory fake S3 so no network is ever touched, and every
path (config, data, vault) is a scratch directory — never the user's real vault.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from support import tmp_vault

from vault.api.service import Service
from vault.core.sync import LOCK_FILENAME, SyncManager, _is_excluded
from vault.errors import BadRequest, SyncError, SyncReadOnly


class FakeS3:
    """A tiny in-memory S3 with the duck-typed surface :class:`SyncManager` uses."""

    def __init__(self) -> None:
        """Start with an empty bucket."""
        self.objects: dict[str, bytes] = {}
        self.if_none_match_supported = True

    @property
    def available(self) -> bool:
        """Always available (no boto3 needed)."""
        return True

    def get(self, key: str) -> bytes | None:
        """Return an object or ``None``."""
        return self.objects.get(key)

    def put(self, key: str, data: bytes, *, if_none_match: bool = False) -> bool:
        """Store an object (create-only when ``if_none_match``)."""
        if if_none_match and key in self.objects:
            return False
        self.objects[key] = bytes(data)
        return True

    def delete(self, key: str) -> None:
        """Delete an object if present."""
        self.objects.pop(key, None)

    def list(self, prefix: str) -> list[dict]:
        """List objects under ``prefix`` with an MD5 ETag."""
        rows = []
        for key, value in self.objects.items():
            if key.startswith(prefix):
                rows.append(
                    {
                        "key": key,
                        "size": len(value),
                        "etag": hashlib.md5(value).hexdigest(),  # noqa: S324
                        "modified": 0,
                    }
                )
        return rows


class SyncTestBase(unittest.TestCase):
    """Scratch vault + fake bucket with the machine-local config redirected to temp."""

    def setUp(self) -> None:
        """Create a scratch vault and a fake S3 client."""
        self._tmp = Path(tempfile.mkdtemp(prefix="sv-sync-"))
        self._old_config = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = str(self._tmp / "config")
        self.session = tmp_vault(self._tmp)
        self.fake = FakeS3()
        self.manager = self.session.sync_manager()
        self.manager.set_client(self.fake)
        self._configure()

    def tearDown(self) -> None:
        """Restore the process environment."""
        if self._old_config is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old_config
        try:
            self.session.close()
        except Exception:  # noqa: BLE001
            pass

    def _configure(self, *, prefix: str = "vault") -> None:
        """Enable sync on the vault and store fake machine-local credentials."""
        from vault.config import save_sync_config

        save_sync_config({"access_key": "test-key", "secret_key": "test-secret"})
        self.session.meta.settings["sync"] = {
            "enabled": True,
            "bucket": "test-bucket",
            "prefix": prefix,
            "endpoint": "",
            "region": "",
        }
        self.session.meta.save()
        self.manager.reload_config()
        self.manager.set_client(self.fake)

    def lock_key(self, prefix: str = "vault") -> str:
        """Return the lock object key for ``prefix``."""
        return f"{prefix}/{LOCK_FILENAME}"


class LockTest(SyncTestBase):
    """The cooperative write lock and the read-only state it produces."""

    def test_acquire_and_release(self) -> None:
        """A free bucket is acquired, then released."""
        status = self.manager.acquire()
        self.assertTrue(status["owned"])
        self.assertFalse(status["readonly"])
        self.assertIn(self.lock_key(), self.fake.objects)
        status = self.manager.release()
        self.assertFalse(status["owned"])
        self.assertTrue(status["readonly"])
        self.assertNotIn(self.lock_key(), self.fake.objects)

    def test_foreign_lock_is_read_only_until_force(self) -> None:
        """A lock owned by another client makes this session read-only."""
        self.fake.objects[self.lock_key()] = json.dumps(
            {"owner": "someone-else", "host": "other-host"}
        ).encode("utf-8")
        status = self.manager.acquire()
        self.assertFalse(status["owned"])
        self.assertTrue(status["readonly"])
        self.assertEqual(status["held_by"]["host"], "other-host")
        status = self.manager.acquire(force=True)
        self.assertTrue(status["owned"])
        self.assertFalse(status["readonly"])

    def test_readonly_blocks_file_writes(self) -> None:
        """Every mutation is refused while another client holds the lock."""
        self.fake.objects[self.lock_key()] = json.dumps(
            {"owner": "someone-else", "host": "other-host"}
        ).encode("utf-8")
        self.manager.acquire()
        self.assertTrue(self.manager.readonly)
        with self.assertRaises(SyncReadOnly):
            self.session.write_file("notes/a.md", b"hello")
        with self.assertRaises(SyncReadOnly):
            self.session.mkdir("notes")
        with self.assertRaises(SyncReadOnly):
            self.session.set_tags("notes/a.md", ["x"])

    def test_write_allowed_when_owned(self) -> None:
        """After acquiring, normal writes go through."""
        self.manager.acquire()
        row = self.session.write_file("notes/a.md", b"hello")
        self.assertEqual(row["logical_path"], "notes/a.md")

    def test_disabled_sync_is_writable(self) -> None:
        """With sync disabled there is no lock and writes are always allowed."""
        self.session.meta.settings["sync"] = {"enabled": False}
        self.session.meta.save()
        manager = SyncManager(self.session, client=self.fake)
        manager.startup()
        self.assertFalse(manager.readonly)
        self.session.write_file("notes/a.md", b"hello")


class MirrorTest(SyncTestBase):
    """The three-way mirror: uploads, downloads and deletes."""

    def setUp(self) -> None:
        """Acquire the write lock before each mirror test."""
        super().setUp()
        self.manager.acquire()
        self.assertTrue(self.manager.owned)

    def rels(self) -> set[str]:
        """Return the vault-relative keys currently in the fake bucket."""
        prefix = self.manager.config.normalized_prefix()
        return {
            key[len(prefix) :]
            for key in self.fake.objects
            if key.startswith(prefix) and not key.endswith(LOCK_FILENAME)
        }

    def test_uploads_everything_once(self) -> None:
        """The first sync uploads the vault files; the second only re-uploads metadata.

        The access log grows on every call, so ``meta.sqlite`` legitimately differs by one
        row between two syncs; the important invariant is that no blob is re-uploaded and
        nothing is downloaded.
        """
        self.session.write_file("notes/a.md", b"alpha")
        first = self.manager.sync()
        self.assertGreaterEqual(first["uploaded"], 3)  # meta + store + blob
        self.assertIn("meta.sqlite", self.rels())
        self.assertIn(".vault-meta.json", self.rels())
        self.assertTrue(any(r.startswith("files/") for r in self.rels()))
        second = self.manager.sync()
        self.assertEqual(second["downloaded"], 0)
        self.assertLessEqual(second["uploaded"], 1)

    def test_downloads_remote_only_file(self) -> None:
        """A file that only exists in the bucket is pulled down."""
        prefix = self.manager.config.normalized_prefix()
        self.fake.objects[f"{prefix}remote.md"] = b"from the cloud"
        result = self.manager.sync()
        self.assertEqual(result["downloaded"], 1)
        self.assertEqual((self.session.home / "remote.md").read_bytes(), b"from the cloud")

    def test_local_delete_propagates_remote(self) -> None:
        """Deleting a synced file locally removes it from the bucket."""
        self.session.write_file("notes/a.md", b"alpha")
        self.manager.sync()
        target = self.session.home / "notes" / "a.md"
        # The logical file is a row + blob; remove the blob so the folder really changes.
        self.session.delete("notes/a.md")
        self.manager.sync()
        self.assertFalse(any(r.startswith("files/") for r in self.rels()))

    def test_remote_delete_propagates_local(self) -> None:
        """An object deleted in the bucket is removed locally."""
        self.session.write_file("notes/a.md", b"alpha")
        self.manager.sync()
        prefix = self.manager.config.normalized_prefix()
        # Remove every blob object but keep the metadata: the local blob then has no peer.
        for key in [k for k in self.fake.objects if k.startswith(f"{prefix}files/")]:
            del self.fake.objects[key]
        # Force a fresh base so the deleted blob is detected as a remote delete.
        state = self.manager._read_state()
        remote_blob = next(
            r for r in state["files"] if r.startswith("files/")
        )
        self.manager.sync()
        local_blob = self.session.home / remote_blob
        self.assertFalse(local_blob.exists())

    def test_semantic_db_is_never_synced(self) -> None:
        """A semantic/vector .db inside the home is excluded from the mirror."""
        (self.session.home / "semantic-abc.db").write_bytes(b"vectors")
        (self.session.home / "cache").mkdir(exist_ok=True)
        (self.session.home / "cache" / "m__8.db").write_bytes(b"cache")
        self.manager.sync()
        self.assertFalse(any("semantic" in r for r in self.rels()))
        self.assertFalse(any(r.endswith(".db") for r in self.rels()))

    def test_is_excluded_rules(self) -> None:
        """Runtime/derived paths are excluded; vault data is not."""
        for excluded in (
            "semantic.db",
            "semantic/x.db",
            "cache/m.db",
            "secure.store-wal",
            "meta.sqlite-wal",
            "store.123.dec",
            "x.tmp",
            ".secure-vault.lock",
        ):
            self.assertTrue(_is_excluded(excluded), excluded)
        for kept in (".vault-meta.json", "meta.sqlite", "secure.store", "files/aa/x.enc"):
            self.assertFalse(_is_excluded(kept), kept)


class AsyncSyncTest(SyncTestBase):
    """Background sync execution, progress job and the connection test."""

    def test_background_sync_reports_progress(self) -> None:
        """``start_sync`` returns at once, the job finishes and carries the counts."""
        self.manager.acquire()
        self.session.write_file("notes/a.md", b"alpha")
        started = self.manager.start_sync()
        self.assertTrue(started["started"])
        deadline = time.time() + 15
        while self.manager.syncing and time.time() < deadline:
            time.sleep(0.02)
        job = self.manager.job()
        self.assertTrue(job["finished"])
        self.assertTrue(job["ok"])
        self.assertGreaterEqual(job["result"]["uploaded"], 2)
        self.assertGreaterEqual(job["upload"]["total"], 2)
        self.assertFalse(self.manager.syncing)

    def test_service_sync_now_is_async(self) -> None:
        """The service method starts a job and returns before it finishes."""
        self.manager.acquire()
        self.session.write_file("notes/a.md", b"alpha")
        service = Service(self.session)
        result = service.dispatch("vault.sync_now", {}, role="ui", session_id="t")
        self.assertTrue(result["started"])
        deadline = time.time() + 15
        while self.manager.syncing and time.time() < deadline:
            time.sleep(0.02)
        self.assertTrue(self.manager.job()["finished"])

    def test_writes_refused_while_syncing(self) -> None:
        """A local write during the mirror is refused instead of racing it."""
        self.manager.acquire()
        self.session._syncing = True
        try:
            with self.assertRaises(SyncError):
                self.session.write_file("notes/b.md", b"x")
        finally:
            self.session._syncing = False

    def test_test_connection(self) -> None:
        """``test_connection`` lists the bucket and reports success."""
        self.manager.acquire()
        result = self.manager.test_connection()
        self.assertTrue(result["ok"])
        self.assertIn("objects", result)

    def test_cancel_stops_background_sync(self) -> None:
        """``cancel`` aborts a running mirror instead of letting it race a lock."""
        import threading

        class BlockingFake(FakeS3):
            def __init__(self) -> None:
                super().__init__()
                self.release = threading.Event()

            def list(self, prefix: str) -> list[dict]:
                self.release.wait(5)
                return super().list(prefix)

        client = BlockingFake()
        self.manager.set_client(client)
        self.manager.reload_config()
        self.manager.acquire()
        self.session.write_file("notes/a.md", b"alpha")
        self.assertTrue(self.manager.start_sync()["started"])
        time.sleep(0.05)  # let the worker reach the blocking list()
        self.manager.cancel()
        client.release.set()
        self.assertTrue(self.manager.wait(5))
        job = self.manager.job()
        self.assertTrue(job["finished"])
        self.assertFalse(job["ok"])
        self.assertEqual(job["error"], "sync_cancelled")

    def test_test_connection_unconfigured(self) -> None:
        """``test_connection`` reports ``not_configured`` instead of raising."""
        self.session.meta.settings["sync"] = {"enabled": False}
        self.session.meta.save()
        manager = SyncManager(self.session, client=self.fake)
        result = manager.test_connection()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "not_configured")


class SyncServiceTest(SyncTestBase):
    """The public service surface for sync."""

    def test_sync_status_route(self) -> None:
        """``vault.sync_status`` reports the configured state."""
        service = Service(self.session)
        result = service.dispatch("vault.sync_status", {}, role="ui", session_id="t")
        self.assertTrue(result["sync"]["configured"])
        self.assertIn("readonly", result["sync"])

    def test_sync_test_route(self) -> None:
        """The service exposes the connection test without transferring anything."""
        service = Service(self.session)
        result = service.dispatch("vault.sync_test", {}, role="ui", session_id="t")
        self.assertTrue(result["connection"]["ok"])

    def test_sync_status_carries_job(self) -> None:
        """``vault.sync_status`` includes the progress job for the UI."""
        service = Service(self.session)
        result = service.dispatch("vault.sync_status", {}, role="ui", session_id="t")
        self.assertIn("job", result["sync"])
        self.assertIn("running", result["sync"]["job"])

    def test_sync_now_requires_lock(self) -> None:
        """``vault.sync_now`` is refused while read-only."""
        self.fake.objects[self.lock_key()] = json.dumps(
            {"owner": "other", "host": "h"}
        ).encode("utf-8")
        self.manager.acquire()
        service = Service(self.session)
        with self.assertRaises(SyncReadOnly):
            service.dispatch("vault.sync_now", {}, role="ui", session_id="t")

    def test_semantic_path_inside_vault_rejected(self) -> None:
        """Settings refuse a vector-cache path inside the vault home."""
        service = Service(self.session)
        inside = str(self.session.home / "vectors")
        with self.assertRaises(BadRequest) as ctx:
            service.dispatch(
                "vault.set_settings",
                {"semantic": {"db_path": inside}},
                role="ui",
                session_id="t",
            )
        self.assertEqual(ctx.exception.message, "semantic_path_inside_vault")

    def test_semantic_path_outside_vault_accepted(self) -> None:
        """A path outside the vault is accepted."""
        service = Service(self.session)
        outside = str(self._tmp / "vectors")
        service.dispatch(
            "vault.set_settings",
            {"semantic": {"db_path": outside}},
            role="ui",
            session_id="t",
        )
        self.assertEqual(self.session.meta.settings["semantic"]["db_path"], outside)


class StdlibS3BackendTest(unittest.TestCase):
    """The dependency-free S3 backend talks real HTTP with a SigV4 signature."""

    @classmethod
    def setUpClass(cls) -> None:
        """Start a tiny in-process S3 look-alike on loopback."""
        import http.server
        import threading
        from urllib.parse import parse_qs, unquote, urlsplit

        store: dict[str, bytes] = {}
        seen: dict[str, str] = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args: object) -> None:  # noqa: D401 - silence
                pass

            def _key(self) -> str:
                path = urlsplit(self.path).path
                parts = path.split("/", 2)
                return unquote(parts[2]) if len(parts) > 2 else ""

            def _send(self, status: int, body: bytes = b"") -> None:
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                seen["auth"] = self.headers.get("Authorization", "")
                seen["date"] = self.headers.get("x-amz-date", "")
                seen["content-sha"] = self.headers.get("x-amz-content-sha256", "")
                query = parse_qs(urlsplit(self.path).query)
                if query.get("list-type"):
                    rows = []
                    for key, value in store.items():
                        digest = hashlib.md5(value).hexdigest()  # noqa: S324
                        rows.append(
                            f"<Contents><Key>{key}</Key><Size>{len(value)}</Size>"
                            f"<ETag>&quot;{digest}&quot;</ETag>"
                            "<LastModified>2024-01-01T00:00:00.000Z</LastModified></Contents>"
                        )
                    xml = (
                        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                        "<IsTruncated>false</IsTruncated>" + "".join(rows) + "</ListBucketResult>"
                    )
                    self._send(200, xml.encode("utf-8"))
                    return
                data = store.get(self._key())
                self._send(404) if data is None else self._send(200, data)

            def do_PUT(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                key = self._key()
                if self.headers.get("If-None-Match") == "*" and key in store:
                    self._send(412)
                    return
                store[key] = body
                self._send(200)

            def do_DELETE(self) -> None:  # noqa: N802
                store.pop(self._key(), None)
                self._send(204)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls._thread = threading.Thread(target=server.serve_forever, daemon=True)
        cls._thread.start()
        cls.server = server
        cls.store = store
        cls.seen = seen

    @classmethod
    def tearDownClass(cls) -> None:
        """Stop the fake server."""
        cls.server.shutdown()
        cls.server.server_close()

    def _client(self) -> "S3Client":
        from vault.core.s3 import S3Client, S3Config

        host, port = self.server.server_address
        return S3Client(
            S3Config(
                enabled=True,
                bucket="bucket",
                endpoint=f"http://127.0.0.1:{port}",
                region="us-east-1",
                access_key="AKIAEXAMPLE",
                secret_key="secret",
            )
        )

    def test_operations_and_signature(self) -> None:
        """put/get/delete/list work and every request is SigV4-signed."""
        client = self._client()
        self.assertEqual(client.backend_name, "stdlib")
        self.assertTrue(client.put("a/b.txt", b"hello"))
        self.assertEqual(client.get("a/b.txt"), b"hello")
        self.assertIsNone(client.get("missing.txt"))
        # create-only put loses against an existing key
        self.assertFalse(client.put("a/b.txt", b"other", if_none_match=True))
        entries = client.list("")
        self.assertEqual([e["key"] for e in entries], ["a/b.txt"])
        self.assertEqual(entries[0]["size"], 5)
        self.assertEqual(entries[0]["etag"], hashlib.md5(b"hello").hexdigest())  # noqa: S324
        client.delete("a/b.txt")
        self.assertIsNone(client.get("a/b.txt"))
        self.assertTrue(self.seen["auth"].startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/"))
        self.assertIn("SignedHeaders=", self.seen["auth"])
        self.assertTrue(self.seen["date"])
        self.assertTrue(self.seen["content-sha"])

    def test_sync_manager_over_stdlib(self) -> None:
        """The whole lock + mirror flow works over the stdlib HTTP backend."""
        from vault.config import save_sync_config

        tmp = Path(tempfile.mkdtemp(prefix="sv-sync-stdlib-"))
        old_config = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = str(tmp / "config")
        try:
            session = tmp_vault(tmp)
            save_sync_config({"access_key": "AKIAEXAMPLE", "secret_key": "secret"})
            session.meta.settings["sync"] = {
                "enabled": True,
                "bucket": "bucket",
                "prefix": "vault",
            }
            session.meta.save()
            manager = session.sync_manager()
            manager.set_client(self._client())
            manager.reload_config()
            self.assertTrue(manager.acquire()["owned"])
            session.write_file("notes/a.md", b"alpha")
            result = manager.sync()
            self.assertGreaterEqual(result["uploaded"], 2)
            self.assertIn("vault/.secure-vault.lock", self.store)
            self.assertIn("vault/meta.sqlite", self.store)
            self.assertTrue(any(k.startswith("vault/files/") for k in self.store))
            session.close()
        finally:
            if old_config is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = old_config


if __name__ == "__main__":
    unittest.main()
