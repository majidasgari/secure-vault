"""Importing an existing vault from S3 (docs/SYNC.md §9) and the guards it depends on.

The accident this feature exists to prevent: a bucket already holds vault **A**, a second
machine creates a brand-new vault **B** and syncs it, and B's empty index and fresh identity
overwrite A's — every blob survives, but the index that names them is gone. Import must
adopt A from the bucket instead, and sync itself must now refuse the clobber.

Everything runs against an in-memory fake S3 with scratch directories only.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from support import tmp_vault
from test_sync import FakeS3

from vault.config import save_sync_config, user_data_dir
from vault import import_cli
from vault.core import remote_import
from vault.core.s3 import S3Config
from vault.core.session import VaultSession
from vault.core.sync import BACKUP_DIRNAME, IDENTITY_FILENAME, METADATA_FILENAMES, META_BACKUP_KEEP
from vault.core.sync import SyncManager
from vault.errors import AlreadyExists, NotFound, SyncError, Unauthorized

PASSWORD = "correct horse battery staple"
OTHER_PASSWORD = "a different master password"
PREFIX = "sync"

FILES = {
    "notes/alpha.md": b"# alpha\nremember the milk\n",
    "notes/beta.md": b"# beta\nsomething else entirely\n",
    "secrets/bank.txt": b"account: 1234-5678\n",
}


def _config(prefix: str = PREFIX, **overrides: object) -> S3Config:
    """Return a complete S3 config for the fake bucket."""
    values: dict[str, object] = {
        "enabled": True,
        "bucket": "test-bucket",
        "prefix": prefix,
        "endpoint": "",
        "region": "",
        "access_key": "test-key",
        "secret_key": "test-secret",
    }
    values.update(overrides)
    return S3Config(**values)  # type: ignore[arg-type]


class ImportTestBase(unittest.TestCase):
    """Vault **A** (with content) mirrored into a fake bucket, plus a scratch machine."""

    def setUp(self) -> None:
        """Create vault A, fill it and sync it into the fake bucket."""
        self._tmp = Path(tempfile.mkdtemp(prefix="sv-import-"))
        self._old_env = {
            name: os.environ.get(name) for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME")
        }
        os.environ["XDG_CONFIG_HOME"] = str(self._tmp / "config")
        os.environ["XDG_DATA_HOME"] = str(self._tmp / "data")
        save_sync_config({"access_key": "test-key", "secret_key": "test-secret"})

        self.vault_a = tmp_vault(self._tmp, password=PASSWORD)
        self.home_a = Path(self.vault_a.home)
        for logical, payload in FILES.items():
            try:
                self.vault_a.mkdir(str(Path(logical).parent))
            except AlreadyExists:
                pass  # two files can share a folder
            self.vault_a.write_file(logical, payload)

        self.fake = FakeS3()
        self.config = _config()
        self.manager_a = self.vault_a.sync_manager()
        self._enable_sync(self.vault_a, self.manager_a)
        self.manager_a.acquire()
        self.uploaded = self.manager_a.sync()
        self.assertGreaterEqual(self.uploaded["uploaded"], 3)

    def tearDown(self) -> None:
        """Restore the process environment and close every session."""
        for name, value in self._old_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        for session in (getattr(self, "vault_a", None), getattr(self, "extra", None)):
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001
                    pass

    def _enable_sync(self, session: VaultSession, manager: SyncManager) -> None:
        """Point ``session`` at the fake bucket."""
        session.meta.settings["sync"] = {
            "enabled": True,
            "bucket": "test-bucket",
            "prefix": PREFIX,
            "endpoint": "",
            "region": "",
        }
        session.meta.save()
        manager.reload_config()
        manager.set_client(self.fake)

    def destination(self, name: str = "dest") -> Path:
        """Return a fresh, empty vault home on this scratch machine."""
        return self._tmp / name

    def remote_keys(self) -> set[str]:
        """Return the vault-relative keys in the fake bucket."""
        prefix = f"{PREFIX}/"
        return {key[len(prefix) :] for key in self.fake.objects if key.startswith(prefix)}

    def fresh_vault(self, name: str = "other", *, password: str = OTHER_PASSWORD) -> VaultSession:
        """Create a second, unrelated vault (vault **B**) on this scratch machine."""
        base = self._tmp / name
        base.mkdir(parents=True, exist_ok=True)
        session = VaultSession.create(base / "vault", password)
        session.mkdir("personal")
        session.write_file("personal/scratch.md", b"brand new vault\n")
        session.flush()
        session.sync_manager().set_client(self.fake)
        self.extra = session
        return session


class ProbeTest(ImportTestBase):
    """Reading what the bucket advertises, before anything is written."""

    def test_probe_describes_the_remote_vault(self) -> None:
        """The probe reports the identity, the index counts and the blob inventory."""
        info, identity = remote_import.probe_remote(self.fake, self.config)
        self.assertEqual(info.vault_id, self.vault_a.meta.vault_id)
        self.assertEqual(info.files, len(FILES))
        self.assertGreaterEqual(info.versions, 1)  # every write keeps a version
        self.assertGreaterEqual(info.folders, 2)  # notes + secrets
        self.assertGreaterEqual(info.blobs, len(FILES))
        self.assertEqual(info.referenced_blobs, info.blobs)
        self.assertGreater(info.blob_bytes, 0)
        self.assertGreater(info.store_bytes, 0)
        self.assertEqual(info.settings_sync.get("bucket"), "test-bucket")
        self.assertEqual(identity.get("vault_id"), self.vault_a.meta.vault_id)

    def test_probe_rejects_an_empty_bucket(self) -> None:
        """A prefix with no objects at all is reported as an empty bucket."""
        with self.assertRaises(NotFound) as ctx:
            remote_import.probe_remote(self.fake, _config(prefix="nowhere"))
        self.assertEqual(ctx.exception.message, "remote_bucket_empty")

    def test_probe_rejects_a_prefix_without_a_vault(self) -> None:
        """Objects without an identity are not a vault."""
        self.fake.objects["nowhere/readme.txt"] = b"nothing to see"
        with self.assertRaises(NotFound) as ctx:
            remote_import.probe_remote(self.fake, _config(prefix="nowhere"))
        self.assertEqual(ctx.exception.message, "remote_vault_missing")

    def test_remote_vault_id_reads_the_identity(self) -> None:
        """The cheap identity lookup used by the sync guard returns the vault id."""
        self.assertEqual(
            remote_import.remote_vault_id(self.fake, self.config), self.vault_a.meta.vault_id
        )
        self.assertEqual(remote_import.remote_vault_id(self.fake, _config(prefix="elsewhere")), "")


class ImportTest(ImportTestBase):
    """Adopting the bucket's vault: identity, index, store and blobs."""

    def test_import_recovers_the_whole_vault(self) -> None:
        """The imported folder unlocks with the *original* password and reads the files."""
        home = self.destination()
        report = remote_import.import_vault(self.fake, self.config, home, password=PASSWORD)
        self.assertTrue(report.ok)
        self.assertEqual(report.vault_id, self.vault_a.meta.vault_id)
        self.assertEqual(report.files, len(FILES))
        self.assertGreaterEqual(report.downloaded, len(FILES))
        self.assertGreater(report.metadata_bytes, 0)
        self.assertFalse(report.replaced)

        restored = VaultSession(home)
        restored.unlock(PASSWORD)
        self.extra = restored
        self.assertEqual(restored.meta.vault_id, self.vault_a.meta.vault_id)
        for logical, payload in FILES.items():
            self.assertEqual(restored.read_file(logical), payload, logical)
        names = {row["logical_path"] for row in restored.list_folder("/")["entries"]}
        self.assertLessEqual({"notes", "secrets"}, names)

    def test_import_reports_progress_and_counts(self) -> None:
        """The progress sink sees the phases in order."""
        phases: list[str] = []
        home = self.destination()
        report = remote_import.import_vault(
            self.fake,
            self.config,
            home,
            password=PASSWORD,
            progress=lambda phase, done, total: phases.append(phase),
        )
        self.assertEqual(report.reused, 0)
        self.assertIn("probe", phases)
        self.assertIn("files", phases)
        self.assertIn("index", phases)
        self.assertIn("install", phases)
        self.assertEqual(phases[-1], "done")

    def test_import_is_idempotent_and_reuses_blobs(self) -> None:
        """Running the import twice downloads nothing the second time."""
        home = self.destination()
        first = remote_import.import_vault(self.fake, self.config, home, password=PASSWORD)
        second = remote_import.import_vault(self.fake, self.config, home, password=PASSWORD)
        self.assertGreater(first.downloaded, 0)
        self.assertEqual(second.downloaded, 0)
        self.assertEqual(second.reused, first.downloaded)
        self.assertFalse(second.replaced)

    def test_import_reuses_blobs_already_on_disk(self) -> None:
        """Blobs left over from another vault are reused instead of re-downloaded.

        This is the recovery case: the folder already holds the blobs (a previous partial
        copy, or another vault's folder) and only the metadata has to be fetched.
        """
        home = self.destination()
        home.mkdir(parents=True, exist_ok=True)
        source = self.home_a / "files"
        blobs = list(source.glob("*/*.enc"))
        for path in blobs:
            target = home / "files" / path.parent.name / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
        report = remote_import.import_vault(self.fake, self.config, home, password=PASSWORD)
        self.assertEqual(report.downloaded, 0)
        self.assertEqual(report.reused, len(blobs))

    def test_import_verifies_the_password_before_writing(self) -> None:
        """A wrong password fails immediately and leaves no half-built vault."""
        home = self.destination()
        with self.assertRaises(Unauthorized):
            remote_import.import_vault(self.fake, self.config, home, password="not the password")
        self.assertFalse((home / IDENTITY_FILENAME).exists())

    def test_import_without_password_still_works(self) -> None:
        """The password is optional: the identity is adopted and checked at unlock time."""
        home = self.destination()
        report = remote_import.import_vault(self.fake, self.config, home)
        self.assertTrue(report.ok)
        self.assertTrue(VaultSession(home).meta.verify_password(PASSWORD))
        self.assertFalse(VaultSession(home).meta.verify_password("wrong"))

    def test_import_refuses_to_replace_another_vault(self) -> None:
        """A different vault already in the folder needs an explicit ``replace``."""
        other = self.fresh_vault()
        home = Path(other.home)
        with self.assertRaises(AlreadyExists) as ctx:
            remote_import.import_vault(self.fake, self.config, home, password=PASSWORD)
        self.assertEqual(ctx.exception.message, "vault_exists")
        self.assertEqual(VaultSession(home).meta.vault_id, other.meta.vault_id)

        # The replaced vault must be closed first (Windows holds the index open).
        other.close()
        self.extra = None
        report = remote_import.import_vault(
            self.fake, self.config, home, password=PASSWORD, replace=True
        )
        self.assertTrue(report.ok)
        self.assertTrue(report.replaced)
        parked = Path(report.parked_at)
        self.assertTrue(parked.is_dir())
        self.assertTrue((parked / IDENTITY_FILENAME).is_file())
        self.assertTrue((parked / "README.txt").is_file())
        self.assertEqual(VaultSession(home).meta.vault_id, self.vault_a.meta.vault_id)
        # The replaced vault's blobs stay in place, ready to be reused or pruned.
        self.assertTrue(any(home.glob("files/*/*.enc")))

    def test_import_reports_a_locked_vault(self) -> None:
        """A vault whose files are held open reports it instead of half-replacing it."""
        other = self.fresh_vault()
        home = Path(other.home)
        with mock.patch.object(
            remote_import.shutil, "copy2", side_effect=OSError("file is in use")
        ):
            with self.assertRaises(SyncError) as ctx:
                remote_import.import_vault(
                    self.fake, self.config, home, password=PASSWORD, replace=True
                )
        self.assertEqual(ctx.exception.message, "vault_in_use")
        self.assertEqual(VaultSession(home).meta.vault_id, other.meta.vault_id)

    def test_import_reports_missing_blobs(self) -> None:
        """A bucket missing a referenced blob refuses to install an index."""
        victim = next(r for r in self.remote_keys() if r.startswith("files/"))
        del self.fake.objects[f"{PREFIX}/{victim}"]
        home = self.destination()
        with self.assertRaises(SyncError) as ctx:
            remote_import.import_vault(self.fake, self.config, home, password=PASSWORD)
        self.assertEqual(ctx.exception.message, "import_incomplete")
        self.assertFalse((home / IDENTITY_FILENAME).exists())

    def test_import_seeds_the_sync_base_manifest(self) -> None:
        """The first sync after an import transfers nothing at all."""
        home = self.destination()
        report = remote_import.import_vault(self.fake, self.config, home, password=PASSWORD)
        self.assertGreater(report.seeded, 0)
        state = user_data_dir() / "sync" / f"{report.vault_id}.json"
        self.assertTrue(state.is_file(), state)

        restored = VaultSession(home)
        restored.unlock(PASSWORD)
        self.extra = restored
        manager = restored.sync_manager()
        self._enable_sync(restored, manager)
        manager.acquire()
        result = manager.sync()
        self.assertEqual(result["downloaded"], 0)
        self.assertEqual(result["uploaded"], 0)


class SyncGuardTest(ImportTestBase):
    """The two guards that make the accident impossible, plus the rollback copies."""

    def test_sync_refuses_a_foreign_vault(self) -> None:
        """Vault B must not mirror itself into vault A's prefix."""
        before = set(self.fake.objects)
        other = self.fresh_vault()
        manager = other.sync_manager()
        self._enable_sync(other, manager)
        manager.acquire()
        with self.assertRaises(SyncError) as ctx:
            manager.sync()
        self.assertEqual(ctx.exception.message, "vault_id_mismatch")
        # A's identity is untouched and nothing of B reached the bucket.
        identity = self.fake.objects[f"{PREFIX}/{IDENTITY_FILENAME}"].decode("utf-8")
        self.assertIn(self.vault_a.meta.vault_id, identity)
        self.assertEqual(set(self.fake.objects), before)

    def test_sync_refuses_to_clobber_a_populated_remote_index(self) -> None:
        """A near-empty local index is not allowed to replace a large remote one."""
        # A populated remote index that also changed since the base manifest, so the plan
        # wants to upload the (tiny) local one over it.
        self.fake.objects[f"{PREFIX}/meta.sqlite"] = b"x" * (2 * 1024 * 1024)
        self.vault_a.write_file("notes/gamma.md", b"# gamma\nmore content\n")
        with self.assertRaises(SyncError) as ctx:
            self.manager_a.sync()
        self.assertEqual(ctx.exception.message, "refusing_to_overwrite_remote_metadata")

    def test_sync_allows_a_deliberate_metadata_overwrite(self) -> None:
        """The documented escape hatch lets a deliberate overwrite through."""
        self.fake.objects[f"{PREFIX}/meta.sqlite"] = b"x" * (2 * 1024 * 1024)
        self.vault_a.meta.settings["sync"]["allow_metadata_overwrite"] = True
        self.vault_a.meta.save()
        self.vault_a.write_file("notes/gamma.md", b"# gamma\nmore content\n")
        result = self.manager_a.sync()
        self.assertGreaterEqual(result["uploaded"], 1)

    def test_sync_backs_up_metadata_before_overwriting(self) -> None:
        """The remote metadata is copied aside before the first overwrite."""
        before = self.fake.objects[f"{PREFIX}/meta.sqlite"]
        self.vault_a.write_file("notes/delta.md", b"# delta\none more\n")
        result = self.manager_a.sync()
        self.assertGreaterEqual(result["uploaded"], 1)
        backups = sorted(
            key
            for key in self.fake.objects
            if key.startswith(f"{PREFIX}/{BACKUP_DIRNAME}/")
        )
        self.assertTrue(backups, "no metadata backup was written")
        self.assertTrue(backups[0].endswith(f"/meta.sqlite"), backups[0])
        self.assertEqual(self.fake.objects[backups[0]], before)
        # The backup folder must never be mirrored into the vault.
        self.assertFalse((self.home_a / BACKUP_DIRNAME).exists())

    def test_backup_pruning_keeps_the_newest_generations(self) -> None:
        """Pruning keeps the newest generations per metadata file."""
        stamps = (
            "20260101T000000Z",
            "20260102T000000Z",
            "20260103T000000Z",
            "20260104T000000Z",
        )
        for stamp in stamps:
            for name in ("meta.sqlite", IDENTITY_FILENAME):
                self.fake.objects[f"{PREFIX}/{BACKUP_DIRNAME}/{stamp}/{name}"] = b"old"
        self.manager_a._prune_backups(self.fake, f"{PREFIX}/")
        root = f"{PREFIX}/{BACKUP_DIRNAME}/"
        kept = sorted(key for key in self.fake.objects if key.startswith(root))
        self.assertEqual(len(kept), 2 * META_BACKUP_KEEP)
        self.assertIn(f"{root}20260104T000000Z/meta.sqlite", kept)
        self.assertNotIn(f"{root}20260101T000000Z/meta.sqlite", kept)

    def test_backup_folder_is_never_downloaded(self) -> None:
        """A backup object in the bucket is not pulled into the vault."""
        self.fake.objects[f"{PREFIX}/{BACKUP_DIRNAME}/20260101T000000Z/meta.sqlite"] = b"junk"
        self.manager_a.sync()
        self.assertFalse((self.home_a / BACKUP_DIRNAME).exists())

    def test_metadata_filenames_are_the_three_vault_files(self) -> None:
        """The guard covers exactly the vault metadata set."""
        self.assertEqual(
            set(METADATA_FILENAMES), {IDENTITY_FILENAME, "meta.sqlite", "secure.store"}
        )


class TransferTimeoutTest(unittest.TestCase):
    """Large uploads get a long socket timeout; small metadata calls stay snappy."""

    def test_small_bodies_keep_the_short_timeout(self) -> None:
        """Metadata requests must fail fast against a dead endpoint."""
        from vault.core.s3 import _READ_TIMEOUT, _UPLOAD_TIMEOUT, request_timeout

        self.assertEqual(request_timeout(None), _READ_TIMEOUT)
        self.assertEqual(request_timeout(b""), _READ_TIMEOUT)
        self.assertEqual(request_timeout(b"x" * (1 << 20)), _READ_TIMEOUT)
        self.assertLess(_READ_TIMEOUT, _UPLOAD_TIMEOUT)

    def test_large_bodies_get_the_upload_timeout(self) -> None:
        """secure.store (tens of MB) must not trip the 15-second write timeout."""
        from vault.core.s3 import _UPLOAD_TIMEOUT, request_timeout

        self.assertEqual(request_timeout(b"x" * ((1 << 20) + 1)), _UPLOAD_TIMEOUT)
        self.assertGreaterEqual(_UPLOAD_TIMEOUT, 120)


class ConfigTest(ImportTestBase):
    """The credentials an import uses are stored machine-locally."""

    def test_persist_sync_credentials_keeps_the_client_id(self) -> None:
        """Saving the credentials keeps the machine's lock identity."""
        from vault.config import load_sync_config

        before = load_sync_config().get("client_id")
        config = _config(access_key="new-key", secret_key="new-secret")
        path = remote_import.persist_sync_credentials(config)
        after = load_sync_config()
        self.assertEqual(after["access_key"], "new-key")
        self.assertEqual(after["secret_key"], "new-secret")
        self.assertEqual(after.get("client_id"), before)
        self.assertTrue(Path(path).is_file())


class RestoreDialogTest(unittest.TestCase):
    """The restore wizard and its background job (offscreen Qt)."""

    @classmethod
    def setUpClass(cls) -> None:
        """Bring up an offscreen QApplication once."""
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def test_dialog_prefills_and_validates(self) -> None:
        """Coordinates are pre-filled, missing keys are refused, replace is explicit."""
        from vault.ui.import_vault import ImportVaultDialog

        dialog = ImportVaultDialog(
            None,
            home=Path("/tmp/sv-vault"),
            credentials={
                "access_key": "saved-key",
                "secret_key": "saved-secret",
                "last_source": {
                    "bucket": "saved-bucket",
                    "prefix": "sync",
                    "endpoint": "https://example.invalid",
                    "region": "r1",
                },
            },
            existing_vault_id="a15b21da",
        )
        try:
            self.assertEqual(dialog.folder_edit.text(), str(Path("/tmp/sv-vault")))
            self.assertEqual(dialog.bucket_edit.text(), "saved-bucket")
            self.assertEqual(dialog.prefix_edit.text(), "sync")
            self.assertEqual(dialog.access_edit.text(), "saved-key")
            self.assertTrue(dialog.replace_check.isVisibleTo(dialog))

            # A missing key is refused with a visible message.
            dialog.secret_edit.setText("")
            self.assertIsNone(dialog.config())
            self.assertTrue(dialog.error_label.text())

            # With every field filled the config is complete.
            dialog.secret_edit.setText("saved-secret")
            config = dialog.config()
            self.assertIsNotNone(config)
            self.assertTrue(config.configured)
            self.assertEqual(config.bucket, "saved-bucket")

            # Replacing another vault needs the explicit tick.
            dialog._on_accept()
            self.assertTrue(dialog.error_label.text())
            dialog.replace_check.setChecked(True)
            dialog._on_accept()
            home, accepted, password, replace = dialog.values()
            self.assertEqual(home, Path("/tmp/sv-vault"))
            self.assertEqual(accepted.bucket, "saved-bucket")
            self.assertIsNone(password)
            self.assertTrue(replace)
        finally:
            dialog.close()

    def test_dialog_accepts_a_new_folder(self) -> None:
        """Without an existing vault the wizard needs no replace tick."""
        from vault.ui.import_vault import ImportVaultDialog

        dialog = ImportVaultDialog(
            None,
            home=Path("/tmp/sv-fresh"),
            credentials={"access_key": "k", "secret_key": "s"},
        )
        try:
            dialog.bucket_edit.setText("b")
            dialog._on_accept()
            self.assertEqual(dialog.error_label.text(), "")
            _home, config, _password, replace = dialog.values()
            self.assertEqual(config.bucket, "b")
            self.assertFalse(replace)
        finally:
            dialog.close()

    def test_progress_and_size_helpers(self) -> None:
        """The progress/format helpers render for both phases and sizes."""
        from vault.ui.import_vault import megabytes, progress_text

        self.assertEqual(megabytes(2 * 1024 * 1024), "2.0")
        self.assertEqual(megabytes(0), "0.0")
        for phase in ("probe", "files", "index", "store", "install", "done"):
            text = progress_text(phase, 1, 4)
            self.assertTrue(text and not text.startswith("\u27e6"), phase)
        self.assertNotEqual(progress_text("files", 1, 4), progress_text("probe", 1, 4))

    def test_job_returns_the_result_and_records_progress(self) -> None:
        """The background job hands the value back without touching Qt."""
        from vault.ui.import_vault import ImportJob

        holder: dict[str, Any] = {}

        def work(state: dict[str, Any], cancel: Any) -> str:
            holder["job"].report("files", 3, 3)
            return "restored"

        job = ImportJob(work)
        holder["job"] = job
        job.start()
        job.pump(self.app)
        self.assertEqual(job.state["result"], "restored")
        self.assertEqual((job.state["phase"], job.state["done"], job.state["total"]), ("files", 3, 3))
        self.assertIsNone(job.state["error"])

    def test_job_reports_failures(self) -> None:
        """An exception inside the worker is captured, never raised in the GUI thread."""
        from vault.ui.import_vault import ImportJob

        def work(state: dict[str, Any], cancel: Any) -> None:
            raise RuntimeError("boom")

        job = ImportJob(work)
        job.start()
        job.pump(self.app)
        self.assertIsInstance(job.state["error"], RuntimeError)
        self.assertIsNone(job.state["result"])


class CliTest(ImportTestBase):
    """The headless entry point (``secure-vault-import``)."""

    def _run(self, argv: list[str]) -> tuple[int, str]:
        """Run the CLI with the fake bucket patched in and capture its stdout."""
        buffer = io.StringIO()
        # stdin is patched so the CLI never blocks on the master-password prompt; both
        # streams are captured because failures are reported on stderr.
        with mock.patch.object(import_cli, "S3Client", lambda config: self.fake):
            with mock.patch("sys.stdin", io.StringIO("")):
                with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
                    code = import_cli.main(argv)
        return code, buffer.getvalue()

    def _base_args(self) -> list[str]:
        """Common arguments for the fake bucket."""
        return [
            "--bucket", "test-bucket",
            "--prefix", PREFIX,
            "--access-key", "test-key",
            "--secret-key", "test-secret",
        ]

    def test_check_reports_the_bucket_vault(self) -> None:
        """``--check`` describes the vault and writes nothing."""
        code, out = self._run([*self._base_args(), "--check", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["vault_id"], self.vault_a.meta.vault_id)
        self.assertEqual(payload["files"], len(FILES))
        self.assertFalse(self.destination().exists())

    def test_cli_restores_the_vault(self) -> None:
        """The CLI restores the vault into the requested folder."""
        home = self.destination()
        code, out = self._run([*self._base_args(), "--home", str(home)])
        self.assertEqual(code, 0, out)
        self.assertIn("restored", out)
        self.assertTrue((home / IDENTITY_FILENAME).is_file())
        session = VaultSession(home)
        session.unlock(PASSWORD)
        self.extra = session
        self.assertEqual(session.read_file("notes/alpha.md"), FILES["notes/alpha.md"])

    def test_cli_refuses_another_vault_without_replace(self) -> None:
        """A different vault in the folder is refused (exit 1) unless ``--replace``."""
        other = self.fresh_vault()
        home = Path(other.home)
        code, out = self._run([*self._base_args(), "--home", str(home)])
        self.assertEqual(code, 1)
        self.assertIn("vault_exists", out)
        self.assertEqual(VaultSession(home).meta.vault_id, other.meta.vault_id)

    def test_cli_reports_a_bad_bucket(self) -> None:
        """An empty prefix exits non-zero with the reason."""
        code, out = self._run(["--bucket", "test-bucket", "--prefix", "nowhere"])
        self.assertEqual(code, 1)
        self.assertIn("remote_bucket_empty", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
