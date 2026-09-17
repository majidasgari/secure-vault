"""Tests for vault.core.meta (SPEC/06 §2 test_meta)."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from vault.core.crypto import HEADER_SIZE
from vault.core.meta import META_FILENAME, VaultMeta
from vault.errors import BadRequest, NotFound


class VaultMetaTest(unittest.TestCase):
    """Creation, loading, validation and settings persistence."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="sv-meta-"))
        self.path = self.tmp / META_FILENAME

    def test_create_and_load(self) -> None:
        """A created file loads back with the same vault id."""
        meta = VaultMeta.create(self.path, "pw")
        self.assertTrue(self.path.exists())
        loaded = VaultMeta.load(self.path)
        self.assertEqual(loaded.vault_id, meta.vault_id)
        self.assertEqual(loaded.data["schema_version"], 1)

    def test_atomic_save_leaves_no_tmp(self) -> None:
        """save() leaves no .tmp files behind."""
        meta = VaultMeta.create(self.path, "pw")
        meta.save()
        self.assertEqual(list(self.tmp.glob("*.tmp")), [])

    def test_schema_too_new_is_bad_request(self) -> None:
        """A future schema version is rejected with BadRequest."""
        meta = VaultMeta.create(self.path, "pw")
        meta.data["schema_version"] = 2
        meta.save()
        with self.assertRaises(BadRequest):
            VaultMeta.load(self.path)

    def test_missing_file_is_not_found(self) -> None:
        """A missing metadata file is NotFound('vault_not_initialised')."""
        with self.assertRaises(NotFound) as ctx:
            VaultMeta.load(self.path)
        self.assertEqual(ctx.exception.message, "vault_not_initialised")

    def test_invalid_file_is_not_found(self) -> None:
        """Invalid JSON is reported as an uninitialised vault."""
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(NotFound):
            VaultMeta.load(self.path)
        self.path.write_text("[1, 2, 3]", encoding="utf-8")
        with self.assertRaises(NotFound):
            VaultMeta.load(self.path)

    def test_settings_mutation_persists(self) -> None:
        """Mutating settings and saving round-trips."""
        meta = VaultMeta.create(self.path, "pw")
        meta.settings["auto_lock_seconds"] = 123
        meta.settings["semantic"]["enabled"] = True
        meta.save()
        loaded = VaultMeta.load(self.path)
        self.assertEqual(loaded.settings["auto_lock_seconds"], 123)
        self.assertTrue(loaded.settings["semantic"]["enabled"])

    def test_default_settings_match_spec(self) -> None:
        """Default settings carry the documented values."""
        meta = VaultMeta.create(self.path, "pw")
        settings = meta.settings
        self.assertEqual(settings["plain_threshold_bytes"], 10 * 1024 * 1024)
        self.assertEqual(settings["auto_lock_seconds"], 900)
        self.assertEqual(settings["default_sensitivity"], "normal")
        self.assertEqual(settings["semantic"]["model"], "all-MiniLM-L6-v2")
        self.assertEqual(
            settings["import_joplin"]["mirror_root"],
            "/data/Cloud/Documents/Notes/joplin-mirror",
        )

    def test_canary_present_and_sized(self) -> None:
        """The canary is present, base64 decodes and has a real payload."""
        meta = VaultMeta.create(self.path, "pw")
        canary = base64.b64decode(meta.data["canary_b64"])
        self.assertGreater(len(canary), HEADER_SIZE)
        self.assertTrue(meta.verify_password("pw"))
        self.assertFalse(meta.verify_password("wrong"))

    def test_kdf_params_round_trip(self) -> None:
        """KDF parameters survive a save/load cycle."""
        meta = VaultMeta.create(self.path, "pw")
        params = meta.kdf_params()
        loaded = VaultMeta.load(self.path).kdf_params()
        self.assertEqual(params, loaded)
        self.assertEqual(len(params.salt), 16)

    def test_rekey_not_implemented(self) -> None:
        """rekey is explicitly out of scope for P1."""
        meta = VaultMeta.create(self.path, "pw")
        with self.assertRaises(NotImplementedError):
            meta.rekey("new")


if __name__ == "__main__":
    unittest.main()
