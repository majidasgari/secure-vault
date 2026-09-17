"""Tests for vault.core.vaultfs (SPEC/06 §2 test_vaultfs)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vault.core import crypto
from vault.core.index import Index
from vault.core.vaultfs import VaultFS
from vault.errors import VaultLocked


class VaultFSTest(unittest.TestCase):
    """Blob storage lifecycle and integrity."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="sv-fs-"))
        self.home = self.tmp / "vault"
        self.home.mkdir()
        self.index = Index(self.home / "meta.sqlite")
        params = crypto.new_kdf_params()
        self.master = crypto.derive_master_key("pw", params)
        self.fs = VaultFS(
            self.home, self.index, self.master, plain_threshold=10 * 1024 * 1024
        )

    def tearDown(self) -> None:
        self.index.close()

    def _put(self, path: str, data: bytes, sensitivity: str = "normal") -> dict:
        """Write a blob and register it in the index."""
        blob_id, size, encrypted = self.fs.write_blob(data, sensitivity=sensitivity)
        self.index.upsert_file(
            path,
            blob_id=blob_id,
            size=size,
            encrypted=encrypted,
            sensitivity=sensitivity,
        )
        return self.index.require_file(path)

    def test_write_read_update_delete(self) -> None:
        """Write, read, replace and delete blobs."""
        row = self._put("a", b"hello")
        self.assertEqual(self.fs.read_bytes(row), b"hello")
        old_id = row["blob_id"]
        self.fs.delete_blob(old_id)
        self.assertFalse(self.fs.blob_path(old_id).exists())

    def test_update_replaces_blob_and_removes_old(self) -> None:
        """Replacing content deletes the previous blob once the row is updated."""
        row = self._put("a", b"one")
        old_id = row["blob_id"]
        new_id, size, encrypted = self.fs.write_blob(b"two", sensitivity="normal")
        self.index.upsert_file("a", blob_id=new_id, size=size, encrypted=encrypted)
        self.fs.delete_blob(old_id)
        self.assertFalse(self.fs.blob_path(old_id).exists())
        self.assertTrue(self.fs.blob_path(new_id).exists())
        self.assertEqual(self.fs.read_bytes(self.index.require_file("a")), b"two")

    def test_gc_orphans(self) -> None:
        """gc_orphans deletes exactly the unreferenced blobs."""
        kept = self._put("a", b"keep")
        orphan_id, _, _ = self.fs.write_blob(b"orphan", sensitivity="normal")
        self.assertEqual(self.fs.gc_orphans(), 1)
        self.assertFalse(self.fs.blob_path(orphan_id).exists())
        self.assertTrue(self.fs.blob_path(kept["blob_id"]).exists())

    def test_plain_threshold(self) -> None:
        """Files strictly larger than the threshold are stored plain."""
        fs = VaultFS(self.home, self.index, self.master, plain_threshold=4)
        plain_id, size, plain_encrypted = fs.write_blob(b"0123456789", sensitivity="normal")
        self.assertEqual(plain_encrypted, 0)
        self.index.upsert_file("plain", blob_id=plain_id, size=size, encrypted=plain_encrypted)
        self.assertEqual(self.index.require_file("plain")["encrypted"], 0)
        self.assertTrue(crypto.is_plain_blob(fs.blob_path(plain_id).read_bytes()))
        exact_id, _, exact_encrypted = fs.write_blob(b"0123", sensitivity="normal")
        self.assertEqual(exact_encrypted, 1)
        self.assertFalse(crypto.is_plain_blob(fs.blob_path(exact_id).read_bytes()))

    def test_locked_read_raises(self) -> None:
        """Reading a blob with no master key raises VaultLocked."""
        row = self._put("a", b"secret")
        self.fs.master_key = None
        with self.assertRaises(VaultLocked):
            self.fs.read_bytes(row)

    def test_verify_blob_detects_corruption(self) -> None:
        """verify_blob returns False for a corrupted blob."""
        row = self._put("a", b"hello")
        self.assertTrue(self.fs.verify_blob(row))
        path = self.fs.blob_path(row["blob_id"])
        data = bytearray(path.read_bytes())
        data[-1] ^= 0x01
        path.write_bytes(bytes(data))
        self.assertFalse(self.fs.verify_blob(row))


if __name__ == "__main__":
    unittest.main()
