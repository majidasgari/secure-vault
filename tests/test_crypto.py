"""Tests for vault.core.crypto (SPEC/06 §2 test_crypto)."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from vault.core import crypto
from vault.errors import TamperDetected
from vault.util import wipe


class CryptoTest(unittest.TestCase):
    """Blob format, key derivation, canary and hygiene."""

    def setUp(self) -> None:
        self.params = crypto.new_kdf_params()
        self.master = crypto.derive_master_key("correct horse", self.params)

    def test_round_trip_sizes(self) -> None:
        """Round-trip payloads of 0, 1, 1 KB and 5 MB."""
        for size in (0, 1, 1024, 5 * 1024 * 1024):
            data = os.urandom(size)
            blob = crypto.encrypt_blob(self.master, "blob-1", data, sensitivity="normal")
            self.assertEqual(
                crypto.decrypt_blob(self.master, "blob-1", blob, sensitivity="normal"),
                data,
                msg=f"size {size}",
            )

    def test_wrong_password_raises_tamper(self) -> None:
        """A different derived key cannot decrypt the blob."""
        other = crypto.derive_master_key("wrong password", self.params)
        blob = crypto.encrypt_blob(self.master, "blob-1", b"payload", sensitivity="normal")
        with self.assertRaises(TamperDetected):
            crypto.decrypt_blob(other, "blob-1", blob, sensitivity="normal")

    def test_bit_flip_anywhere_detected(self) -> None:
        """Flipping any byte of an encrypted blob is detected."""
        data = os.urandom(64)
        blob = crypto.encrypt_blob(self.master, "blob-1", data, sensitivity="normal")
        for index in range(len(blob)):
            corrupted = bytearray(blob)
            corrupted[index] ^= 0x01
            with self.assertRaises(TamperDetected, msg=f"byte {index}"):
                crypto.decrypt_blob(
                    self.master, "blob-1", bytes(corrupted), sensitivity="normal"
                )

    def test_blob_id_mismatch(self) -> None:
        """AAD binds the blob id: decrypting under another id fails."""
        blob = crypto.encrypt_blob(self.master, "blob-a", b"payload", sensitivity="normal")
        with self.assertRaises(TamperDetected):
            crypto.decrypt_blob(self.master, "blob-b", blob, sensitivity="normal")

    def test_sensitivity_mismatch(self) -> None:
        """AAD binds the sensitivity level."""
        blob = crypto.encrypt_blob(self.master, "blob-a", b"payload", sensitivity="secret")
        with self.assertRaises(TamperDetected):
            crypto.decrypt_blob(self.master, "blob-a", blob, sensitivity="normal")

    def test_plain_blob_round_trip_and_header(self) -> None:
        """Plain blobs carry the header and authenticate it."""
        blob = crypto.encrypt_blob(
            self.master, "blob-a", b"plain-payload", sensitivity="normal", plain=True
        )
        self.assertEqual(blob[:4], crypto.MAGIC)
        self.assertEqual(blob[4], crypto.FORMAT_VERSION)
        self.assertTrue(crypto.is_plain_blob(blob))
        self.assertEqual(
            crypto.decrypt_blob(self.master, "blob-a", blob, sensitivity="normal"),
            b"plain-payload",
        )
        for index in range(crypto.HEADER_SIZE):
            corrupted = bytearray(blob)
            corrupted[index] ^= 0x01
            with self.assertRaises(TamperDetected, msg=f"header byte {index}"):
                crypto.decrypt_blob(
                    self.master, "blob-a", bytes(corrupted), sensitivity="normal"
                )

    def test_truncated_and_garbage_input(self) -> None:
        """Short or malformed input never leaks a raw exception."""
        samples = [
            b"",
            b"S",
            b"SVLT",
            os.urandom(10),
            crypto.MAGIC + bytes(10),
            b"XXXX" + bytes(40),
        ]
        for sample in samples:
            with self.assertRaises(TamperDetected, msg=repr(sample)):
                crypto.decrypt_blob(self.master, "blob-a", sample, sensitivity="normal")

    def test_canary_accepts_right_and_rejects_wrong(self) -> None:
        """Canary verification is a boolean and never raises."""
        canary = crypto.make_canary(self.master)
        self.assertTrue(crypto.check_canary(self.master, canary))
        other = crypto.derive_master_key("nope", self.params)
        self.assertFalse(crypto.check_canary(other, canary))
        self.assertFalse(crypto.check_canary(self.master, b"garbage"))
        self.assertFalse(crypto.check_canary(self.master, canary[:-1]))

    def test_new_kdf_params_uses_available_kdf(self) -> None:
        """new_kdf_params() matches available_kdf()."""
        params = crypto.new_kdf_params()
        self.assertEqual(params.algo, crypto.available_kdf())
        if crypto.available_kdf() == "argon2id":
            self.assertEqual(params.time_cost, crypto.ARGON2_TIME_COST)
            self.assertEqual(params.memory_kib, crypto.ARGON2_MEMORY_KIB)

    def test_pbkdf2_path_round_trips(self) -> None:
        """The PBKDF2 fallback also derives and round-trips."""
        params = crypto.KdfParams(
            algo="pbkdf2-sha512",
            salt=os.urandom(16),
            time_cost=0,
            memory_kib=0,
            parallelism=0,
            iterations=10000,
        )
        master = crypto.derive_master_key("pw", params)
        blob = crypto.encrypt_blob(
            master, "b", b"data", sensitivity="normal", kdf_id=crypto.KDF_PBKDF2
        )
        self.assertEqual(crypto.decrypt_blob(master, "b", blob, sensitivity="normal"), b"data")

    def test_available_kdf_monkeypatched(self) -> None:
        """Monkeypatching available_kdf() selects the PBKDF2 branch."""
        with mock.patch.object(crypto, "available_kdf", return_value="pbkdf2-sha512"):
            params = crypto.new_kdf_params()
        self.assertEqual(params.algo, "pbkdf2-sha512")
        self.assertEqual(params.iterations, crypto.PBKDF2_ITERATIONS)

    def test_different_salts_give_different_keys(self) -> None:
        """Two fresh parameter sets yield different salts and keys."""
        first = crypto.new_kdf_params()
        second = crypto.new_kdf_params()
        self.assertNotEqual(first.salt, second.salt)
        self.assertNotEqual(
            bytes(crypto.derive_master_key("pw", first)),
            bytes(crypto.derive_master_key("pw", second)),
        )

    def test_file_keys_differ_per_blob(self) -> None:
        """HKDF derives a distinct key per blob id."""
        salt = os.urandom(16)
        first = crypto.derive_file_key(self.master, "blob-a", salt)
        second = crypto.derive_file_key(self.master, "blob-b", salt)
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), crypto.KEY_SIZE)

    def test_wipe_zeroes(self) -> None:
        """wipe() overwrites every byte."""
        buffer = bytearray(b"top secret")
        wipe(buffer)
        self.assertEqual(bytes(buffer), bytes(len(buffer)))


if __name__ == "__main__":
    unittest.main()
