"""Blob encryption and key derivation (SPEC/01 §4).

Blob format (all integers big-endian)::

    offset  size  field
    0       4     magic  b"SVLT"
    4       1     format version = 1
    5       1     kdf id   (1 = argon2id, 2 = pbkdf2-sha512)
    6       1     flags    (bit0 = plain, reserved bits 0)
    7       1     reserved = 0
    8       16    per-file salt (HKDF salt; random; unused when flags.plain)
    24      12    nonce (unused when plain)
    36      ...   ciphertext||tag (or the raw bytes when plain)
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import NamedTuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from ..errors import ProviderUnavailable, TamperDetected

try:  # pragma: no cover - import availability is environment dependent
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_hash

    _HAVE_ARGON2 = True
except ImportError:  # pragma: no cover
    _HAVE_ARGON2 = False

MAGIC = b"SVLT"
FORMAT_VERSION = 1
HEADER_SIZE = 36
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

KDF_ARGON2ID = 1
KDF_PBKDF2 = 2

ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 262144
ARGON2_PARALLELISM = 4
PBKDF2_ITERATIONS = 600000

_CANARY_BLOB_ID = "canary"
_CANARY_PLAINTEXT = b"secure-vault"


class KdfParams(NamedTuple):
    """Key-derivation parameters persisted in ``.vault-meta.json``."""

    algo: str
    salt: bytes
    time_cost: int
    memory_kib: int
    parallelism: int
    iterations: int


def available_kdf() -> str:
    """Return ``"argon2id"`` when argon2-cffi is importable, else ``"pbkdf2-sha512"``."""
    return "argon2id" if _HAVE_ARGON2 else "pbkdf2-sha512"


def new_kdf_params() -> KdfParams:
    """Generate fresh KDF parameters for a new vault using the available KDF."""
    salt = os.urandom(SALT_SIZE)
    if available_kdf() == "argon2id":
        return KdfParams(
            algo="argon2id",
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_kib=ARGON2_MEMORY_KIB,
            parallelism=ARGON2_PARALLELISM,
            iterations=PBKDF2_ITERATIONS,
        )
    return KdfParams(
        algo="pbkdf2-sha512",
        salt=salt,
        time_cost=0,
        memory_kib=0,
        parallelism=0,
        iterations=PBKDF2_ITERATIONS,
    )


def derive_master_key(password: str, params: KdfParams) -> bytearray:
    """Derive the 32-byte master key from ``password`` and ``params``.

    Raises:
        ProviderUnavailable: if the params request argon2id but argon2-cffi is missing.
    """
    if params.algo == "argon2id":
        if not _HAVE_ARGON2:  # pragma: no cover - environment dependent
            raise ProviderUnavailable(
                "argon2id_not_available",
                details={"hint": "install argon2-cffi or re-create the vault"},
            )
        raw = _argon2_hash(
            password.encode("utf-8"),
            params.salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_kib,
            parallelism=params.parallelism,
            hash_len=KEY_SIZE,
            type=_Argon2Type.ID,
        )
    else:
        raw = hashlib.pbkdf2_hmac(
            "sha512",
            password.encode("utf-8"),
            params.salt,
            params.iterations,
            dklen=KEY_SIZE,
        )
    return bytearray(raw)


def derive_file_key(master_key: bytes, blob_id: str, salt: bytes) -> bytes:
    """Derive a per-blob AES key via HKDF-SHA256 bound to ``blob_id`` and ``salt``."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=b"secure-vault/file/" + blob_id.encode("utf-8"),
    )
    return hkdf.derive(bytes(master_key))


def _aad(blob_id: str, sensitivity: str) -> bytes:
    """Build the additional authenticated data binding blob id and sensitivity."""
    return b"sv/" + blob_id.encode("utf-8") + b"/" + sensitivity.encode("utf-8")


def _plain_mac(master_key: bytes, header_prefix: bytes, nonce: bytes, aad: bytes) -> bytes:
    """Keyed MAC stored in the salt field of a plain blob.

    Plain payloads carry no AEAD tag, so the header itself is authenticated with an
    HMAC-SHA256 (truncated to the 16-byte salt field). This makes a bit flip anywhere in
    a plain header detectable while keeping the documented header layout.
    """
    mac = hmac.new(
        bytes(master_key), header_prefix + nonce + aad, hashlib.sha256
    ).digest()
    return mac[:SALT_SIZE]


def encrypt_blob(
    master_key: bytes,
    blob_id: str,
    data: bytes,
    *,
    sensitivity: str,
    plain: bool = False,
    kdf_id: int = KDF_ARGON2ID,
) -> bytes:
    """Encrypt ``data`` into a self-describing blob.

    When ``plain`` is true the payload is stored unencrypted but the header (and the
    ``flags.plain`` bit) is still written. ``sensitivity`` and ``blob_id`` are bound as
    AEAD associated data, so decrypting with either changed raises :class:`TamperDetected`.
    """
    flags = 0x01 if plain else 0x00
    header_prefix = MAGIC + bytes([FORMAT_VERSION, kdf_id, flags, 0])
    aad = _aad(blob_id, sensitivity)
    if plain:
        nonce = bytes(NONCE_SIZE)
        salt = _plain_mac(master_key, header_prefix, nonce, aad)
        payload = bytes(data)
    else:
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = derive_file_key(master_key, blob_id, salt)
        payload = AESGCM(key).encrypt(nonce, bytes(data), aad)
    return header_prefix + salt + nonce + payload


def decrypt_blob(
    master_key: bytes,
    blob_id: str,
    blob: bytes,
    *,
    sensitivity: str,
) -> bytes:
    """Decrypt a blob produced by :func:`encrypt_blob`.

    Raises:
        TamperDetected: on malformed/truncated headers, wrong version, unsupported flags,
            authentication failure, or a mismatched ``blob_id``/``sensitivity``.
    """
    try:
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise ValueError("blob_not_bytes")
        raw = bytes(blob)
        if len(raw) < HEADER_SIZE:
            raise ValueError("blob_truncated")
        if raw[:4] != MAGIC:
            raise ValueError("bad_magic")
        version = raw[4]
        kdf_id = raw[5]
        flags = raw[6]
        reserved = raw[7]
        if version != FORMAT_VERSION:
            raise ValueError("unsupported_version")
        if kdf_id not in (KDF_ARGON2ID, KDF_PBKDF2):
            raise ValueError("unsupported_kdf")
        if reserved != 0 or (flags & ~0x01):
            raise ValueError("unsupported_flags")
        salt = raw[8 : 8 + SALT_SIZE]
        nonce = raw[8 + SALT_SIZE : HEADER_SIZE]
        payload = raw[HEADER_SIZE:]
        aad = _aad(blob_id, sensitivity)
        if flags & 0x01:
            expected = _plain_mac(master_key, raw[:8], nonce, aad)
            if not hmac.compare_digest(salt, expected):
                raise ValueError("plain_header_mac_mismatch")
            return payload
        key = derive_file_key(master_key, blob_id, salt)
        return AESGCM(key).decrypt(nonce, payload, aad)
    except TamperDetected:
        raise
    except Exception as exc:  # noqa: BLE001 - any failure means tampering/truncation
        raise TamperDetected("blob_authentication_failed", details={"reason": str(exc)}) from exc


def is_plain_blob(blob: bytes) -> bool:
    """Return True when ``blob`` is a well-formed blob with the plain flag set."""
    try:
        raw = bytes(blob)
    except Exception:  # noqa: BLE001
        return False
    if len(raw) < HEADER_SIZE or raw[:4] != MAGIC:
        return False
    return bool(raw[6] & 0x01)


def make_canary(master_key: bytes) -> bytes:
    """Create the password-verification canary for ``master_key``."""
    return encrypt_blob(
        master_key,
        _CANARY_BLOB_ID,
        _CANARY_PLAINTEXT,
        sensitivity="normal",
    )


def check_canary(master_key: bytes, canary: bytes) -> bool:
    """Return True iff ``canary`` decrypts to the expected value; never raises."""
    try:
        return decrypt_blob(
            master_key, _CANARY_BLOB_ID, canary, sensitivity="normal"
        ) == _CANARY_PLAINTEXT
    except Exception:  # noqa: BLE001 - callers only need a boolean
        return False


__all__ = [
    "KdfParams",
    "available_kdf",
    "new_kdf_params",
    "derive_master_key",
    "derive_file_key",
    "encrypt_blob",
    "decrypt_blob",
    "is_plain_blob",
    "make_canary",
    "check_canary",
    "MAGIC",
    "FORMAT_VERSION",
    "HEADER_SIZE",
]
