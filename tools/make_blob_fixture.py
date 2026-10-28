#!/usr/bin/env python3
"""Vectors proving the Android client seals blobs exactly like the desktop.

    PYTHONPATH=src ./.venv/bin/python tools/make_blob_fixture.py --android /data/Codes/secure-vault-android

The desktop's own ``encrypt_blob`` produces each vector with a **fixed** salt and nonce (randomness is
patched for the run), so AES-256-GCM is deterministic and the Kotlin side can be compared byte for
byte. A second device that sealed bytes differently would produce blobs nobody else could read.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vault.core import crypto  # noqa: E402

MASTER_KEY = bytes(range(32))
CASES = [
    # name, blob id, sensitivity, payload, plain
    ("normal_note", "b7a1c3d5e7f90123", "normal", b"# title\nbody text", False),
    ("secretfile_entry", "0123456789abcdef", "secretfile", b"password: hunter2", False),
    ("empty_payload", "fedcba9876543210", "normal", b"", False),
    ("persian_utf8", "0011223344556677", "secret", "یادداشت فارسی".encode("utf-8"), False),
    ("plain_large", "89abcdef01234567", "normal", b"x" * 64, True),
]


def _fixed_random() -> bytes:
    """A deterministic stand-in for ``os.urandom`` (salt then nonce, per call)."""
    counter = {"n": 0}

    def take(size: int) -> bytes:
        start = counter["n"]
        counter["n"] += size
        return bytes((start + index * 7) % 256 for index in range(size))

    return take


def main(argv: list[str] | None = None) -> int:
    """Write the blob vectors and (optionally) copy them into the Android tests."""
    parser = argparse.ArgumentParser(description="Generate blob-format parity vectors.")
    parser.add_argument("--android", help="Android repo to copy the fixture into")
    args = parser.parse_args(argv)

    import os as _os

    original = crypto.os.urandom
    vectors = []
    try:
        for name, blob_id, sensitivity, payload, plain in CASES:
            crypto.os.urandom = _fixed_random()
            blob = crypto.encrypt_blob(
                MASTER_KEY, blob_id, payload, sensitivity=sensitivity, plain=plain
            )
            header = crypto.decrypt_blob(MASTER_KEY, blob_id, blob, sensitivity=sensitivity)
            assert header == payload, name
            vectors.append(
                {
                    "name": name,
                    "master_key_b64": base64.b64encode(MASTER_KEY).decode(),
                    "blob_id": blob_id,
                    "sensitivity": sensitivity,
                    "plain": plain,
                    "data_b64": base64.b64encode(payload).decode(),
                    "blob_b64": base64.b64encode(blob).decode(),
                }
            )
    finally:
        crypto.os.urandom = original

    text = json.dumps({"generated_by": "secure-vault/tools/make_blob_fixture.py", "cases": vectors},
                      indent=2) + "\n"
    local = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "blob_vectors.json"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(text, encoding="utf-8")
    print(f"wrote {len(vectors)} vectors → {local}")
    if args.android:
        target = Path(args.android) / "app/src/test/resources/fixture/blob_vectors.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        print(f"copied → {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
