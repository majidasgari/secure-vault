"""Real-mirror importer verification (opt-in; skipped unless it is explicitly enabled).

``tests/invariants_source_p4.py`` imports the user's *real* Joplin mirror
(``/data/Cloud/Documents/Notes/joplin-mirror``) into a throw-away vault and checks counts,
fidelity, idempotency, encryption-at-rest and that the mirror is never modified. It is slow
and depends on the user's data, so it only runs when ``SECURE_VAULT_REAL_MIRROR=1`` is set
(see docs/TESTING.md). The fixture-based suite (``test_importers.py``) is the always-on one.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(__file__).resolve().parent / "invariants_source_p4.py"
MIRROR = Path("/data/Cloud/Documents/Notes/joplin-mirror")


@unittest.skipUnless(
    os.environ.get("SECURE_VAULT_REAL_MIRROR") == "1",
    "set SECURE_VAULT_REAL_MIRROR=1 to run against the real Joplin mirror",
)
class RealMirrorImportTest(unittest.TestCase):
    """The importer must survive the real corpus without touching the source."""

    def setUp(self) -> None:
        """Skip when the mirror is not present on this machine."""
        if not MIRROR.is_dir():
            self.skipTest(f"mirror not found at {MIRROR}")

    def test_real_mirror_import(self) -> None:
        """Run the verifier; it exits non-zero when any check fails."""
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if proc.returncode != 0:
            tail = "\n".join((proc.stdout or "").splitlines()[-60:])
            self.fail(
                f"invariants_source_p4.py exited {proc.returncode}\n{tail}\n"
                f"--- stderr ---\n{(proc.stderr or '')[-2000:]}"
            )
        self.assertIn("0 failed", proc.stdout or "")


if __name__ == "__main__":  # pragma: no cover - manual run
    unittest.main()
