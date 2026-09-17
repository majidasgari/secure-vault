"""Run the orchestrator's headless UI verification as part of the suite."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(__file__).resolve().parent / "invariants_source_p3.py"

try:  # the verifier needs PySide6; skip cleanly when it is absent
    import PySide6  # noqa: F401

    HAVE_QT = True
except ImportError:  # pragma: no cover
    HAVE_QT = False


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class UiInvariants(unittest.TestCase):
    """The UI must honour every rule in the verifier script (offscreen)."""

    def test_black_box_ui_invariants(self) -> None:
        """Run the verifier; it exits non-zero when any check fails."""
        env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=900,
            env=env,
        )
        if proc.returncode != 0:
            tail = "\n".join((proc.stdout or "").splitlines()[-60:])
            self.fail(
                f"invariants_source_p3.py exited {proc.returncode}\n{tail}\n"
                f"--- stderr ---\n{(proc.stderr or '')[-2000:]}"
            )
        self.assertIn("0 failed", proc.stdout or "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
