"""Run the orchestrator's black-box interface verification as part of the suite.

``tests/invariants_source_p2.py`` drives the real headless daemon over its Unix socket and
the real MCP stdio bridge in subprocesses, which is deliberately not in-process: those are
the guarantees an agent-facing client actually depends on. This wrapper fails the suite when
any of its checks fail, and prints the script's own output when it does.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(__file__).resolve().parent / "invariants_source_p2.py"


class ApiInvariants(unittest.TestCase):
    """The daemon/MCP bridge must honour every invariant in the verifier script."""

    def test_black_box_api_and_mcp_invariants(self) -> None:
        """Run the verifier; it exits non-zero when any check fails."""
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=900,
        )
        if proc.returncode != 0:
            tail = "\n".join((proc.stdout or "").splitlines()[-60:])
            self.fail(
                f"invariants_source_p2.py exited {proc.returncode}\n{tail}\n"
                f"--- stderr ---\n{(proc.stderr or '')[-2000:]}"
            )
        self.assertIn("0 failed", proc.stdout or "")


if __name__ == "__main__":  # pragma: no cover - manual run
    unittest.main()
