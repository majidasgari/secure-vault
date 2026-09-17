"""Shared test helpers (SPEC/06 §1).

Only the phase-P1 helpers are implemented here. The socket/MCP helpers
(``fake_daemon``/``mcp_stdio``) belong to phase P2 and are intentionally absent.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

from vault.core.session import VaultSession
from vault.core.store import SecureStore
from vault.core.vaultfs import VaultFS

DEFAULT_PASSWORD = "correct horse battery staple"


def scratch_home(tmpdir: Path | str | None = None) -> Path:
    """Return a fresh scratch directory, never the user's real vault home."""
    if tmpdir is not None:
        base = Path(tmpdir) / f"scratch-{uuid.uuid4().hex[:8]}"
        base.mkdir(parents=True, exist_ok=True)
        return base
    return Path(tempfile.mkdtemp(prefix="sv-scratch-"))


def tmp_vault(
    tmpdir: Path | str | None = None,
    *,
    password: str = DEFAULT_PASSWORD,
    settings: dict | None = None,
    plain_threshold: int | None = None,
) -> VaultSession:
    """Create an unlocked vault in a scratch directory and return its session."""
    base = scratch_home(tmpdir)
    home = base / "vault"
    runtime = base / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    os.chmod(runtime, 0o700)
    session = VaultSession.create(home, password, settings=settings)
    session._runtime = runtime
    if session._store is not None:
        master_key = session._master_key
        session._store.close()
        session._store = SecureStore.open(home, master_key, runtime)
    if plain_threshold is not None:
        session._plain_threshold_override = plain_threshold
        session._fs = VaultFS(
            home, session._index, session._master_key, plain_threshold=plain_threshold
        )
    return session


def assert_no_plaintext(root: Path | str, needles: list[bytes]) -> None:
    """Assert none of ``needles`` appear in any file under ``root``."""
    root = Path(root)
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:  # pragma: no cover - transient files
            continue
        for needle in needles:
            if needle and needle in data:
                raise AssertionError(f"plaintext {needle!r} found in {path}")


def assert_under(path: Path | str, root: Path | str) -> None:
    """Assert ``path`` resolves to a location inside ``root``."""
    resolved = Path(path).resolve()
    root_resolved = Path(root).resolve()
    if root_resolved != resolved and root_resolved not in resolved.parents:
        raise AssertionError(f"{resolved} is not under {root_resolved}")


__all__ = [
    "DEFAULT_PASSWORD",
    "scratch_home",
    "tmp_vault",
    "assert_no_plaintext",
    "assert_under",
]
