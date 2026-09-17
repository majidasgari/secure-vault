#!/usr/bin/env python3
"""End-to-end smoke test for the vault core (SPEC/06 §3).

Creates a scratch vault, exercises the full lifecycle — create, unlock, write notes,
the three searches, a secret-file request, lock, proof that content is unreachable,
unlock and blob verification — then prints the vault tree and the access-log summary.
Prints ``PASS``/``FAIL`` per step and exits non-zero on any failure.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from vault.core import semantics  # noqa: E402
from vault.core.session import VaultSession  # noqa: E402
from vault.errors import VaultLocked  # noqa: E402

PASSWORD = "smoke-e2e-password"
PASS = "PASS"
FAIL = "FAIL"
_failures = 0
_state: dict[str, Any] = {}


def step(name: str, fn: Callable[[], None]) -> None:
    """Run one named step, print its result and remember failures."""
    global _failures
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - smoke reporting
        _failures += 1
        print(f"{FAIL}  {name}: {type(exc).__name__}: {exc}")
    else:
        print(f"{PASS}  {name}")


def main() -> int:
    """Run every smoke step and return the exit code."""
    scratch = Path(tempfile.mkdtemp(prefix="sv-smoke-e2e-"))
    home = scratch / "vault"
    runtime = scratch / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    os.chmod(runtime, 0o700)
    previous_xdg = os.environ.get("XDG_RUNTIME_DIR")
    os.environ["XDG_RUNTIME_DIR"] = str(runtime)

    persian_body = "سلام دنیا\n\nکتاب روی میز است\n"
    attachment_body = "# Attachment note\n\n" + ("attachment body line\n" * 4000)
    secret_body = "# Hidden note\n\nsecretfile body marker\n"

    def create() -> None:
        session = VaultSession.create(home, PASSWORD)
        _state["session"] = session
        assert not session.is_locked
        assert (home / ".vault-meta.json").exists()

    def unlock() -> None:
        session = _state["session"]
        session.lock()
        assert session.is_locked
        session.unlock(PASSWORD)
        assert not session.is_locked

    def write_notes() -> None:
        session = _state["session"]
        session.set_semantic_provider(semantics.StubProvider())
        session.write_file("notes/persian.md", persian_body.encode("utf-8"))
        session.write_file("notes/attachment.md", attachment_body.encode("utf-8"))
        session.write_file("notes/hidden.md", secret_body.encode("utf-8"))
        session.set_sensitivity("notes/hidden.md", "secret", source="ui")
        semantics.index_all(session)
        assert session.read_text("notes/persian.md") == persian_body

    def search_filenames() -> None:
        session = _state["session"]
        results = session.search_filenames("persian")
        assert any(r["logical_path"] == "notes/persian.md" for r in results), results

    def search_text() -> None:
        session = _state["session"]
        results = session.search_text("کتاب")
        assert any(r["logical_path"] == "notes/persian.md" for r in results), results
        hidden = session.search_text("secretfile")
        assert not any(r["logical_path"] == "notes/hidden.md" for r in hidden), hidden

    def search_semantic() -> None:
        session = _state["session"]
        results = session.search_semantic("کتاب")
        assert any(r["logical_path"] == "notes/persian.md" for r in results), results

    def mark_secretfile() -> None:
        session = _state["session"]
        session.set_sensitivity("notes/hidden.md", "secretfile", source="ui")
        row = session.index.require_file("notes/hidden.md")
        assert row["sensitivity"] == "secretfile", row

    def request_open_secret() -> None:
        session = _state["session"]
        seen: list[dict[str, Any]] = []
        session.on_secret_request = lambda request: seen.append(request)
        result = session.request_open_secret("notes/hidden.md", source="mcp")
        assert result["status"] == "pending", result
        assert seen, "the UI callback was not invoked"
        assert "secretfile body marker" not in str(result), "content leaked to the agent"

    def lock() -> None:
        session = _state["session"]
        session.lock()
        assert session.is_locked

    def unreachable() -> None:
        session = _state["session"]
        assert isinstance(session.list_folder("/"), dict), "metadata must survive lock"
        try:
            session.read_file("notes/persian.md")
        except VaultLocked:
            return
        raise AssertionError("content was readable while locked")

    def unlock_and_intact() -> None:
        session = _state["session"]
        session.unlock(PASSWORD)
        assert session.read_text("notes/persian.md") == persian_body
        assert session.read_text("notes/attachment.md") == attachment_body
        assert session.read_text("notes/hidden.md") == secret_body

    def verify_blobs() -> None:
        session = _state["session"]
        checked = 0
        for row in session.index.walk("/"):
            if int(row["is_dir"]) or not row.get("blob_id"):
                continue
            assert session.fs.verify_blob(row), f"blob failed verification: {row['logical_path']}"
            checked += 1
        assert checked >= 3, checked
        _state["verified_blobs"] = checked

    step("create vault", create)
    step("lock then unlock", unlock)
    step("write 3 notes (Persian, attachment-sized, secret)", write_notes)
    step("search filenames", search_filenames)
    step("search text", search_text)
    step("search semantic", search_semantic)
    step("mark secretfile", mark_secretfile)
    step("request_open_secret", request_open_secret)
    step("lock", lock)
    step("prove content unreachable while locked", unreachable)
    step("unlock and verify content intact", unlock_and_intact)
    step("verify every blob", verify_blobs)

    session = _state.get("session")
    if session is not None:
        print("\n--- vault tree ---")
        _print_tree(session, "/", "")
        print("\n--- access log summary ---")
        _print_log_summary(session)
        print(f"\nverified blobs: {_state.get('verified_blobs', 0)}")
        session.close()

    if previous_xdg is None:
        os.environ.pop("XDG_RUNTIME_DIR", None)
    else:
        os.environ["XDG_RUNTIME_DIR"] = previous_xdg
    shutil.rmtree(scratch, ignore_errors=True)

    if _failures:
        print(f"\n{FAIL}: {_failures} step(s) failed")
        return 1
    print("\nPASS: all smoke_e2e steps succeeded")
    return 0


def _print_tree(session: VaultSession, path: str, indent: str) -> None:
    """Print the vault tree rooted at ``path``."""
    for entry in session.list_folder(path)["entries"]:
        level = entry["sensitivity"]
        print(f"{indent}{entry['logical_path']} [{level}]")
        if int(entry["is_dir"]):
            _print_tree(session, entry["logical_path"], indent + "  ")


def _print_log_summary(session: VaultSession) -> None:
    """Print a count of access-log rows per outcome."""
    counts: dict[str, int] = {}
    for row in session.access_log(limit=1000):
        counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
    for outcome, count in sorted(counts.items()):
        print(f"{outcome}: {count}")
    if not counts:
        print("(no access-log rows)")


if __name__ == "__main__":
    raise SystemExit(main())
