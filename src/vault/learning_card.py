"""Launch the learning-card window for the MCP tool ``show_learning_card``.

The window is a separate process on purpose: it is a *review* UI an agent opens, next to the
vault app rather than inside it (the cycle itself lives in the metadata index —
:mod:`vault.core.learning`; this is one more view of it). Only the stdlib is imported here, so the
MCP process never loads Qt just to spawn it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from .config import runtime_dir

STATE_FILENAME = "learning_card.json"
LOG_FILENAME = "learning_card.log"
WINDOW_MODULE = "vault.ui.learning_card_window"

_POLL_SECONDS = 0.2


def state_path() -> Path:
    """Return the file the window publishes its pid in (inside the runtime dir)."""
    return runtime_dir() / STATE_FILENAME


def log_path() -> Path:
    """Return the file the window's stdout and stderr go to."""
    return runtime_dir() / LOG_FILENAME


def _alive(pid: int) -> bool:
    """Return True when a process with ``pid`` exists."""
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def running() -> int | None:
    """Return the pid of the open card window, or None.

    shortcut: a recycled pid reads as "still open"; the window removes its file on exit, so that
    only survives a crash. Upgrade to a loopback ping if it ever bites.
    """
    try:
        data = json.loads(state_path().read_text(encoding="utf-8"))
        pid = int(data["pid"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return pid if pid > 0 and _alive(pid) else None


def publish_pid() -> None:
    """Record this process as the open card window (atomic replace)."""
    target = state_path()
    fd, tmp_name = tempfile.mkstemp(prefix=".learning-card-", suffix=".json",
                                    dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"pid": os.getpid(), "started": int(time.time() * 1000)}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        with suppress(OSError):
            os.unlink(tmp_name)
        raise


def clear_pid() -> None:
    """Remove the pid file, unless a newer window instance owns it."""
    with suppress(OSError, ValueError, TypeError):
        if int(json.loads(state_path().read_text(encoding="utf-8"))["pid"]) != os.getpid():
            return
    with suppress(OSError):
        state_path().unlink()


def _child_env() -> dict[str, str]:
    """Rebuild the display variables a filtered agent environment drops."""
    root = str(Path(__file__).resolve().parents[2])
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [root] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    if os.name != "nt":
        env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        runtime = Path(env["XDG_RUNTIME_DIR"])
        if not env.get("WAYLAND_DISPLAY") and not env.get("DISPLAY"):
            for socket in sorted(runtime.glob("wayland-?")):
                env["WAYLAND_DISPLAY"] = socket.name
                break
        if env.get("WAYLAND_DISPLAY"):
            env.setdefault("QT_QPA_PLATFORM", "wayland")
    return env


def ensure_window(client: Any, *, timeout: float = 15.0) -> dict[str, Any]:
    """Open the card window (or report the open one) and say what is due right now."""
    cards = client.call("vault.learning_list", {}) or {}
    due = [card for card in cards.get("due") or [] if isinstance(card, dict)]
    payload: dict[str, Any] = {
        "displayed": False,
        "due": len(due),
        "cards": [
            {key: card.get(key) for key in ("path", "stage", "total", "overdue_days")}
            for card in due
        ],
    }
    pid = running()
    if pid is not None:
        return {**payload, "displayed": True, "already_open": True, "pid": pid}

    spawn: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "close_fds": True,
        "env": _child_env(),
        "cwd": str(Path(__file__).resolve().parents[2]),
    }
    if os.name == "nt":
        spawn["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        spawn["start_new_session"] = True
    try:
        with open(log_path(), "ab") as log:
            subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                [sys.executable, "-m", WINDOW_MODULE], stdout=log, stderr=log, **spawn
            )
    except OSError as exc:
        return {**payload, "display_error": f"spawn failed: {exc}"}

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pid = running()
        if pid is not None:
            return {**payload, "displayed": True, "pid": pid}
        time.sleep(_POLL_SECONDS)
    return {**payload, "display_error": f"the window did not start; see {log_path()}"}


__all__ = [
    "LOG_FILENAME",
    "STATE_FILENAME",
    "WINDOW_MODULE",
    "clear_pid",
    "ensure_window",
    "log_path",
    "publish_pid",
    "running",
    "state_path",
]
