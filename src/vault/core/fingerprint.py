"""Fingerprint quick unlock — a convenience layer over the master password.

The user enables it once, while the vault is unlocked: the master key is wrapped with a
machine-local *device secret* and stored (``0600``) under the user data directory. Every
later unlock must first pass a real ``fprintd`` verification of the enrolled finger; only
then is the device secret used to unwrap the master key, so the password is never needed
again on this machine.

Honest properties (see ``docs/SECURITY.md`` §11):

* The device secret is a plain ``0600`` file in the user's own data directory. The record
  is therefore **not** a cryptographic boundary against a local attacker who can already
  read that directory (e.g. malware running as the same user, or root): such an attacker
  could unwrap the key without a finger. It *is* a boundary against anyone who has the
  vault folder but not this account (the wrapped key is machine- and account-bound and
  useless on another machine), and it removes the typing of the password from the daily
  path.
* Only the **master key** is stored, never the password text, and it is stored wrapped
  (AES-256-GCM) with the vault id, the vault path and the creation time as associated
  data, so a record cannot be moved to another vault or edited in place.
* The passphrase path always stays available; losing the fingerprint data, the device
  file or the sensor support only costs the user a password entry.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, NamedTuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..config import user_data_dir
from ..errors import BadRequest, NotFound, Unauthorized, VaultError
from ..util import atomic_write_bytes, now_ms, wipe
from .meta import META_FILENAME, VaultMeta

LOG = logging.getLogger(__name__)

RECORD_VERSION = 1
"""Format version of the quick-unlock record."""

DIRNAME = "fingerprint"
"""Sub-directory of the user data dir holding the record and the device secret."""

DEVICE_KEY_FILENAME = "device.key"
"""The machine-local 32-byte device secret (``0600``)."""

PROTECTION_FILE = "file"
"""How the device secret is protected: today always a ``0600`` file."""

DEFAULT_VERIFY_TIMEOUT = 25.0
"""Seconds to wait for a finger before the scan is cancelled."""

KEY_SIZE = 32
NONCE_SIZE = 12
SALT_SIZE = 16

_HKDF_INFO = b"secure-vault/quick-unlock/v1"
_AAD_PREFIX = b"quick-unlock/v1"

_VERIFY_BINARIES = ("fprintd-verify", "fprintd-list")

#: ``fprintd`` can only run one claim per device; the CLI clients are serialized here.
_SCAN_LOCK = threading.Lock()


class VerifyResult(NamedTuple):
    """The outcome of one fingerprint verification.

    ``reason`` is one of ``match``, ``no_match``, ``timeout``, ``busy``, ``unavailable``
    or ``error``; ``message`` carries a short diagnostic for the UI (never a secret).
    """

    matched: bool
    reason: str
    message: str = ""
    fingers: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Alias of :attr:`matched` for symmetry with the API responses."""
        return self.matched


# --------------------------------------------------------------------------- layout
def record_dir() -> Path:
    """Return (and create) ``<user data>/fingerprint`` with mode ``0700``."""
    path = user_data_dir() / DIRNAME
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # pragma: no cover - best effort on exotic filesystems
        pass
    return path


def device_key_path() -> Path:
    """Return the path of the machine-local device secret."""
    return record_dir() / DEVICE_KEY_FILENAME


def _machine_id() -> str:
    """Return a stable machine identifier (binding material, not a secret).

    ``SECURE_VAULT_MACHINE_ID`` wins (tests, portable copies), then ``/etc/machine-id``,
    then the host name (which is what a non-Linux platform falls back to).
    """
    override = os.environ.get("SECURE_VAULT_MACHINE_ID")
    if override:
        return override.strip()
    try:
        data = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        if data:
            return data
    except OSError:
        pass
    return platform.node() or "unknown-host"


def _binding_digest() -> bytes:
    """Return ``sha256(machine id | uid | user)`` used to bind the record to the account."""
    material = f"{_machine_id()}|{os.getuid() if hasattr(os, 'getuid') else ''}|{Path.home()}"
    return hashlib.sha256(material.encode("utf-8")).digest()


def _device_secret(*, create: bool) -> bytes:
    """Return the 32-byte device secret, creating it with mode ``0600`` when asked.

    Raises:
        NotFound: when ``create`` is false and the file does not exist.
    """
    path = device_key_path()
    if path.exists():
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise NotFound("quick_unlock_device_key_unreadable", details={"reason": str(exc)})
        if len(raw) != KEY_SIZE:
            raise NotFound("quick_unlock_device_key_invalid", details={"size": len(raw)})
        return raw
    if not create:
        raise NotFound("quick_unlock_device_key_missing", details={"path": str(path)})
    secret = os.urandom(KEY_SIZE)
    atomic_write_bytes(path, secret)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - best effort on exotic filesystems
        pass
    return secret


def vault_identity(home: Path | str) -> tuple[str, str]:
    """Return ``(vault_id, resolved home)`` for an initialised vault.

    Raises:
        NotFound: when ``home`` is not an initialised vault.
    """
    home_path = Path(home)
    meta = VaultMeta.load(home_path / META_FILENAME)
    identifier = meta.vault_id
    if not identifier:
        raise NotFound("vault_not_initialised", details={"path": str(home_path)})
    try:
        resolved = str(home_path.resolve())
    except OSError:  # pragma: no cover - unresolvable paths are pathological
        resolved = str(home_path)
    return identifier, resolved


def record_path(home: Path | str) -> Path:
    """Return the record path for the vault at ``home`` (no existence guarantee)."""
    identifier, _ = vault_identity(home)
    return record_dir() / f"{identifier}.json"


# --------------------------------------------------------------------------- record
def load_record(home: Path | str) -> dict[str, Any] | None:
    """Return the stored record for ``home``, or None when quick unlock is off.

    A record written for a different vault (a reused ``vault_id``) is ignored, and an
    unreadable/corrupt record is reported as ``None`` so the caller falls back to the
    password instead of failing to start.
    """
    try:
        path = record_path(home)
    except NotFound:
        return None
    if not path.exists():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        LOG.warning("quick unlock record unreadable at %s", path)
        return None
    if not isinstance(record, dict) or int(record.get("version", 0)) != RECORD_VERSION:
        return None
    identifier, resolved = vault_identity(home)
    if record.get("vault_id") != identifier or record.get("vault_home") != resolved:
        return None
    return record


def _wrap_key(device_secret: bytes, salt: bytes) -> bytes:
    """Derive the AES key that wraps the master key from the device secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=_HKDF_INFO,
    )
    return hkdf.derive(device_secret + _binding_digest())


def _aad(vault_id: str, vault_home: str, created_at: int) -> bytes:
    """Build the associated data binding a record to its vault and creation moment."""
    return b"|".join(
        [
            _AAD_PREFIX,
            vault_id.encode("utf-8"),
            vault_home.encode("utf-8"),
            str(created_at).encode("ascii"),
        ]
    )


def quick_unlock_state(home: Path | str) -> dict[str, Any]:
    """Describe quick unlock for the unlock screen: availability plus stored record.

    Returns a dict with ``available`` (fprintd + a device + an enrolled finger),
    ``enabled`` (a usable record exists), ``device``, ``fingers``, ``protection``,
    ``created_at``/``last_used_at``/``uses`` and ``reason`` (why it is unavailable).
    """
    info = device_info()
    state: dict[str, Any] = {
        "available": bool(info.get("available")),
        "enabled": False,
        "device": info.get("device") or "",
        "fingers": list(info.get("fingers") or []),
        "protection": PROTECTION_FILE,
        "created_at": None,
        "last_used_at": None,
        "uses": 0,
        "reason": info.get("reason") or "",
    }
    record = load_record(home)
    if record is None:
        return state
    state.update(
        {
            "enabled": True,
            "protection": str(record.get("protection") or PROTECTION_FILE),
            "fingers": list(record.get("fingers") or state["fingers"]),
            "created_at": record.get("created_at"),
            "last_used_at": record.get("last_used_at"),
            "uses": int(record.get("uses", 0) or 0),
        }
    )
    # A record whose device secret is gone can never release the key again.
    if not device_key_path().exists():
        state["enabled"] = False
        state["reason"] = "device_key_missing"
    return state


def enable_quick_unlock(
    home: Path | str,
    master_key: bytes | bytearray,
    verification: VerifyResult,
    *,
    finger: str | None = None,
) -> dict[str, Any]:
    """Wrap ``master_key`` into a new record, gated by a matched ``verification``.

    Args:
        home: the vault home.
        master_key: the 32-byte master key of the (unlocked) vault.
        verification: the result of a real fingerprint verification; a result that is not
            :attr:`VerifyResult.matched` refuses the write, so no caller can enable quick
            unlock without a fingerprint.
        finger: optional single finger name the record was created with (display only).

    Raises:
        Unauthorized: when ``verification`` did not match.
        BadRequest: when ``master_key`` is not 32 bytes.
    """
    if not verification.matched:
        raise Unauthorized(
            "fingerprint_not_verified", details={"reason": verification.reason}
        )
    key = bytes(master_key)
    if len(key) != KEY_SIZE:
        raise BadRequest("bad_master_key_size", details={"size": len(key)})
    identifier, resolved = vault_identity(home)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    created_at = now_ms()
    secret = _device_secret(create=True)
    try:
        wrapped = AESGCM(_wrap_key(secret, salt)).encrypt(
            nonce, key, _aad(identifier, resolved, created_at)
        )
    finally:
        wipe(bytearray(secret))
    record = {
        "version": RECORD_VERSION,
        "vault_id": identifier,
        "vault_home": resolved,
        "protection": PROTECTION_FILE,
        "created_at": created_at,
        "last_used_at": None,
        "uses": 0,
        "fingers": [finger] if finger else list(verification.fingers),
        "cipher": "aes-256-gcm",
        "kdf": "hkdf-sha256",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "wrapped_b64": base64.b64encode(wrapped).decode("ascii"),
    }
    path = record_path(home)
    atomic_write_bytes(path, json.dumps(record, ensure_ascii=False, indent=2).encode("utf-8"))
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - best effort
        pass
    LOG.info("quick unlock enabled for vault %s", identifier[:8])
    return quick_unlock_state(home)


def disable_quick_unlock(home: Path | str) -> bool:
    """Delete the record for ``home`` (the device secret is kept for future records)."""
    try:
        path = record_path(home)
    except NotFound:
        return False
    if not path.exists():
        return False
    try:
        path.unlink()
    except OSError as exc:  # pragma: no cover - permissions on the user's own dir
        raise BadRequest("quick_unlock_record_remove_failed", details={"reason": str(exc)})
    LOG.info("quick unlock disabled for %s", path.name)
    return True


def release_master_key(
    home: Path | str,
    verification: VerifyResult,
) -> bytearray:
    """Return the vault master key for ``home`` after a matched ``verification``.

    Raises:
        Unauthorized: when the fingerprint did not match, the record is missing/corrupt,
            the device secret is gone, or the record cannot be authenticated here (it was
            copied from another machine/account or edited in place).
    """
    if not verification.matched:
        raise Unauthorized(
            "fingerprint_not_verified",
            details={"reason": verification.reason, "message": verification.message},
        )
    record = load_record(home)
    if record is None:
        raise Unauthorized("quick_unlock_not_enabled", details={"home": str(home)})
    try:
        salt = base64.b64decode(record["salt_b64"])
        nonce = base64.b64decode(record["nonce_b64"])
        wrapped = base64.b64decode(record["wrapped_b64"])
        secret = _device_secret(create=False)
    except (KeyError, ValueError, VaultError) as exc:
        raise Unauthorized("quick_unlock_record_invalid", details={"reason": str(exc)})
    aad = _aad(
        str(record.get("vault_id", "")),
        str(record.get("vault_home", "")),
        int(record.get("created_at", 0) or 0),
    )
    try:
        key = AESGCM(_wrap_key(secret, salt)).decrypt(nonce, wrapped, aad)
    except Exception as exc:  # noqa: BLE001 - any failure means the record is not ours
        LOG.warning("quick unlock record rejected: %s", type(exc).__name__)
        raise Unauthorized(
            "quick_unlock_record_invalid", details={"reason": "authentication_failed"}
        )
    finally:
        wipe(bytearray(secret))
    _touch_record(home, record)
    return bytearray(key)


def _touch_record(home: Path | str, record: dict[str, Any]) -> None:
    """Best-effort update of the record's usage counters (never fails an unlock)."""
    try:
        record["last_used_at"] = now_ms()
        record["uses"] = int(record.get("uses", 0) or 0) + 1
        path = record_path(home)
        atomic_write_bytes(
            path, json.dumps(record, ensure_ascii=False, indent=2).encode("utf-8")
        )
        os.chmod(path, 0o600)
    except (OSError, ValueError, VaultError):  # pragma: no cover - counter only
        LOG.debug("could not update the quick unlock record", exc_info=True)


# ----------------------------------------------------------------------- fprintd
def _binary(name: str) -> str | None:
    """Return the absolute path of an ``fprintd`` CLI tool, if installed."""
    return shutil.which(name)


def fprintd_available() -> bool:
    """Return True when the ``fprintd`` CLI tools are installed."""
    return all(_binary(name) for name in _VERIFY_BINARIES)


_FINGER_LINE = re.compile(r"^\s*-\s*#\d+:\s*(\S+)\s*$", re.MULTILINE)
_DEVICE_LINE = re.compile(r"^Device at (\S+)$", re.MULTILINE)


def _parse_listing(text: str) -> tuple[str, list[str]]:
    """Parse ``fprintd-list`` output into ``(device, fingers)``."""
    device = ""
    found = _DEVICE_LINE.search(text)
    if found:
        device = found.group(1)
    elif "found 1 devices" in text or "Using device" in text:
        using = re.search(r"Using device (\S+)", text)
        device = using.group(1) if using else "default"
    fingers = [match.group(1) for match in _FINGER_LINE.finditer(text)]
    return device, fingers


def device_info(username: str | None = None) -> dict[str, Any]:
    """Return ``{available, device, fingers, username, reason}`` for the sensor.

    Never raises: a missing tool, a missing device or a ``fprintd`` error all report
    ``available: False`` plus a machine-readable ``reason`` so the UI can explain it.
    """
    user = username or _current_user()
    info: dict[str, Any] = {
        "available": False,
        "device": "",
        "fingers": [],
        "username": user,
        "reason": "",
    }
    if not fprintd_available():
        info["reason"] = "fprintd_missing"
        return info
    try:
        result = _spawn([str(_binary("fprintd-list")), user], timeout=15)
    except Exception as exc:  # noqa: BLE001 - any failure means "no sensor here"
        info["reason"] = _reason_for_failure(exc)
        return info
    output = f"{result.stdout or ''}{result.stderr or ''}"
    device, fingers = _parse_listing(output)
    info["device"] = device
    info["fingers"] = fingers
    if not device:
        info["reason"] = "no_device"
        return info
    if not fingers:
        info["reason"] = "no_enrolled_finger"
        return info
    info["available"] = True
    return info


class SpawnResult(NamedTuple):
    """The outcome of running one ``fprintd`` CLI client."""

    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    cancelled: bool = False


def _death_hook() -> Callable[[], None] | None:
    """Return a pre-exec hook that kills the child when this process dies (Linux).

    ``fprintd-verify`` waits for a finger indefinitely, so a crashed or SIGKILLed app used
    to leave an orphan holding the sensor — which then answers "device claimed" to the next
    scan (the screen lock included). ``PR_SET_PDEATHSIG`` makes the kernel take the child
    down with us. Returns ``None`` where that is not available.
    """
    if not sys.platform.startswith("linux"):  # pragma: no cover - other platforms
        return None
    try:
        import ctypes
        import signal

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except Exception:  # noqa: BLE001 - no libc: fall back to the cancel path
        return None
    pr_set_pdeathsig = 1

    def hook() -> None:
        libc.prctl(pr_set_pdeathsig, int(signal.SIGKILL), 0, 0, 0)

    return hook


#: Resolved once: passing a Python callback as ``preexec_fn`` on every spawn is wasteful.
_DEATH_HOOK = _death_hook()


def _spawn(
    argv: list[str],
    timeout: float,
    cancel: threading.Event | None = None,
) -> SpawnResult:
    """Run an ``fprintd`` CLI client, killing it on timeout or ``cancel``.

    ``fprintd-verify`` blocks until a finger is presented, so the child is watched in a
    short poll loop: the scan can be cancelled from the UI (``cancel``) and can never hang
    the caller beyond ``timeout`` seconds. The child also dies with this process
    (:data:`_DEATH_HOOK`), so no orphan can keep the sensor claimed.
    """
    try:
        extra: dict[str, Any] = {}
        if _DEATH_HOOK is not None:  # ``preexec_fn`` is POSIX-only and rejected on Windows
            extra["preexec_fn"] = _DEATH_HOOK
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, absolute binary from which()
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            stdin=subprocess.DEVNULL,
            **extra,
        )
    except OSError as exc:
        return SpawnResult(None, "", f"{type(exc).__name__}: {exc}")
    deadline = time.monotonic() + max(1.0, timeout)
    while True:
        if proc.poll() is not None:
            break
        if cancel is not None and cancel.is_set():
            _terminate(proc)
            out, err = proc.communicate()
            return SpawnResult(None, out or "", err or "", cancelled=True)
        if time.monotonic() >= deadline:
            _terminate(proc)
            out, err = proc.communicate()
            return SpawnResult(None, out or "", err or "", timed_out=True)
        time.sleep(0.1)
    out, err = proc.communicate()
    return SpawnResult(proc.returncode, out or "", err or "")


def _terminate(proc: Any) -> None:
    """Ask an ``fprintd`` client to stop, escalating to a kill (best effort)."""
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:  # noqa: BLE001 - escalation only
        try:
            proc.kill()
        except Exception:  # noqa: BLE001 - the process is already gone
            pass


def _current_user() -> str:
    """Return the current user name (empty when it cannot be determined)."""
    try:
        import getpass

        return getpass.getuser()
    except Exception:  # noqa: BLE001 - a broken passwd entry must not crash the UI
        return os.environ.get("USER", "") or ""


def _reason_for_failure(exc: Exception) -> str:
    """Map a spawn/parse failure to a machine-readable reason."""
    if isinstance(exc, subprocess.TimeoutExpired):
        return "timeout"
    if isinstance(exc, FileNotFoundError):
        return "fprintd_missing"
    return "error"


def verify(
    username: str | None = None,
    *,
    finger: str | None = None,
    timeout: float = DEFAULT_VERIFY_TIMEOUT,
    cancel: threading.Event | None = None,
) -> VerifyResult:
    """Ask ``fprintd`` for a fingerprint and report whether it matched.

    This blocks on the sensor (call it off the GUI thread) until a finger is matched, the
    ``timeout`` expires, or ``cancel`` is set. It never raises: an unusable sensor, a
    claimed device or a cancelled scan are all ordinary results.
    """
    user = username or _current_user()
    if not fprintd_available():
        return VerifyResult(False, "unavailable", "fprintd_missing")
    binary = _binary("fprintd-verify")
    argv = [str(binary)]
    if finger:
        argv += ["-f", finger]
    if user:
        argv.append(user)
    if not _SCAN_LOCK.acquire(timeout=max(1.0, timeout)):
        return VerifyResult(False, "busy", "device_claimed")
    started = time.monotonic()
    try:
        result = _spawn(argv, timeout, cancel)
    except Exception as exc:  # noqa: BLE001 - map every failure to a plain result
        return VerifyResult(False, _reason_for_failure(exc), type(exc).__name__)
    finally:
        _SCAN_LOCK.release()
    elapsed = time.monotonic() - started
    if result.cancelled:
        return VerifyResult(False, "cancelled", "cancelled")
    if result.timed_out:
        return VerifyResult(False, "timeout", f"{elapsed:.0f}s")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    combined = f"{stdout}\n{stderr}"
    _, fingers = _parse_listing(combined)
    code = int(result.returncode) if result.returncode is not None else None
    # A match needs positive evidence: fprintd's own success line, or an exit-0 client that
    # printed something. An empty/unknown result is never turned into an unlock.
    if _matched_output(stdout) or (code == 0 and stdout.strip() and not _failed_output(combined)):
        return VerifyResult(True, "match", f"{elapsed:.1f}s", tuple(fingers))
    if _failed_output(combined):
        return VerifyResult(False, "no_match", "no_match", tuple(fingers))
    if not stdout.strip() and not stderr.strip():
        return VerifyResult(False, "error", "no_output")
    detail = stderr.strip().splitlines()[-1] if stderr.strip() else "no_output"
    return VerifyResult(False, "error", detail[:160])


def _matched_output(text: str) -> bool:
    """Return True only for fprintd's explicit success line.

    ``Verify result: verify-retry-scan (done)`` is *not* a match — it means the scan was
    unreadable and fprintd is still waiting — so a match must be spelled out. Anything
    ambiguous falls through to a refusal rather than an unlock.
    """
    lowered = text.lower()
    if "verify-match" in lowered:
        return True
    for line in text.splitlines():
        stripped = line.strip().lower()
        if "verify result" in stripped and "no-match" not in stripped and "retry" not in stripped:
            return True
    return False


#: fprintd result tokens that mean "no usable scan" rather than "a different finger".
_FAILURE_TOKENS = (
    "verify-no-match",
    "verify-retry-scan",
    "verify-swipe-too-short",
    "verify-finger-not-centered",
    "verify-too-fast",
    "verify-too-slow",
    "verify-disconnected",
    "verify-unknown-error",
    "verify-timeout",
)


def _failed_output(text: str) -> bool:
    """Return True when ``text`` carries any fprintd failure/retry token."""
    lowered = text.lower()
    return any(token in lowered for token in _FAILURE_TOKENS)


__all__ = [
    "DEFAULT_VERIFY_TIMEOUT",
    "DEVICE_KEY_FILENAME",
    "DIRNAME",
    "PROTECTION_FILE",
    "RECORD_VERSION",
    "VerifyResult",
    "device_info",
    "device_key_path",
    "disable_quick_unlock",
    "enable_quick_unlock",
    "fprintd_available",
    "load_record",
    "quick_unlock_state",
    "record_dir",
    "record_path",
    "release_master_key",
    "vault_identity",
    "verify",
]
