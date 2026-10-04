"""One-time codes (RFC 6238) for the credential entries that carry an ``otpauth://`` value.

The credential tree under ``/رمزها`` keeps its source's OTP field verbatim, so a stored value is
one of three things: an ``otpauth://totp/…?secret=…`` URI, a bare base32 seed, or a code someone
pasted by hand (a backup code). :func:`value_to_code` turns the first two into a live code and
returns the third unchanged — it never invents a code for a value it does not understand.

Two properties matter and are enforced here:

* **No secret leaves the process.** The value is used for one HMAC and dropped; nothing is cached,
  logged or handed to a web engine. Only the desktop UI calls this module — there is no API method
  behind it, so neither the agent role nor the browser bridge can ask for a live code.
* **No Qt.** The module is stdlib-only (``hashlib``/``hmac``/``base64``/``struct``/``time``) so a
  test can generate codes without a display, and the viewer stays the only place that renders one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from . import credentials

BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

DEFAULT_ALGORITHM = "SHA1"
DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30

#: Parameters outside these bounds are clamped (a wrong ``digits`` must not raise on a live code).
MIN_DIGITS = 4
MAX_DIGITS = 10
MIN_PERIOD = 5

#: Value that the migration writes when a field is empty — never an OTP.
PLACEHOLDER = "—"

_ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
_DIGITS_RE = re.compile(r"^\d{4,10}$")

#: A bare base32 seed: the alphabet is ``A-Z`` + ``2-7``, so a *sentence* in capitals is
#: technically decodable and would silently produce a wrong code. Requiring 16+ characters with no
#: spaces, dashes or punctuation keeps prose out.
_SECRET_RE = re.compile(r"^[A-Z2-7]{16,}$")


@dataclass(frozen=True)
class TotpSpec:
    """Parameters of one TOTP generator parsed out of a stored value."""

    secret: str
    algorithm: str = DEFAULT_ALGORITHM
    digits: int = DEFAULT_DIGITS
    period: int = DEFAULT_PERIOD
    issuer: str = ""
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return the caller-facing representation (the seed itself is included, never logged)."""
        return {
            "secret": self.secret,
            "algorithm": self.algorithm,
            "digits": self.digits,
            "period": self.period,
            "issuer": self.issuer,
            "label": self.label,
        }


@dataclass(frozen=True)
class OtpCode:
    """One generated (or stored) one-time code, ready to display."""

    code: str
    live: bool
    remaining: int | None
    period: int
    digits: int
    algorithm: str = DEFAULT_ALGORITHM
    issuer: str = ""
    label: str = ""

    @property
    def kind(self) -> str:
        """``"totp"`` for a generated code, ``"static"`` for a pasted backup code."""
        return "totp" if self.live else "static"

    @property
    def display(self) -> str:
        """The code as the eye should read it (``595 561``), never the value to copy.

        Grouping is presentation only: ``code`` stays the exact digits a site expects, and the copy
        button uses it. Six digits split 3+3, eight split 4+4, nine split 3+3+3; anything else is
        left untouched rather than chopped into an odd shape. A pasted backup code is never
        regrouped — it is not a rotating code and must be typed exactly as stored.
        """
        text = self.code
        if not self.live:
            return text
        if text.isdigit() and len(text) % 3 == 0:
            return " ".join(text[i : i + 3] for i in range(0, len(text), 3))
        if text.isdigit() and len(text) % 2 == 0:
            half = len(text) // 2
            return f"{text[:half]} {text[half:]}"
        return text

    def to_dict(self) -> dict[str, Any]:
        """Return a display descriptor (no seed, so it is safe to hand to a widget/test)."""
        return {
            "code": self.code,
            "display": self.display,
            "live": self.live,
            "kind": self.kind,
            "remaining": self.remaining,
            "period": self.period,
            "digits": self.digits,
            "algorithm": self.algorithm,
            "issuer": self.issuer,
            "label": self.label,
        }


def base32_decode(text: str) -> bytes:
    """Decode an RFC 4648 base32 string, tolerating padding, spaces and dashes.

    Raises:
        ValueError: when a character is outside the base32 alphabet or the result is empty.
    """
    clean = re.sub(r"[\s-]", "", str(text or "")).upper().rstrip("=")
    if not clean:
        raise ValueError("empty_secret")
    padding = "=" * ((8 - len(clean) % 8) % 8)
    try:
        data = base64.b32decode(clean + padding, casefold=True)
    except Exception as exc:  # noqa: BLE001 - any decode failure is the same caller-facing error
        raise ValueError("invalid_base32") from exc
    if not data:
        raise ValueError("empty_secret")
    return data


def looks_like_secret(text: str) -> bool:
    """Return True when ``text`` is plausibly a bare base32 seed (see ``_SECRET_RE``)."""
    return bool(_SECRET_RE.match(str(text or "").strip().upper().rstrip("=")))


def parse_otpauth(uri: str) -> TotpSpec | None:
    """Parse an ``otpauth://totp/…`` URI into a :class:`TotpSpec`; None when it is not one.

    Only the ``totp`` type is understood (``hotp`` is counter-based and needs a counter we do not
    store). Missing parameters fall back to the RFC defaults; ``digits``/``period`` are clamped.
    """
    text = str(uri or "").strip()
    if not text.lower().startswith("otpauth://"):
        return None
    parsed = urlparse(text)
    if parsed.scheme.lower() != "otpauth":
        return None
    if (parsed.netloc or "").lower() != "totp":
        return None
    query = parse_qs(parsed.query)
    secret = (query.get("secret") or [""])[0].strip()
    if not secret:
        return None
    try:
        algorithm = ((query.get("algorithm") or [DEFAULT_ALGORITHM])[0] or DEFAULT_ALGORITHM).upper()
    except IndexError:  # pragma: no cover - empty list cannot happen with a default
        algorithm = DEFAULT_ALGORITHM
    if algorithm not in _ALGORITHMS:
        algorithm = DEFAULT_ALGORITHM
    digits = _to_int((query.get("digits") or [""])[0], DEFAULT_DIGITS)
    period = _to_int((query.get("period") or [""])[0], DEFAULT_PERIOD)
    return TotpSpec(
        secret=secret,
        algorithm=algorithm,
        digits=min(MAX_DIGITS, max(MIN_DIGITS, digits)),
        period=max(MIN_PERIOD, period),
        issuer=(query.get("issuer") or [""])[0],
        label=unquote((parsed.path or "").lstrip("/")),
    )


def _to_int(value: str, fallback: int) -> int:
    """Return ``value`` as a positive int, or ``fallback`` when it is not one."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return fallback
    return number if number > 0 else fallback


def code_for(spec: TotpSpec, at: float | None = None) -> tuple[str, int]:
    """Generate the code for ``spec`` and return ``(code, seconds_remaining)``."""
    now = time.time() if at is None else float(at)
    counter = int(now // spec.period)
    digest = hmac.new(
        base32_decode(spec.secret),
        struct.pack(">Q", counter),
        _ALGORITHMS.get(spec.algorithm, hashlib.sha1),
    ).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = str(binary % (10**spec.digits)).zfill(spec.digits)
    remaining = spec.period - int(now % spec.period)
    return code, remaining


def value_to_code(value: str, at: float | None = None) -> OtpCode | None:
    """Turn one stored OTP value into something to display, or None when it is not an OTP.

    Order: ``otpauth://`` URI → live; a 4–10 digit number → a *static* code (returned as-is, no
    countdown); a bare base32 seed → live with the RFC defaults. Anything else is not an OTP.
    """
    text = str(value or "").strip()
    if not text or text == PLACEHOLDER:
        return None
    spec = parse_otpauth(text)
    if spec is not None:
        try:
            code, remaining = code_for(spec, at)
        except ValueError:
            return None
        return OtpCode(
            code=code,
            live=True,
            remaining=remaining,
            period=spec.period,
            digits=spec.digits,
            algorithm=spec.algorithm,
            issuer=spec.issuer,
            label=spec.label,
        )
    if _DIGITS_RE.match(text):
        return OtpCode(
            code=text, live=False, remaining=None, period=DEFAULT_PERIOD, digits=len(text)
        )
    if looks_like_secret(text):
        seed = TotpSpec(secret=text)
        try:
            code, remaining = code_for(seed, at)
        except ValueError:
            return None
        return OtpCode(
            code=code,
            live=True,
            remaining=remaining,
            period=seed.period,
            digits=seed.digits,
            algorithm=seed.algorithm,
        )
    return None


def otp_value_from_body(text: str) -> str:
    """Return the raw OTP value a credential body stores ("" when it has no OTP field)."""
    try:
        return str(credentials.parse_body(text or "").get("otp", "") or "")
    except Exception:  # noqa: BLE001 - a malformed body must not break the caller
        return ""


def otp_for_body(text: str, at: float | None = None) -> OtpCode | None:
    """Return the live code of one credential body, or None when the body carries no OTP.

    The OTP field is read with the same parser the credential tree uses, so the label the migration
    writes (``کد یکبارمصرف (otp): …``) and the browser bridge agree on what an OTP line is.
    """
    return value_to_code(otp_value_from_body(text), at)


__all__ = [
    "BASE32_ALPHABET",
    "DEFAULT_ALGORITHM",
    "DEFAULT_DIGITS",
    "DEFAULT_PERIOD",
    "MAX_DIGITS",
    "MIN_DIGITS",
    "MIN_PERIOD",
    "PLACEHOLDER",
    "OtpCode",
    "TotpSpec",
    "base32_decode",
    "code_for",
    "looks_like_secret",
    "otp_for_body",
    "otp_value_from_body",
    "parse_otpauth",
    "value_to_code",
]
