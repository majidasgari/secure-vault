"""Tests for the one-time-code generator (``core/totp.py``) and its desktop-only surface.

Three layers:

* the algorithm — RFC 6238 Appendix B vectors for SHA-1/SHA-256/SHA-512;
* the stored-value handling — ``otpauth://`` parsing, bare base32 seeds, pasted backup codes and
  the values that are *not* OTPs at all (the migration's ``—`` placeholder, prose);
* the boundary — the code is generated in the UI process, so there is no API route that an agent
  or the browser bridge could call to read one.
"""

from __future__ import annotations

import base64
import inspect
import unittest

from vault.api.service import Service
from vault.core import credentials as creds
from vault.core import totp

#: Appendix B seeds: the ASCII digits 1..0 repeated to the hash length the vector needs.
RFC_SECRET = {
    "SHA1": b"1234567890" * 2,
    "SHA256": b"1234567890" * 3 + b"12",
    "SHA512": b"1234567890" * 6 + b"1234",
}
RFC_VECTORS = {
    "SHA1": [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
             (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")],
    "SHA256": [(59, "46119246"), (1111111109, "68084774"), (1111111111, "67062674"),
               (1234567890, "91819424"), (2000000000, "90698825"), (20000000000, "77737706")],
    "SHA512": [(59, "90693936"), (1111111109, "25091201"), (1111111111, "99943326"),
               (1234567890, "93441116"), (2000000000, "38618901"), (20000000000, "47863826")],
}

#: A body with the exact shape ``tools/keepass-migration/apply.py`` writes.
CREDENTIAL_BODY = """# GitHub

سایت: github.com | دسته: برنامه‌نویسی

نام کاربری: max@example.com
گذرواژه: github-pass-1
آدرس: https://github.com/login
کد یکبارمصرف (otp): otpauth://totp/github.com:max?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub
برچسب‌ها: dev, code

## یادداشت
password: do-not-parse
"""


def _b32(raw: bytes) -> str:
    """Base32-encode a test seed without padding."""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


class RfcVectorsTest(unittest.TestCase):
    """The generator must reproduce RFC 6238 Appendix B exactly."""

    def test_reference_vectors(self) -> None:
        """Every published time step matches for all three hash algorithms."""
        for algorithm, vectors in RFC_VECTORS.items():
            seed = _b32(RFC_SECRET[algorithm])
            for at, expected in vectors:
                spec = totp.TotpSpec(secret=seed, algorithm=algorithm, digits=8)
                code, remaining = totp.code_for(spec, at)
                self.assertEqual(code, expected, f"{algorithm} at t={at}")
                self.assertGreater(remaining, 0)
                self.assertLessEqual(remaining, 30)

    def test_code_is_stable_inside_a_period_and_renewed_after(self) -> None:
        """Two instants in the same step give one code; the next step gives another."""
        spec = totp.TotpSpec(secret=_b32(RFC_SECRET["SHA1"]))
        first, _ = totp.code_for(spec, 1000)
        again, _ = totp.code_for(spec, 1019)
        later, _ = totp.code_for(spec, 1020)
        self.assertEqual(first, again)
        self.assertNotEqual(first, later)

    def test_remaining_counts_down_to_the_step_boundary(self) -> None:
        """``remaining`` is the seconds left in the current step."""
        spec = totp.TotpSpec(secret=_b32(RFC_SECRET["SHA1"]), period=30)
        self.assertEqual(totp.code_for(spec, 30)[1], 30)
        self.assertEqual(totp.code_for(spec, 31)[1], 29)
        self.assertEqual(totp.code_for(spec, 59)[1], 1)


class ParseTest(unittest.TestCase):
    """Stored values: otpauth URIs, bare seeds, pasted codes and everything else."""

    def test_otpauth_parameters_are_honoured(self) -> None:
        """digits, period, algorithm, issuer and label come from the URI."""
        spec = totp.parse_otpauth(
            "otpauth://totp/ACME%20Co:john?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co"
            "&algorithm=SHA256&digits=8&period=60"
        )
        assert spec is not None
        self.assertEqual(spec.secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(spec.algorithm, "SHA256")
        self.assertEqual(spec.digits, 8)
        self.assertEqual(spec.period, 60)
        self.assertEqual(spec.issuer, "ACME Co")
        self.assertEqual(spec.label, "ACME Co:john")

    def test_otpauth_defaults_match_the_rfc(self) -> None:
        """A URI with only a secret falls back to SHA1/6/30."""
        spec = totp.parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
        assert spec is not None
        self.assertEqual((spec.algorithm, spec.digits, spec.period), ("SHA1", 6, 30))

    def test_otpauth_clamps_silly_parameters(self) -> None:
        """Out-of-range digits/period are clamped and an unknown algorithm falls back."""
        spec = totp.parse_otpauth(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=40&period=1&algorithm=MD5"
        )
        assert spec is not None
        self.assertEqual(spec.digits, totp.MAX_DIGITS)
        self.assertGreaterEqual(spec.period, totp.MIN_PERIOD)
        self.assertEqual(spec.algorithm, "SHA1")

    def test_only_totp_type_and_a_secret_are_accepted(self) -> None:
        """hotp, a missing secret and a non-URI are all rejected."""
        self.assertIsNone(totp.parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1"))
        self.assertIsNone(totp.parse_otpauth("otpauth://totp/x?issuer=ACME"))
        self.assertIsNone(totp.parse_otpauth("https://example.com/?secret=JBSWY3DPEHPK3PXP"))
        self.assertIsNone(totp.parse_otpauth(""))

    def test_base32_decode_tolerates_case_padding_spaces_and_dashes(self) -> None:
        """The seed people paste varies in shape; the bytes must be the same."""
        wanted = totp.base32_decode("JBSWY3DPEHPK3PXP")
        for variant in ("JBSWY3DPEHPK3PXP", "jbswy3dpehpk3pxp", "JBSWY3DPEHPK3PXP====",
                        "JBSWY 3DPE-HPK3 PXP"):
            self.assertEqual(totp.base32_decode(variant), wanted)
        for bad in ("", "   ", "JBSWY3DPEHPK3PX0", "not-a-seed!!"):
            with self.assertRaises(ValueError):
                totp.base32_decode(bad)

    def test_seed_detection_keeps_prose_out(self) -> None:
        """A sentence in capitals is decodable but must never be treated as a seed."""
        self.assertTrue(totp.looks_like_secret("JBSWY3DPEHPK3PXP"))
        self.assertTrue(totp.looks_like_secret("jbswy3dpehpk3pxp===="))
        self.assertFalse(totp.looks_like_secret("PASSWORD PHRASE"))
        self.assertFalse(totp.looks_like_secret("NOTASEED123"))       # too short + digits 1/9
        self.assertFalse(totp.looks_like_secret("12345678901234567890"))
        self.assertFalse(totp.looks_like_secret("—"))

    def test_pasted_code_is_returned_unchanged(self) -> None:
        """A stored backup code is shown as it is, with no countdown invented for it."""
        result = totp.value_to_code("123456")
        assert result is not None
        self.assertEqual(result.code, "123456")
        self.assertFalse(result.live)
        self.assertEqual(result.kind, "static")
        self.assertIsNone(result.remaining)

    def test_uri_and_bare_seed_both_generate_live_codes(self) -> None:
        """Both shapes produce a live code; the URI's parameters are respected."""
        uri = totp.value_to_code(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8&period=60", 59
        )
        seed = totp.value_to_code("JBSWY3DPEHPK3PXP", 59)
        assert uri is not None and seed is not None
        self.assertTrue(uri.live and seed.live)
        self.assertEqual(len(uri.code), 8)
        self.assertEqual(uri.period, 60)
        self.assertEqual(seed.period, 30)
        self.assertEqual(len(seed.code), 6)

    def test_display_grouping_is_presentation_only(self) -> None:
        """Six digits read as two triplets; the value a caller copies stays unspaced."""
        live = totp.value_to_code("JBSWY3DPEHPK3PXP", 59)
        assert live is not None
        self.assertEqual(len(live.code), 6)
        self.assertEqual(live.display, f"{live.code[:3]} {live.code[3:]}")
        self.assertEqual(live.display.replace(" ", ""), live.code)
        eight = totp.value_to_code("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8", 59)
        assert eight is not None
        self.assertEqual(len(eight.display.split(" ")), 2)
        self.assertEqual(eight.display.replace(" ", ""), eight.code)
        static = totp.value_to_code("987654")
        assert static is not None
        self.assertEqual(static.display, "987654")          # a backup code is never regrouped
        self.assertEqual(static.to_dict()["display"], "987654")

    def test_non_otp_values_answer_none(self) -> None:
        """The migration's placeholder, an empty value and prose are not OTPs."""
        for value in ("", "   ", "—", "hello world", "passw0rd"):
            self.assertIsNone(totp.value_to_code(value), value)


class BodyTest(unittest.TestCase):
    """Reading the OTP out of one credential body (the viewer's entry point)."""

    def test_body_with_otp_yields_a_live_code(self) -> None:
        """The label the migration writes is understood and never read from the note section."""
        result = totp.otp_for_body(CREDENTIAL_BODY, 59)
        assert result is not None
        self.assertTrue(result.live)
        self.assertEqual(len(result.code), 6)
        self.assertEqual(result.issuer, "GitHub")
        self.assertEqual(creds.parse_body(CREDENTIAL_BODY)["otp"],
                         "otpauth://totp/github.com:max?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub")

    def test_body_without_otp_yields_none(self) -> None:
        """A bank card entry has nothing to count down."""
        body = "# بانک نمونه\n\nسایت: bank.ir\n\nشماره کارت: 6037991234567890\n"
        self.assertIsNone(totp.otp_for_body(body))
        self.assertEqual(totp.otp_value_from_body(body), "")

    def test_broken_body_never_raises(self) -> None:
        """A malformed body must not break the viewer."""
        self.assertIsNone(totp.otp_for_body(None))  # type: ignore[arg-type]
        self.assertIsNone(totp.otp_for_body("کد یکبارمصرف (otp): "))


class SurfaceTest(unittest.TestCase):
    """The desktop UI owns the code: no API route hands one to another role."""

    def test_no_api_route_for_one_time_codes(self) -> None:
        """Adding a route would let the agent/browser roles read live codes — ruled out."""
        offenders = [name for name in Service._ROUTES if "otp" in name.lower()]
        self.assertEqual(offenders, [])

    def test_core_module_is_qt_free(self) -> None:
        """The generator must stay callable without a display (and outside the UI process)."""
        source = inspect.getsource(totp)
        self.assertNotIn("PySide6", source)
        self.assertNotIn("QtCore", source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
