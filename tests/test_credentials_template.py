"""The credential template is the contract between the phone and the desktop.

Both clients write the same body (`CredentialTemplate.kt` on Android); this test pins the desktop side
to what its own parser — and therefore the credential card, field search and the browser add-on — reads.
"""

from __future__ import annotations

import unittest

from vault.core.credentials import build_body, credential_path, parse_body


class CredentialTemplateTest(unittest.TestCase):
    def test_template_round_trips_through_the_parser(self) -> None:
        body = build_body(
            site="جیمیل",
            category="ایمیل",
            username="me@example.com",
            password="s3cret",
            url="https://mail.google.com",
            otp="otpauth://totp/x?secret=ABC",
        )
        fields = parse_body(body)
        self.assertEqual(fields["username"], "me@example.com")
        self.assertEqual(fields["password"], "s3cret")
        self.assertEqual(fields["url"], "https://mail.google.com")
        self.assertEqual(fields["otp"], "otpauth://totp/x?secret=ABC")
        self.assertEqual(fields["category"], "ایمیل")
        self.assertEqual(fields["site"], "جیمیل")
        self.assertLess(body.index("گذرواژه"), body.index("## یادداشت"))

    def test_empty_fields_are_omitted(self) -> None:
        body = build_body(site="بانک", username="u")
        self.assertNotIn("گذرواژه", body)
        self.assertNotIn("آدرس", body)
        self.assertEqual(parse_body(body)["username"], "u")

    def test_path_stays_under_the_credential_root(self) -> None:
        self.assertEqual(credential_path("جیمیل", "ایمیل"), "/رمزها/ایمیل/جیمیل.md")
        self.assertEqual(credential_path("بانک"), "/رمزها/عمومی/بانک.md")
        self.assertEqual(credential_path("a/b"), "/رمزها/عمومی/a-b.md")


if __name__ == "__main__":
    unittest.main()
