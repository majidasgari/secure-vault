"""The bank-card template: the same body shape as a credential, read back by the same parser.

A card is *not* a login: the browser add-on must never offer it for a site, so what matters here is
that every Shetab field survives a round trip, that Persian digits are stored as ASCII, and that a
card produces no host and no password (i.e. it stays out of the autofill candidates).
"""

from __future__ import annotations

import unittest

from vault.core.credentials import build_card_body, digits_only, parse_body


class CardTemplateTest(unittest.TestCase):
    def test_shetab_fields_round_trip(self) -> None:
        body = build_card_body(
            bank="بانک ملت",
            number="6104 3388 1234 5678",
            expiry="۰۸/۰۶",
            cvv2="۱۲۳",
            pin2="987654",
            account="1234567890",
            sheba="ir12 0170 0000 0012 3456 7890 01",
            holder="ملینا النور",
        )
        card = parse_body(body)["card"]
        self.assertEqual(card["bank"], "بانک ملت")
        self.assertEqual(card["number"], "6104338812345678")
        self.assertEqual(card["expiry"], "۰۸/۰۶")
        self.assertEqual(card["cvv2"], "123")
        self.assertEqual(card["pin2"], "987654")
        self.assertEqual(card["account"], "1234567890")
        self.assertEqual(card["sheba"], "IR120170000000123456789001")
        self.assertEqual(card["holder"], "ملینا النور")

    def test_title_keeps_only_the_last_four_digits(self) -> None:
        body = build_card_body(bank="سامان", number="6219861012345678")
        fields = parse_body(body)
        self.assertEqual(fields["title"], "سامان — کارت 5678")
        self.assertNotIn("6219861012345678", fields["title"])

    def test_empty_fields_are_omitted(self) -> None:
        body = build_card_body(bank="ملی", number="6037991111112222")
        self.assertNotIn("CVV2", body)
        self.assertNotIn("رمز دوم", body)
        self.assertNotIn("شبا", body)

    def test_a_card_is_not_a_login(self) -> None:
        body = build_card_body(
            bank="پاسارگاد", number="5022291000000000", cvv2="111", sheba="IR000000000000000000000000"
        )
        fields = parse_body(body)
        self.assertTrue(fields["is_card"])
        self.assertFalse(fields["has_password"])
        self.assertEqual(fields["hosts"], [])
        self.assertEqual(fields["site"], "پاسارگاد — کارت 0000")

    def test_digits_only_normalises_persian_and_arabic_digits(self) -> None:
        self.assertEqual(digits_only("۶۱۰۴-۳۳۸۸ ۱۲۳۴"), "610433881234")
        self.assertEqual(digits_only("٦١٠٤ 3388"), "61043388")
        self.assertEqual(digits_only(""), "")


if __name__ == "__main__":
    unittest.main()
