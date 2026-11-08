"""The card side of the browser bridge: listing cards and revealing one for a payment page.

A Shaparak payment page has no account and no host to match, so what keeps it safe is that only
entries inside the card folder answer, the listing carries no number, the reveal is rate-limited
and every reveal is audited.
"""

from __future__ import annotations

import json
import unittest

from support import tmp_vault
from vault.api.browser import BrowserBridge
from vault.api.service import Service
from vault.core.credentials import CARD_CATEGORY, CREDENTIAL_ROOT
from vault.errors import BadRequest, PermissionDenied

CARD_BODY = """# ملت — کارت 5678

سایت: ملت — کارت 5678 | دسته: بانک و پرداخت

بانک: بانک ملت
شماره کارت: 6104338812345678
تاریخ انقضا: 08/06
CVV2: 123
رمز دوم: 987654
شماره حساب: 1234567890
شبا: IR120170000000123456789001
صاحب حساب: ملینا النور

## یادداشت
کارت اصلی خرید.
"""

LOGIN_BODY = """# سایت نمونه

سایت: shop.example | دسته: خرید

نام کاربری: me@example.com
گذرواژه: shop-pass
آدرس: https://shop.example/login
"""

CARD_PATH = f"/{CREDENTIAL_ROOT}/{CARD_CATEGORY}/ملت — کارت 5678.md"


def seed(session, path: str, body: str, *, level: str = "secretfile") -> None:
    """Write one entry into the scratch vault (the way the migration and the app both do)."""
    logical = path.strip("/")
    parts = logical.split("/")
    for index in range(1, len(parts)):
        try:
            session.mkdir("/".join(parts[:index]), source="ui")
        except Exception:  # noqa: BLE001 - the folder may already exist
            pass
    session.write_file(logical, body.encode("utf-8"), source="ui", sensitivity=level)


class CardBridgeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.session = tmp_vault()
        self.service = Service(self.session)
        self.bridge = BrowserBridge(self.service, runtime_dir=self.session._runtime)
        seed(self.session, CARD_PATH, CARD_BODY)
        seed(self.session, f"/{CREDENTIAL_ROOT}/خرید/shop.example/سایت.md", LOGIN_BODY)

    def tearDown(self) -> None:
        self.session.close()

    def test_list_is_metadata_only(self) -> None:
        """The listing names the bank and the last four digits — never the number or the CVV2."""
        result = self.bridge.cards()
        self.assertEqual(result["count"], 1)
        card = result["cards"][0]
        self.assertEqual(card["bank"], "بانک ملت")
        self.assertEqual(card["last4"], "5678")
        self.assertEqual(card["path"], CARD_PATH)
        self.assertTrue(card["has_cvv2"])
        self.assertTrue(card["has_pin2"])
        # The card entry itself carries no value: only the bank, the last four digits and which
        # fields exist. (The payload's timestamps are not part of that assertion.)
        blob = json.dumps(result["cards"], ensure_ascii=False)
        for secret in ("6104338812345678", "08/06", "123", "987654", "IR120170000000123456789001"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, blob)

    def test_reveal_returns_the_shetab_fields(self) -> None:
        """Picking one card yields exactly what a payment form asks for."""
        card = self.bridge.reveal_card(CARD_PATH)
        self.assertEqual(card["number"], "6104338812345678")
        self.assertEqual(card["expiry"], "08/06")
        self.assertEqual(card["cvv2"], "123")
        self.assertEqual(card["pin2"], "987654")
        self.assertEqual(card["holder"], "ملینا النور")

    def test_reveal_is_audited(self) -> None:
        """Every card reveal is one access-log row naming the file (a password never is)."""
        self.bridge.reveal_card(CARD_PATH)
        entries = self.session.access_log(limit=5)
        rows = [row for row in entries if row.get("source") == "browser"]
        self.assertTrue(rows)
        blob = json.dumps(rows, ensure_ascii=False)
        self.assertNotIn("6104338812345678", blob)

    def test_login_entries_are_not_cards(self) -> None:
        """A login file inside the card folder is refused, and outside it the path never answers."""
        seed(self.session, f"/{CREDENTIAL_ROOT}/{CARD_CATEGORY}/not-a-card.md", LOGIN_BODY)
        with self.assertRaises(BadRequest):
            self.bridge.reveal_card(f"/{CREDENTIAL_ROOT}/{CARD_CATEGORY}/not-a-card.md")
        with self.assertRaises(PermissionDenied):
            self.bridge.reveal_card(f"/{CREDENTIAL_ROOT}/خرید/shop.example/سایت.md")

    def test_reveal_is_rate_limited(self) -> None:
        """The same rolling-minute cap as a password reveal applies to cards."""
        bridge = BrowserBridge(self.service, runtime_dir=self.session._runtime, reveal_limit=1)
        bridge.reveal_card(CARD_PATH)
        with self.assertRaises(PermissionDenied) as caught:
            bridge.reveal_card(CARD_PATH)
        self.assertEqual(caught.exception.code, "PERMISSION_DENIED")


if __name__ == "__main__":
    unittest.main()
