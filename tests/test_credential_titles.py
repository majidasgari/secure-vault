"""The one-off title fix: what it rewrites, and what it must leave alone."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "credential_titles.py"


def _tool():
    """Load ``tools/credential_titles.py`` as a module (it is not a package)."""
    spec = importlib.util.spec_from_file_location("credential_titles", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RetitleTest(unittest.TestCase):
    """Only the first heading changes; nothing else in the body moves."""

    def setUp(self) -> None:
        self.tool = _tool()
        self.body = (
            "# گیت‌هاب\n"
            "سایت: github.com | دسته: برنامه‌نویسی\n"
            "نام کاربری: demo\n"
            "گذرواژه: secret-value\n"
        )

    def test_the_username_lands_in_the_heading_only(self) -> None:
        out = self.tool.retitle(self.body, "demo")
        self.assertEqual(out.splitlines()[0], "# گیت‌هاب — demo")
        self.assertEqual(out.splitlines()[1:], self.body.splitlines()[1:])

    def test_a_title_that_already_carries_the_username_is_left_alone(self) -> None:
        self.assertIsNone(self.tool.retitle("# گیت‌هاب — demo\nنام کاربری: demo\n", "demo"))

    def test_a_body_without_a_heading_is_left_alone(self) -> None:
        self.assertIsNone(self.tool.retitle("سایت: x\nنام کاربری: someone\n", "someone"))

    def test_the_trailing_newline_survives_either_way(self) -> None:
        self.assertTrue(self.tool.retitle("# T\nنام کاربری: u", "u").endswith("u"))
        self.assertTrue(self.tool.retitle("# T\nنام کاربری: u\n", "u").endswith("\n"))


class RenamedPathTest(unittest.TestCase):
    """The file name is what the list shows, so the account has to fit in it."""

    def setUp(self) -> None:
        self.tool = _tool()

    def test_the_username_goes_before_the_extension(self) -> None:
        self.assertEqual(
            self.tool.renamed_path("رمزها/ایمیل/جیمیل/جیمیل.md", "max@example.com"),
            "رمزها/ایمیل/جیمیل/جیمیل — max@example.com.md",
        )

    def test_a_duplicate_counter_is_dropped(self) -> None:
        self.assertEqual(
            self.tool.renamed_path("رمزها/اینترنت/windscribe.com/windscribe.com (2).md", "u2"),
            "رمزها/اینترنت/windscribe.com/windscribe.com — u2.md",
        )

    def test_a_name_that_already_carries_the_username_is_left_alone(self) -> None:
        self.assertIsNone(
            self.tool.renamed_path("رمزها/ایمیل/جیمیل — max@example.com.md", "max@example.com")
        )


if __name__ == "__main__":
    unittest.main()
