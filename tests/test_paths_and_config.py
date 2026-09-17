"""Tests for vault.util and vault.config (SPEC/06 §2 test_paths_and_config)."""

from __future__ import annotations

import os
import stat
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from vault import config
from vault.core.meta import default_settings
from vault.errors import InvalidPath
from vault.util import atomic_write_bytes, normalize_logical_path


class NormalizeLogicalPathTest(unittest.TestCase):
    """Accept/reject rules for logical paths."""

    def test_acceptations(self) -> None:
        """Canonical forms are produced."""
        self.assertEqual(normalize_logical_path("a/b"), "a/b")
        self.assertEqual(normalize_logical_path("a\\b"), "a/b")
        self.assertEqual(normalize_logical_path("  a/b  "), "a/b")
        self.assertEqual(normalize_logical_path("a//b"), "a/b")
        self.assertEqual(normalize_logical_path("a/./b"), "a/b")
        self.assertEqual(normalize_logical_path("/"), "/")
        self.assertEqual(normalize_logical_path("///"), "/")
        self.assertEqual(normalize_logical_path("notes/"), "notes")

    def test_nfc_normalization(self) -> None:
        """Decomposed input is NFC-normalized."""
        decomposed = unicodedata.normalize("NFD", "café")
        self.assertNotEqual(decomposed, "café")
        self.assertEqual(normalize_logical_path(decomposed), "café")

    def test_rejections(self) -> None:
        """Malformed paths raise InvalidPath."""
        for bad in (
            "",
            "   ",
            "/absolute",
            "a/../b",
            "../a",
            "a/..",
            "a\x00b",
            "a\x01b",
            "a" * 1025,
        ):
            with self.assertRaises(InvalidPath, msg=repr(bad)):
                normalize_logical_path(bad)

    def test_non_string_rejected(self) -> None:
        """Non-string input is an InvalidPath."""
        with self.assertRaises(InvalidPath):
            normalize_logical_path(None)  # type: ignore[arg-type]


class AtomicWriteTest(unittest.TestCase):
    """atomic_write_bytes leaves no temporary file."""

    def test_write_and_no_tmp(self) -> None:
        """The target holds the data and no .tmp remains."""
        tmp = Path(tempfile.mkdtemp(prefix="sv-aw-"))
        target = tmp / "data.bin"
        atomic_write_bytes(target, b"hello")
        self.assertEqual(target.read_bytes(), b"hello")
        self.assertEqual(list(tmp.glob("*.tmp")), [])

    def test_overwrite(self) -> None:
        """An existing file is replaced atomically."""
        tmp = Path(tempfile.mkdtemp(prefix="sv-aw-"))
        target = tmp / "data.bin"
        atomic_write_bytes(target, b"one")
        atomic_write_bytes(target, b"two")
        self.assertEqual(target.read_bytes(), b"two")


class RuntimeDirTest(unittest.TestCase):
    """runtime_dir honours XDG_RUNTIME_DIR and is mode 0700."""

    def test_honours_xdg_runtime_dir(self) -> None:
        """The directory is created under XDG_RUNTIME_DIR with mode 0700."""
        base = Path(tempfile.mkdtemp(prefix="sv-rt-"))
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(base)}):
            path = config.runtime_dir()
        self.assertEqual(path, base / "secure-vault")
        self.assertTrue(path.is_dir())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_fallback_when_unset(self) -> None:
        """Without XDG_RUNTIME_DIR the fallback path is used."""
        env = dict(os.environ)
        env.pop("XDG_RUNTIME_DIR", None)
        with mock.patch.dict(os.environ, env, clear=True):
            path = config.runtime_dir()
        self.assertEqual(path, Path("/tmp") / f"secure-vault-{os.getuid()}")


class UserConfigTest(unittest.TestCase):
    """user_config round-trips and preserves unknown keys."""

    def test_defaults(self) -> None:
        """A missing ui.json yields documented defaults."""
        base = Path(tempfile.mkdtemp(prefix="sv-cfg-"))
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(base)}):
            cfg = config.user_config()
            self.assertEqual(cfg.language, "fa")
            self.assertEqual(cfg.window, {})
            self.assertIsNone(cfg.last_folder)

    def test_round_trip_keeps_unknown_keys(self) -> None:
        """Unknown keys survive a save/load cycle."""
        base = Path(tempfile.mkdtemp(prefix="sv-cfg-"))
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(base)}):
            cfg = config.user_config()
            cfg.language = "en"
            cfg.window = {"w": 800, "h": 600}
            cfg.last_folder = "notes"
            cfg.data["future_feature"] = {"enabled": True}
            cfg.save()
            reloaded = config.user_config()
        self.assertEqual(reloaded.language, "en")
        self.assertEqual(reloaded.window, {"w": 800, "h": 600})
        self.assertEqual(reloaded.last_folder, "notes")
        self.assertEqual(reloaded.data["future_feature"], {"enabled": True})

    def test_atomic_save_leaves_no_tmp(self) -> None:
        """Saving the user config leaves no .tmp file."""
        base = Path(tempfile.mkdtemp(prefix="sv-cfg-"))
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(base)}):
            cfg = config.user_config()
            cfg.save()
            cfg_dir = base / "secure-vault"
        self.assertEqual(list(cfg_dir.glob("*.tmp")), [])


class DefaultsAgreeTest(unittest.TestCase):
    """Module defaults agree with the SPEC and the settings defaults."""

    def test_defaults(self) -> None:
        """DEFAULT_VAULT_HOME and the settings defaults match the SPEC."""
        self.assertEqual(config.DEFAULT_VAULT_HOME, "/data/Cloud/SecureVault")
        self.assertEqual(config.DEFAULT_PLAIN_THRESHOLD, 10 * 1024 * 1024)
        self.assertEqual(config.DEFAULT_AUTO_LOCK_SECONDS, 900)
        self.assertEqual(config.DEFAULT_LANGUAGE, "fa")
        settings = default_settings()
        self.assertEqual(settings["plain_threshold_bytes"], config.DEFAULT_PLAIN_THRESHOLD)
        self.assertEqual(settings["auto_lock_seconds"], config.DEFAULT_AUTO_LOCK_SECONDS)

    def test_app_paths(self) -> None:
        """app_paths points at the repo's assets and i18n directories."""
        paths = config.app_paths()
        self.assertTrue(paths.repo_root.is_dir())
        self.assertEqual(paths.assets_dir, paths.repo_root / "assets")
        self.assertEqual(paths.i18n_dir, paths.repo_root / "i18n")


if __name__ == "__main__":
    unittest.main()
