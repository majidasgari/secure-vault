"""Tests for the Joplin mirror importer (SPEC/06 §2 test_importers)."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from support import tmp_vault
from vault.core.session import VaultSession
from vault.errors import BadRequest
from vault.importers.joplin_mirror import (
    DEFAULT_SKIP,
    JoplinMirrorImporter,
    sanitize,
    strip_frontmatter,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "mirror_small"
MISSING_RESOURCE = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _tree_digest(root: Path) -> dict[str, str]:
    """Hash every persistent file under ``root``.

    SQLite's ``-shm``/``-wal`` scratch files are excluded: reading a WAL database may
    touch the shared-memory index without writing any vault data, which is exactly what a
    dry run is allowed to do. Every content/metadata file is still compared.
    """
    digest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name.endswith(("-shm", "-wal")):
            continue
        digest[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest


class JoplinMirrorImporterTest(unittest.TestCase):
    """Drive the importer against a temp copy of the committed fixture mirror."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="sv-import-test-"))
        self.mirror = self.tmp / "mirror"
        shutil.copytree(FIXTURE, self.mirror)
        self.session = tmp_vault(self.tmp)
        self.importer = JoplinMirrorImporter(self.mirror)

    def tearDown(self) -> None:
        self.session.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --------------------------------------------------------------------- dry run
    def test_dry_run_writes_nothing(self) -> None:
        """A dry run counts but leaves the vault byte-identical."""
        before = _tree_digest(self.session.home)
        report = self.importer.run(self.session, dry_run=True)
        after = _tree_digest(self.session.home)
        self.assertEqual(before, after)
        self.assertEqual(report.notes_created, 3)
        self.assertEqual(report.notes_updated, 0)
        self.assertEqual(report.folders_created, 2)
        # every asset of the manifest is materialised, referenced or not (SPEC/04 §2.2 rule 6)
        self.assertEqual(report.assets_imported, len(json.loads((self.mirror / "_meta" / "index.json").read_text(encoding="utf-8"))["assets"]))
        self.assertEqual(report.errors, [])
        self.assertIsNone(self.session.index.get_file("Work/first.md"))

    # ------------------------------------------------------------------- real run
    def test_real_run_counts_and_structure(self) -> None:
        """A real run creates the folders, notes, tags and asset with no errors."""
        report = self.importer.run(self.session)
        self.assertEqual(report.notes_created, 3)
        self.assertEqual(report.notes_updated, 0)
        self.assertEqual(report.notes_skipped, 0)
        self.assertEqual(report.folders_created, 2)
        self.assertEqual(report.assets_imported, len(json.loads((self.mirror / "_meta" / "index.json").read_text(encoding="utf-8"))["assets"]))
        self.assertEqual(report.tags_applied, 2)
        self.assertEqual(report.errors, [])
        self.assertIsNotNone(self.session.index.get_file("Work"))
        self.assertIsNotNone(self.session.index.get_file("Personal"))
        self.assertIsNotNone(self.session.index.get_file("Work/first.md"))
        self.assertIsNotNone(self.session.index.get_file("Work/second.md"))
        self.assertIsNotNone(self.session.index.get_file("Personal/third.md"))

    def test_frontmatter_stripped(self) -> None:
        """The body no longer contains the Joplin frontmatter block."""
        self.importer.run(self.session)
        body = self.session.read_text("Work/first.md")
        self.assertNotIn("id: n-first", body)
        self.assertNotIn("created_time", body)
        self.assertNotIn("---", body.splitlines()[0])
        self.assertTrue(body.startswith("# First note"), body)

    def test_tags_and_todo(self) -> None:
        """Manifest tags are applied verbatim and ``is_todo`` adds the ``todo`` tag."""
        self.importer.run(self.session)
        self.assertEqual(self.session.index.get_tags("Work/first.md"), ["alpha"])
        self.assertEqual(self.session.index.get_tags("Work/second.md"), ["todo"])

    def test_asset_import_and_link_rewrite(self) -> None:
        """The referenced binary is imported and its link rewritten to ``vault:``."""
        self.importer.run(self.session)
        asset = self.session.index.get_file("attachments/pic.png")
        self.assertIsNotNone(asset)
        self.assertFalse(int(asset["is_dir"]))
        body = self.session.read_text("Work/first.md")
        self.assertIn("vault:/attachments/pic.png", body)
        self.assertNotIn(":/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", body)

    def test_stray_import_and_skips(self) -> None:
        """The stray markdown is imported while ``_index.md``/``README.md`` are skipped."""
        report = self.importer.run(self.session)
        self.assertIn("idea.md", report.extra["stray_imported"])
        self.assertIsNotNone(self.session.index.get_file("idea.md"))
        self.assertIsNone(self.session.index.get_file("_index.md"))
        self.assertIsNone(self.session.index.get_file("README.md"))
        self.assertIsNone(self.session.index.get_file("Work/_index.md"))

    def test_second_run_is_noop(self) -> None:
        """A second run skips all three notes and updates nothing."""
        self.importer.run(self.session)
        report = self.importer.run(self.session)
        self.assertEqual(report.notes_skipped, 3)
        self.assertEqual(report.notes_created, 0)
        self.assertEqual(report.notes_updated, 0)
        self.assertEqual(report.folders_created, 0)
        self.assertEqual(report.errors, [])

    def test_updated_note_updates(self) -> None:
        """Changing a note's ``updated`` in the manifest updates the vault file."""
        self.importer.run(self.session)
        manifest_path = self.mirror / "_meta" / "index.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for note in manifest["notes"]:
            if note["id"] == "n-third":
                note["updated"] = "2025-01-01T00:00:00Z"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        (self.mirror / "Personal" / "third.md").write_text(
            "---\nid: n-third\nupdated_time: 2025-01-01T00:00:00Z\n---\n\n"
            "# Third note\n\nupdated third body\n",
            encoding="utf-8",
        )
        report = self.importer.run(self.session)
        self.assertEqual(report.notes_updated, 1)
        self.assertEqual(report.notes_created, 0)
        self.assertIn("updated third body", self.session.read_text("Personal/third.md"))

    # ------------------------------------------------------------------ sensitivity
    def test_mark_secret_glob(self) -> None:
        """A ``--mark-secret`` glob imports the matching note as ``secret``."""
        importer = JoplinMirrorImporter(self.mirror, mark_secret_globs=["*idea*"])
        report = importer.run(self.session)
        self.assertEqual(report.errors, [])
        row = self.session.index.get_file("idea.md")
        self.assertEqual(row["sensitivity"], "secret")
        texts = [r["logical_path"] for r in self.session.search_text("stray")]
        self.assertNotIn("idea.md", texts)

    def test_mark_secret_glob_on_manifest_note(self) -> None:
        """The glob also matches a manifest note by path/title."""
        importer = JoplinMirrorImporter(self.mirror, mark_secret_globs=["*second*"])
        importer.run(self.session)
        row = self.session.index.get_file("Work/second.md")
        self.assertEqual(row["sensitivity"], "secret")
        self.assertEqual(
            [r["logical_path"] for r in self.session.search_text("second")], []
        )

    def test_default_level_applies(self) -> None:
        """``default_level`` is used for notes that no glob matches."""
        importer = JoplinMirrorImporter(self.mirror, default_level="secret")
        importer.run(self.session)
        row = self.session.index.get_file("Personal/third.md")
        self.assertEqual(row["sensitivity"], "secret")

    # ------------------------------------------------------------------- collision
    def test_collision_renames_never_overwrites(self) -> None:
        """An untracked file at a colliding path is preserved and the note renamed."""
        self.session.write_file("Work/first.md", b"pre-existing untracked content")
        report = self.importer.run(self.session)
        self.assertEqual(
            self.session.read_text("Work/first.md"), "pre-existing untracked content"
        )
        self.assertIsNotNone(self.session.index.get_file("Work/first (imported 2).md"))
        self.assertGreaterEqual(report.extra["renamed_conflicts"], 1)

    # --------------------------------------------------------------- unresolved refs
    def test_unresolved_ref_counted_not_fatal(self) -> None:
        """A reference to a missing resource is counted and left untouched."""
        report = self.importer.run(self.session)
        self.assertEqual(report.errors, [])
        resources = {ref["resource"] for ref in report.extra["unresolved_refs"]}
        self.assertIn(MISSING_RESOURCE, resources)
        body = self.session.read_text("Work/first.md")
        self.assertIn(f":/{MISSING_RESOURCE}", body)

    # ----------------------------------------------------------------------- flags
    def test_no_assets_leaves_links(self) -> None:
        """``import_assets=False`` imports nothing and rewrites nothing."""
        importer = JoplinMirrorImporter(self.mirror, import_assets=False)
        report = importer.run(self.session)
        self.assertEqual(report.assets_imported, 0)
        self.assertIsNone(self.session.index.get_file("attachments/pic.png"))
        self.assertIn(":/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", self.session.read_text("Work/first.md"))

    def test_no_stray_skips_stray(self) -> None:
        """``include_stray_md=False`` leaves stray markdown out."""
        importer = JoplinMirrorImporter(self.mirror, include_stray_md=False)
        report = importer.run(self.session)
        self.assertEqual(report.extra["stray_imported"], [])
        self.assertIsNone(self.session.index.get_file("idea.md"))

    # ------------------------------------------------------------------- safety
    def test_mirror_never_modified(self) -> None:
        """The importer never writes to the mirror."""
        before = _tree_digest(self.mirror)
        self.importer.run(self.session)
        after = _tree_digest(self.mirror)
        self.assertEqual(before, after)

    def test_home_inside_mirror_refused(self) -> None:
        """A vault home inside the mirror is refused with ``BadRequest``."""
        inside = self.mirror / "vault-home"
        session = VaultSession.create(inside, "pw")
        try:
            with self.assertRaises(BadRequest):
                self.importer.run(session)
        finally:
            session.close()

    def test_mirror_inside_home_refused(self) -> None:
        """A mirror inside the vault home is refused with ``BadRequest``."""
        home = self.tmp / "outer-vault"
        session = VaultSession.create(home, "pw")
        mirror = home / "mirror"
        shutil.copytree(FIXTURE, mirror)
        try:
            with self.assertRaises(BadRequest):
                JoplinMirrorImporter(mirror).run(session)
        finally:
            session.close()


class SanitizeTest(unittest.TestCase):
    """``sanitize`` follows the SPEC/04 §2.2.3 rules."""

    def test_unsafe_characters_replaced(self) -> None:
        """Windows-unsafe characters become underscores."""
        self.assertEqual(sanitize('a:b/c?d\\e*f.md'), "a_b/c_d_e_f.md")
        self.assertEqual(sanitize('a"b<c>d|e.md'), "a_b_c_d_e.md")

    def test_persian_and_specials_preserved(self) -> None:
        """``#``, ``$``, ``@``, Persian and emoji survive."""
        raw = "$weird/#tag/@x/برنامه‌ریزی/😀.md"
        self.assertEqual(sanitize(raw), raw)

    def test_trailing_dots_and_spaces_stripped(self) -> None:
        """Trailing dots/spaces are stripped per segment."""
        self.assertEqual(sanitize("trail. /seg. "), "trail/seg")
        self.assertEqual(sanitize("a/./b//c.md"), "a/b/c.md")

    def test_root_and_empty(self) -> None:
        """Empty and root-like inputs map to ``/``."""
        self.assertEqual(sanitize(""), "/")
        self.assertEqual(sanitize("///"), "/")

    def test_strip_frontmatter(self) -> None:
        """Frontmatter is removed and the body preserved."""
        text = "---\nid: x\n---\n\n# Title\n\nbody\n"
        self.assertEqual(strip_frontmatter(text), "# Title\n\nbody\n")
        self.assertEqual(strip_frontmatter("no frontmatter"), "no frontmatter")

    def test_default_skip_list(self) -> None:
        """The documented mirror-tooling names are all in ``DEFAULT_SKIP``."""
        for name in ("_index.md", "_meta", "_skills", "__pycache__", "README.md",
                     "browser.py", "convert_jex.py", "joplin_mcp.py",
                     "open-joplin.bat", "open-joplin.sh"):
            self.assertIn(name, DEFAULT_SKIP)


if __name__ == "__main__":
    unittest.main()
