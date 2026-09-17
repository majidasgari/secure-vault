"""The Joplin markdown-mirror importer (SPEC/04 §2).

Reads a read-only Joplin export mirror (``_meta/index.json`` is the authoritative
manifest) and materialises its notebooks, notes, tags, assets and stray markdown into a
:class:`~vault.core.session.VaultSession`. The mirror is never modified and every write
is idempotent via the ``joplin:note:<id>`` / ``joplin:asset:<id>`` / ``joplin:stray:<rel>``
kv records.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..core.security import LEVELS, SOURCE_IMPORTER
from ..errors import BadRequest, VaultError
from ..util import now_ms, normalize_logical_path, sha256_hex
from .base import ImportReport, ProgressCallback

LOG = logging.getLogger("vault.importers.joplin")

DEFAULT_MIRROR = Path("/data/Cloud/Documents/Notes/joplin-mirror")
"""The real Joplin mirror location (read-only input)."""

DEFAULT_SKIP: tuple[str, ...] = (
    "_index.md",
    "_meta",
    "_skills",
    "__pycache__",
    "README.md",
    "browser.py",
    "convert_jex.py",
    "joplin_mcp.py",
    "open-joplin.bat",
    "open-joplin.sh",
)
"""Mirror tooling that must never be imported (``--no-skip`` disables it)."""

DEFAULT_ASSETS_FOLDER = "attachments"
"""Vault folder that imported resource binaries are written to."""

_UNSAFE_CHARS = frozenset('\\:*?"<>|')
_RESOURCE_RE = re.compile(r":/([0-9a-fA-F]{32})")
_FRONTMATTER_RE = re.compile(
    r"\A---[ \t]*\r?\n.*?\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL
)


def sanitize(path: str) -> str:
    """Return a Windows-safe vault logical path for a raw mirror path.

    Applies :func:`~vault.util.normalize_logical_path` after replacing ``\\ : * ? " < > |``
    and control characters with ``_``, collapsing empty segments and stripping trailing
    dots/spaces from every segment. ``#``, ``$``, ``@``, Persian text and emoji are kept.
    """
    text = unicodedata.normalize("NFC", str(path))
    cleaned: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch in _UNSAFE_CHARS or code < 0x20 or code == 0x7F:
            cleaned.append("_")
        else:
            cleaned.append(ch)
    segments: list[str] = []
    for raw_segment in "".join(cleaned).split("/"):
        segment = raw_segment.rstrip(" .")
        if segment in ("", "."):
            continue
        if segment == "..":
            segment = "__"
        segments.append(segment)
    if not segments:
        return "/"
    return normalize_logical_path("/".join(segments))


def strip_frontmatter(text: str) -> str:
    """Return ``text`` without its leading ``---`` YAML-ish frontmatter block."""
    match = _FRONTMATTER_RE.match(text)
    if match is None:
        return text
    remainder = text[match.end():]
    if remainder.startswith("\r\n"):
        return remainder[2:]
    if remainder.startswith("\n"):
        return remainder[1:]
    return remainder


class JoplinMirrorImporter:
    """Import a Joplin markdown mirror into a vault (SPEC/04 §2)."""

    name = "joplin_mirror"

    def __init__(
        self,
        mirror_root: Path,
        *,
        mark_secret_globs: list[str] = (),
        default_level: str = "normal",
        include_stray_md: bool = True,
        skip_names: tuple[str, ...] = DEFAULT_SKIP,
        import_assets: bool = True,
    ) -> None:
        """Configure the importer for ``mirror_root``.

        Raises:
            BadRequest: when ``default_level`` is not a known sensitivity level.
        """
        self.mirror_root = Path(mirror_root)
        if default_level not in LEVELS:
            raise BadRequest("unknown_level", details={"level": default_level})
        self.mark_secret_globs = list(mark_secret_globs)
        self.default_level = default_level
        self.include_stray_md = bool(include_stray_md)
        self.skip_names = tuple(skip_names)
        self.import_assets = bool(import_assets)
        self.assets_folder = DEFAULT_ASSETS_FOLDER
        self._assets: dict[str, str] = {}
        self._run_assets: dict[str, str] = {}
        #: Live progress for a UI (plain values, safe to poll from another thread).
        self.progress: dict[str, Any] = {
            "phase": "",
            "phase_done": 0,
            "phase_total": 0,
            "done": 0,
            "total": 0,
            "percent": 0,
            "finished": False,
        }
        self._phase_totals: dict[str, int] = {}
        self._phase_done: dict[str, int] = {}

    # --------------------------------------------------------------------- public
    def run(
        self,
        session: Any,
        *,
        dry_run: bool = False,
        progress: ProgressCallback | None = None,
    ) -> ImportReport:
        """Import the mirror into ``session`` and return the report.

        ``dry_run`` counts everything but writes nothing. :attr:`progress` is updated as the
        run advances so a UI can show a real percentage instead of an indeterminate bar.
        """
        started = now_ms()
        self._run_assets = {}
        self._phase_totals = {}
        self._phase_done = {}
        report = ImportReport(
            source=str(self.mirror_root), started=started, finished=started, dry_run=bool(dry_run)
        )
        report.extra.update(
            {
                "unresolved_refs": [],
                "stray_imported": [],
                "stray_updated": [],
                "stray_skipped": 0,
                "renamed_conflicts": 0,
                "bad_timestamps": 0,
                "assets_rewritten_links": 0,
            }
        )
        self._check_home(session)
        manifest = self._load_manifest()
        self._assets = {
            str(key).lower(): str(value)
            for key, value in (manifest.get("assets") or {}).items()
        }
        for entry in manifest.get("unresolved_refs") or []:
            if isinstance(entry, dict):
                report.extra["unresolved_refs"].append(dict(entry))

        notebooks = list(manifest.get("notebooks") or [])
        notes = list(manifest.get("notes") or [])
        note_paths = {str(note.get("path")) for note in notes if note.get("path")}
        asset_filenames = set(self._assets.values())
        strays = (
            self._stray_candidates(note_paths, asset_filenames)
            if self.include_stray_md
            else []
        )
        # Totals for the progress bar: every phase is known before the work starts (the strays
        # need one cheap scan). Without this the dialog could only show an indeterminate bar.
        self._phase_totals = {
            "folders": len(notebooks),
            "notes": len(notes),
            "assets": len(self._assets) if self.import_assets else 0,
            "strays": len(strays),
        }
        self._phase_done = {name: 0 for name in self._phase_totals}
        self._advance("folders", 0, self._phase_totals["folders"])
        self._import_folders(session, report, notebooks, dry_run)

        tracked = self._tracked_paths(session.index, "joplin:note:")
        total = len(notes)
        for position, note in enumerate(notes, start=1):
            try:
                self._import_note(session, report, note, dry_run, tracked)
            except Exception as exc:  # noqa: BLE001 - one bad note must not stop the run
                self._error(report, str(note.get("path")), exc)
            self._advance("notes", position, total)
            self._tick(progress, "notes", position, total)

        if self.import_assets:
            self._import_all_assets(session, report, dry_run)
        self._import_strays(session, report, strays, dry_run)

        self.progress["finished"] = True
        report.finished = now_ms()
        return report

    # ------------------------------------------------------------------ internals
    def _check_home(self, session: Any) -> None:
        """Refuse to run when the vault home and the mirror overlap."""
        home = Path(session.home).resolve()
        mirror = self.mirror_root.resolve()
        if home == mirror or mirror in home.parents or home in mirror.parents:
            raise BadRequest(
                "vault_home_overlaps_mirror",
                details={"home": str(home), "mirror": str(mirror)},
            )

    def _load_manifest(self) -> dict[str, Any]:
        """Load and parse ``_meta/index.json``."""
        path = self.mirror_root / "_meta" / "index.json"
        if not path.is_file():
            raise BadRequest("mirror_manifest_missing", details={"path": str(path)})
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BadRequest(
                "mirror_manifest_invalid", details={"path": str(path), "error": str(exc)}
            ) from exc
        if not isinstance(data, dict):
            raise BadRequest("mirror_manifest_invalid", details={"path": str(path)})
        return data

    def _import_folders(
        self,
        session: Any,
        report: ImportReport,
        notebooks: Iterable[dict[str, Any]],
        dry_run: bool,
    ) -> None:
        """Create every notebook folder, shallowest first."""
        index = session.index
        ordered = sorted(
            notebooks, key=lambda item: str(item.get("path") or "").count("/")
        )
        for position, notebook in enumerate(ordered, start=1):
            raw = str(notebook.get("path") or notebook.get("name") or "")
            self._advance("folders", position, len(ordered))
            try:
                logical = sanitize(raw)
            except VaultError as exc:
                self._error(report, raw, exc)
                continue
            if logical == "/" or index.get_file(logical) is not None:
                continue
            report.folders_created += 1
            if not dry_run:
                session.mkdir(logical, source=SOURCE_IMPORTER)

    def _import_note(
        self,
        session: Any,
        report: ImportReport,
        note: dict[str, Any],
        dry_run: bool,
        tracked: set[str],
    ) -> None:
        """Create/update/skip one manifest note."""
        index = session.index
        note_id = str(note.get("id"))
        raw_path = str(note.get("path") or "")
        logical = sanitize(raw_path)
        title = str(note.get("title") or "")
        updated = note.get("updated")
        created = note.get("created")
        tags = [str(tag) for tag in (note.get("tags") or []) if str(tag).strip()]
        if note.get("is_todo") and "todo" not in tags:
            tags.append("todo")
        level = self._level_for(logical, title)
        kv_key = f"joplin:note:{note_id}"
        record = self._kv_get(index, kv_key)
        existing = index.get_file(logical)
        file_exists = existing is not None and not int(existing["is_dir"])

        if record is not None and record.get("updated") == updated and file_exists:
            report.notes_skipped += 1
            tracked.add(logical)
            return

        if record is not None and file_exists:
            # Content changed: overwrite but keep the existing level and re-apply tags.
            body = self._prepare_body(
                session, report, note_id, raw_path, str(existing["sensitivity"]), dry_run
            )
            if not dry_run:
                self._write_note(
                    session,
                    logical,
                    body,
                    str(existing["sensitivity"]),
                    updated,
                    created,
                    report,
                )
                if tags:
                    session.set_tags(logical, tags, source=SOURCE_IMPORTER)
                self._kv_set(index, kv_key, {"path": logical, "updated": updated})
            report.notes_updated += 1
            report.tags_applied += len(tags)
            tracked.add(logical)
            return

        target = logical
        if existing is not None and logical not in tracked:
            target = self._unique_path(index, logical)
            report.extra["renamed_conflicts"] += 1
        body = self._prepare_body(session, report, note_id, raw_path, level, dry_run)
        if not dry_run:
            self._write_note(session, target, body, level, updated, created, report)
            if tags:
                session.set_tags(target, tags, source=SOURCE_IMPORTER)
            self._kv_set(index, kv_key, {"path": target, "updated": updated})
        report.notes_created += 1
        report.tags_applied += len(tags)
        tracked.add(target)

    def _prepare_body(
        self,
        session: Any,
        report: ImportReport,
        note_id: str,
        raw_path: str,
        level: str,
        dry_run: bool,
    ) -> bytes:
        """Read a note file, strip its frontmatter and rewrite asset links."""
        source_path = self.mirror_root / raw_path
        text = source_path.read_text(encoding="utf-8", errors="replace")
        body = strip_frontmatter(text)
        if self.import_assets:
            body = self._rewrite_asset_links(session, report, note_id, body, level, dry_run)
        return body.encode("utf-8")

    def _write_note(
        self,
        session: Any,
        logical: str,
        body: bytes,
        level: str,
        updated: Any,
        created: Any,
        report: ImportReport,
    ) -> None:
        """Write a note body and restore its manifest timestamps."""
        row = session.write_file(logical, body, source=SOURCE_IMPORTER, sensitivity=level)
        session.index.upsert_file(
            logical,
            blob_id=row.get("blob_id"),
            is_dir=False,
            size=int(row["size"]),
            encrypted=int(row["encrypted"]),
            sensitivity=row["sensitivity"],
            mtime=self._parse_ts(updated, report),
            created=self._parse_ts(created, report),
            source=SOURCE_IMPORTER,
        )

    def _rewrite_asset_links(
        self,
        session: Any,
        report: ImportReport,
        note_id: str,
        body: str,
        level: str,
        dry_run: bool,
    ) -> str:
        """Rewrite every ``:/<id>`` resource reference to a ``vault:`` link."""
        def replace(match: re.Match[str]) -> str:
            resource_id = match.group(1).lower()
            filename = self._assets.get(resource_id)
            if filename is None:
                self._add_unresolved(report, note_id, resource_id)
                return match.group(0)
            target = self._import_asset(
                session, report, resource_id, filename, level, dry_run
            )
            if target is None:
                self._add_unresolved(report, note_id, resource_id)
                return match.group(0)
            report.extra["assets_rewritten_links"] += 1
            return f"vault:/{target}"

        return _RESOURCE_RE.sub(replace, body)

    def _import_asset(
        self,
        session: Any,
        report: ImportReport,
        resource_id: str,
        filename: str,
        level: str,
        dry_run: bool,
    ) -> str | None:
        """Import one resource binary and return its vault logical path (or None).

        Resources are handled at most once per run: the note-body rewrite pass and the
        whole-manifest pass both go through here, and in a dry run the bookkeeping key is
        never written, so a per-run memo keeps the reported counts identical to a real run.
        """
        already = self._run_assets.get(resource_id)
        if already is not None:
            return already
        source_path = self.mirror_root / "assets" / filename
        if not source_path.is_file():
            return None
        index = session.index
        data = source_path.read_bytes()
        digest = sha256_hex(data)
        kv_key = f"joplin:asset:{resource_id}"
        record = self._kv_get(index, kv_key)
        logical = sanitize(f"{self.assets_folder}/{filename}")
        if record is not None and record.get("sha256") == digest:
            record_path = str(record.get("path") or logical)
            if index.get_file(record_path) is not None:
                report.assets_skipped += 1
                self._run_assets[resource_id] = record_path
                return record_path
        target = logical
        existing = index.get_file(logical)
        if existing is not None and (record is None or record.get("path") != logical):
            target = self._unique_path(index, logical)
            report.extra["renamed_conflicts"] += 1
        if not dry_run:
            session.write_file(target, data, source=SOURCE_IMPORTER, sensitivity=level)
            self._kv_set(
                index,
                kv_key,
                {"path": target, "size": len(data), "sha256": digest},
            )
        report.assets_imported += 1
        self._run_assets[resource_id] = target
        return target

    def _import_all_assets(
        self,
        session: Any,
        report: ImportReport,
        dry_run: bool,
    ) -> None:
        """Import every resource binary the manifest lists, not only the referenced ones.

        Only a handful of note bodies reference their resource by id, but the images and
        files under ``assets/`` are the user's data and must survive the move into the vault
        (SPEC/04 §2.2 rule 6). The importer therefore materialises the whole resource set;
        link rewriting in the note bodies happens independently where refs exist.
        """
        for position, (resource_id, filename) in enumerate(
            sorted(self._assets.items()), start=1
        ):
            self._advance("assets", position, len(self._assets))
            try:
                self._import_asset(
                    session, report, resource_id, filename, self.default_level, dry_run
                )
            except Exception as exc:  # noqa: BLE001 - one bad asset must not stop the run
                self._error(report, f"assets/{filename}", exc)

    def _stray_candidates(
        self, note_paths: set[str], asset_filenames: set[str]
    ) -> list[tuple[Path, str]]:
        """Return every mirror ``*.md`` that the manifest does not describe.

        Computed before the run so the progress bar knows the strays phase's size; the same list
        is what :meth:`_import_strays` then imports.
        """
        found: list[tuple[Path, str]] = []
        if not self.mirror_root.is_dir():
            return found
        for path in sorted(self.mirror_root.rglob("*.md")):
            relative = path.relative_to(self.mirror_root).as_posix()
            parts = relative.split("/")
            if any(part in self.skip_names for part in parts):
                continue
            if relative in note_paths:
                continue
            if parts[0] == "assets" and "/".join(parts[1:]) in asset_filenames:
                continue
            found.append((path, relative))
        return found

    def _import_strays(
        self,
        session: Any,
        report: ImportReport,
        strays: Iterable[tuple[Path, str]],
        dry_run: bool,
    ) -> None:
        """Import stray ``*.md`` files that the manifest does not describe."""
        if not self.include_stray_md:
            return
        items = list(strays)
        for position, (path, relative) in enumerate(items, start=1):
            self._advance("strays", position, len(items))
            try:
                self._import_stray(session, report, path, relative, dry_run)
            except Exception as exc:  # noqa: BLE001 - one bad stray must not stop the run
                self._error(report, relative, exc)

    def _import_stray(
        self,
        session: Any,
        report: ImportReport,
        path: Path,
        relative: str,
        dry_run: bool,
    ) -> None:
        """Import one stray markdown file, tracked by ``joplin:stray:<rel>``."""
        index = session.index
        data = path.read_bytes()
        digest = sha256_hex(data)
        kv_key = f"joplin:stray:{relative}"
        record = self._kv_get(index, kv_key)
        logical = sanitize(relative)
        existing = index.get_file(logical)
        if record is not None and record.get("sha256") == digest and existing is not None:
            report.extra["stray_skipped"] += 1
            return
        level = self._level_for(logical, path.stem)
        target = logical
        if existing is not None and (record is None or record.get("path") != logical):
            target = self._unique_path(index, logical)
            report.extra["renamed_conflicts"] += 1
        if not dry_run:
            session.write_file(target, data, source=SOURCE_IMPORTER, sensitivity=level)
            self._kv_set(
                index,
                kv_key,
                {"path": target, "size": len(data), "sha256": digest},
            )
        if record is not None:
            report.extra["stray_updated"].append(target)
        else:
            report.extra["stray_imported"].append(target)

    # ------------------------------------------------------------------- helpers
    def _level_for(self, logical: str, title: str) -> str:
        """Return the level for a path/title given the ``--mark-secret`` globs."""
        name = logical.lower()
        candidate_title = str(title).lower()
        for pattern in self.mark_secret_globs:
            lowered = str(pattern).lower()
            if fnmatch.fnmatch(name, lowered) or fnmatch.fnmatch(candidate_title, lowered):
                return "secret"
        return self.default_level

    @staticmethod
    def _unique_path(index: Any, logical: str) -> str:
        """Return ``<logical> (imported N).<ext>`` that does not exist yet."""
        stem, dot, extension = logical.rpartition(".")
        if not dot:
            stem, extension = logical, ""
        counter = 2
        while True:
            suffix = f" (imported {counter})"
            candidate = f"{stem}{suffix}.{extension}" if extension else f"{stem}{suffix}"
            if index.get_file(candidate) is None:
                return candidate
            counter += 1

    @staticmethod
    def _parse_ts(value: Any, report: ImportReport) -> int:
        """Convert an ISO-8601 string to epoch milliseconds, counting bad values."""
        if not value:
            report.extra["bad_timestamps"] += 1
            return now_ms()
        text = str(value).strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp() * 1000)
        except ValueError:
            report.extra["bad_timestamps"] += 1
            return now_ms()

    @staticmethod
    def _kv_get(index: Any, key: str) -> dict[str, Any] | None:
        """Return the decoded JSON kv record stored under ``key`` (or None)."""
        raw = index.kv_get(key)
        if raw is None:
            return None
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return decoded if isinstance(decoded, dict) else None

    @staticmethod
    def _kv_set(index: Any, key: str, value: dict[str, Any]) -> None:
        """Store ``value`` as JSON under ``key``."""
        index.kv_set(key, json.dumps(value, ensure_ascii=False, sort_keys=True))

    @staticmethod
    def _tracked_paths(index: Any, prefix: str) -> set[str]:
        """Return the logical paths recorded by the importer's ``prefix`` kv records."""
        rows = index.conn.execute(
            "SELECT value FROM kv WHERE key LIKE ?", (prefix + "%",)
        ).fetchall()
        paths: set[str] = set()
        for row in rows:
            try:
                record = json.loads(row["value"])
            except (TypeError, ValueError):
                continue
            if isinstance(record, dict) and record.get("path"):
                paths.add(str(record["path"]))
        return paths

    @staticmethod
    def _add_unresolved(report: ImportReport, note_id: str, resource_id: str) -> None:
        """Record an unresolved resource reference once."""
        entry = {"note": note_id, "resource": resource_id}
        refs = report.extra["unresolved_refs"]
        if entry not in refs:
            refs.append(entry)

    @staticmethod
    def _error(report: ImportReport, path: str, exc: BaseException) -> None:
        """Append one structured error to the report."""
        code = getattr(exc, "code", type(exc).__name__)
        report.errors.append({"path": path, "error": str(exc), "code": code})

    def _advance(self, phase: str, done: int, total: int) -> None:
        """Record how far ``phase`` has gone and publish the overall percentage.

        The UI polls :attr:`progress` (plain ints and strings, safe from another thread) so the
        dialog can show ``n%  (done/total)`` instead of an indeterminate bar: with 876 notes and
        no feedback the user cannot tell a working import from a stuck one.
        """
        if not self._phase_totals:
            return
        safe_done = max(0, int(done))
        self._phase_done[phase] = safe_done
        overall_total = sum(int(value) for value in self._phase_totals.values()) or 1
        overall_done = sum(
            min(int(self._phase_done.get(name, 0)), max(int(limit), 0))
            for name, limit in self._phase_totals.items()
        )
        self.progress.update(
            phase=phase,
            phase_done=safe_done,
            phase_total=max(0, int(total)),
            done=overall_done,
            total=overall_total,
            percent=int(round(100.0 * overall_done / overall_total)),
        )

    @staticmethod
    def _tick(
        progress: ProgressCallback | None, label: str, done: int, total: int
    ) -> None:
        """Call ``progress`` at most every 25 items."""
        if progress is None:
            return
        if done % 25 == 0 or done == total:
            progress(label, done, total)


__all__ = [
    "DEFAULT_MIRROR",
    "DEFAULT_SKIP",
    "DEFAULT_ASSETS_FOLDER",
    "JoplinMirrorImporter",
    "sanitize",
    "strip_frontmatter",
]
