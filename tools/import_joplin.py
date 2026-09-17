#!/usr/bin/env python3
"""Import a Joplin markdown mirror into a Secure Vault (SPEC/04 §2.4).

Reads the master password from a ``0600`` file (never argv, never stdin), unlocks the
vault, runs :class:`~vault.importers.joplin_mirror.JoplinMirrorImporter`, writes the
markdown report and exits ``0`` when there were no errors (``1`` otherwise, unless
``--allow-errors``).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from vault.core.session import VaultSession  # noqa: E402
from vault.errors import BadRequest, VaultError  # noqa: E402
from vault.importers.base import ImportReport  # noqa: E402
from vault.importers.joplin_mirror import (  # noqa: E402
    DEFAULT_MIRROR,
    DEFAULT_SKIP,
    JoplinMirrorImporter,
)

LOG = logging.getLogger("vault.import_joplin")

SEED_EXAMPLE = """# خدمت: <name>

username: <نام کاربری>
password: <گذرواژه>
url: <نشانی سرویس>
notes: <یادداشت>

---

این پرونده یک نمونه است. برای هر سرویس یک پرونده بسازید و سطح آن را روی
«secretfile» بگذارید؛ هیچ‌گاه گذرواژه‌ها را در پرونده‌های «normal» نگه ندارید.
"""


def build_parser() -> argparse.ArgumentParser:
    """Return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="import_joplin.py",
        description="Import a Joplin markdown mirror into a Secure Vault.",
    )
    parser.add_argument("--home", required=True, help="vault home directory")
    parser.add_argument(
        "--unlock-file",
        required=True,
        help="0600 file holding the master password (never argv/stdin)",
    )
    parser.add_argument(
        "--mirror",
        default=str(DEFAULT_MIRROR),
        help=f"Joplin mirror root (default: {DEFAULT_MIRROR})",
    )
    parser.add_argument(
        "--mark-secret",
        action="append",
        default=[],
        metavar="GLOB",
        help="import notes matching GLOB (path or title) as secret (repeatable)",
    )
    parser.add_argument(
        "--default-level",
        choices=("normal", "secret"),
        default="normal",
        help="sensitivity for imported notes and assets (default: normal)",
    )
    parser.add_argument("--dry-run", action="store_true", help="count only; write nothing")
    parser.add_argument(
        "--no-assets", dest="assets", action="store_false", help="do not import assets"
    )
    parser.add_argument(
        "--no-stray", dest="stray", action="store_false", help="do not import stray markdown"
    )
    parser.add_argument(
        "--no-skip",
        dest="skip",
        action="store_false",
        help="do not skip mirror tooling (_index.md, _meta/, README.md, ...)",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="report path (default: docs/reports/joplin-import-<UTC>.md)",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument(
        "--allow-errors", action="store_true", help="exit 0 even when errors were recorded"
    )
    parser.add_argument(
        "--seed-example",
        action="store_true",
        help="create secrets/EXAMPLE.md documenting the credential shape",
    )
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    return parser


def _read_password(path: Path) -> str:
    """Read the master password from a 0600 file.

    Raises:
        BadRequest: when the file is missing or unreadable.
    """
    path = Path(path)
    if not path.is_file():
        raise BadRequest("unlock_file_missing", details={"path": str(path)})
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        LOG.warning("unlock file %s is group/world readable (mode %o)", path, mode)
    try:
        return path.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise BadRequest(
            "unlock_file_unreadable", details={"path": str(path), "error": str(exc)}
        ) from exc


def _seed_example(session: VaultSession) -> None:
    """Create ``secrets/EXAMPLE.md`` (normal) documenting the credential shape."""
    path = "secrets/EXAMPLE.md"
    if session.index.get_file(path) is None:
        session.write_file(path, SEED_EXAMPLE.encode("utf-8"))


def _write_report(report: ImportReport, report_path: str | None) -> Path:
    """Write the markdown report and return the path used."""
    if report_path:
        path = Path(report_path)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = REPO_ROOT / "docs" / "reports" / f"joplin-import-{stamp}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.to_markdown(), encoding="utf-8")
    return path


def _summary(report: ImportReport) -> str:
    """Return a one-line human summary of the report."""
    return (
        f"created={report.notes_created} updated={report.notes_updated} "
        f"skipped={report.notes_skipped} folders={report.folders_created} "
        f"assets={report.assets_imported}/{report.assets_skipped} "
        f"tags={report.tags_applied} errors={len(report.errors)}"
    )


def main(argv: list[str] | None = None) -> int:
    """Run the importer CLI and return the process exit code."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    home = Path(args.home)
    session: VaultSession | None = None
    try:
        password = _read_password(Path(args.unlock_file))
        if not VaultSession.is_initialised(home):
            raise BadRequest("vault_not_initialised", details={"home": str(home)})
        session = VaultSession(home)
        session.unlock(password)
        if args.seed_example and not args.dry_run:
            _seed_example(session)
        importer = JoplinMirrorImporter(
            Path(args.mirror),
            mark_secret_globs=list(args.mark_secret),
            default_level=args.default_level,
            include_stray_md=args.stray,
            skip_names=DEFAULT_SKIP if args.skip else (),
            import_assets=args.assets,
        )

        def progress(label: str, done: int, total: int) -> None:
            """Print a one-line progress marker every 100 items."""
            if done % 100 == 0 or done == total:
                print(f"[{label}] {done}/{total}")

        report = importer.run(session, dry_run=args.dry_run, progress=progress)
        report_path = _write_report(report, args.report)
        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(_summary(report))
        print(f"report: {report_path}", file=sys.stderr)
        if report.errors and not args.allow_errors:
            return 1
        return 0
    except VaultError as exc:
        print(f"error: {exc.code}: {exc.message}", file=sys.stderr)
        return 1
    finally:
        if session is not None:
            session.close()


if __name__ == "__main__":
    raise SystemExit(main())
