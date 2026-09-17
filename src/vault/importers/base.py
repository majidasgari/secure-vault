"""Base contract for importers (SPEC/04 §1).

Every importer walks an external source and materialises it into a
:class:`~vault.core.session.VaultSession`, returning an :class:`ImportReport`. A dry run
walks and counts exactly like a real run but writes nothing, so the vault stays
byte-identical.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Protocol, runtime_checkable

from ..core.session import VaultSession

ProgressCallback = Callable[[str, int, int], None]


@dataclass
class ImportReport:
    """The outcome of an importer run (SPEC/04 §1)."""

    source: str
    started: int
    finished: int
    notes_created: int = 0
    notes_updated: int = 0
    notes_skipped: int = 0
    folders_created: int = 0
    assets_imported: int = 0
    assets_skipped: int = 0
    tags_applied: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        """True when the run recorded no errors."""
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the report."""
        return asdict(self)

    def to_markdown(self) -> str:
        """Render the report as the markdown written to ``docs/reports/``."""
        lines: list[str] = [
            "# Joplin import report",
            "",
            f"- Source: `{self.source}`",
            f"- Dry run (nothing written): {'yes' if self.dry_run else 'no'}",
            f"- Started (epoch ms): {self.started}",
            f"- Finished (epoch ms): {self.finished}",
            "",
            "| metric | count |",
            "|---|---|",
        ]
        for label, value in (
            ("notes_created", self.notes_created),
            ("notes_updated", self.notes_updated),
            ("notes_skipped", self.notes_skipped),
            ("folders_created", self.folders_created),
            ("assets_imported", self.assets_imported),
            ("assets_skipped", self.assets_skipped),
            ("tags_applied", self.tags_applied),
            ("errors", len(self.errors)),
        ):
            lines.append(f"| {label} | {value} |")
        lines.append("")
        if self.extra:
            lines.append("## Extra")
            lines.append("")
            for key, value in self.extra.items():
                lines.append(f"- **{key}**: {value}")
            lines.append("")
        lines.append("## Errors")
        lines.append("")
        if self.errors:
            for error in self.errors:
                lines.append(
                    f"- `{error.get('path')}`: {error.get('error')} "
                    f"({error.get('code')})"
                )
        else:
            lines.append("_none_")
        lines.append("")
        return "\n".join(lines)


@runtime_checkable
class Importer(Protocol):
    """Structural contract implemented by every importer."""

    name: str

    def run(
        self,
        session: VaultSession,
        *,
        dry_run: bool = False,
        progress: ProgressCallback | None = None,
    ) -> ImportReport:
        """Import into ``session`` and return the report.

        ``dry_run`` walks and counts everything while writing nothing. ``progress`` is
        called at most every 25 items with ``(label, done, total)``.
        """
        ...


__all__ = ["ImportReport", "Importer", "ProgressCallback"]
