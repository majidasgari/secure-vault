"""Spaced repetition ("learning") for the notes the user chose to keep in mind.

A note that enters learning comes back as a flashcard after 1, 2, 4, 8, 16 and 32 days, each
interval counted from the previous review. The schedule is therefore one number — the stage, how
many reviews have happened — plus the moment the next one is due.

The state is plaintext metadata on the file (the ``learning`` table in ``meta.sqlite``), like an
emoji label: it survives a rename, it is readable while locked, and it travels to the read-only
phone client with the rest of the metadata. No note content is involved.

The arithmetic lives here, free of Qt/SQLite, so both clients schedule identically and the rules
can be tested without a vault.
"""

from __future__ import annotations

DAY_MS = 24 * 60 * 60 * 1000

#: Days until the next review, one entry per stage; after the last one the cycle is over.
INTERVALS_DAYS: tuple[int, ...] = (1, 2, 4, 8, 16, 32)

TOTAL_STAGES = len(INTERVALS_DAYS)


def next_due(now: int, stage: int) -> int:
    """Return when a card at ``stage`` (reviews done so far) is due; 0 when nothing is left."""
    stage = int(stage)
    if stage < 0 or stage >= TOTAL_STAGES:
        return 0
    return int(now) + INTERVALS_DAYS[stage] * DAY_MS


def started(now: int) -> tuple[int, int]:
    """Return ``(stage, due)`` for a note entering learning now: first card tomorrow."""
    return 0, next_due(now, 0)


def reviewed(now: int, stage: int) -> tuple[int, int]:
    """Return ``(stage, due)`` after a review; ``due == 0`` means the cycle is finished."""
    stage = min(int(stage) + 1, TOTAL_STAGES)
    return stage, next_due(now, stage)


def is_due(due: int, now: int) -> bool:
    """True when a card should be shown now (0 = a finished cycle, never due)."""
    return 0 < int(due) <= int(now)


def days_overdue(due: int, now: int) -> int:
    """Whole days a due card is late (0 on the day it falls due)."""
    if not is_due(due, now):
        return 0
    return max(0, (int(now) - int(due)) // DAY_MS)


def days_left(due: int, now: int) -> int:
    """Whole days until a card falls due (0 once it is due, at least 1 while it is ahead)."""
    due, now = int(due), int(now)
    if due <= now:
        return 0
    return max(1, -(-(due - now) // DAY_MS))


def is_complete(stage: int) -> bool:
    """True when every review of the cycle has happened."""
    return int(stage) >= TOTAL_STAGES


__all__ = [
    "DAY_MS",
    "INTERVALS_DAYS",
    "TOTAL_STAGES",
    "days_left",
    "days_overdue",
    "is_complete",
    "is_due",
    "next_due",
    "reviewed",
    "started",
]
