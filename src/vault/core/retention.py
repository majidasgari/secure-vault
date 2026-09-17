"""Access-log retention: owner-side housekeeping, never reachable by an agent.

The access log is an audit trail and stays append-only from the vault's own data layer
(``vault.core.index`` has no DELETE for it — ``tests/invariants_source.py`` checks exactly that).
This module is the one place that trims it, and it is called only from the *local* session
lifecycle (unlock / lock), i.e. by the person who owns the vault, never through the API or MCP.

Without a bound the log grows for as long as anything watches the vault: measured on a real
vault it was ~2.3 rows/second while the web UI polled, which is what filled the disk.
"""

from __future__ import annotations

import logging
from typing import Any

from ..util import now_ms

LOG = logging.getLogger("vault.core.retention")

#: Newest rows kept (per vault). Older rows are removed, newest first.
KEEP_ROWS = 5000
#: Rows older than this many days are removed as well.
MAX_AGE_DAYS = 30


def prune_access_log(
    index: Any, *, keep_rows: int = KEEP_ROWS, max_age_days: int = MAX_AGE_DAYS
) -> int:
    """Trim the access log and return how many rows were removed.

    ``keep_rows`` is applied first (keeping the newest), then the age cut-off.
    """
    conn = getattr(index, "conn", None)
    if conn is None:
        return 0
    removed = 0
    if keep_rows > 0:
        cur = conn.execute(
            "DELETE FROM access_log WHERE id NOT IN ("
            "  SELECT id FROM access_log ORDER BY id DESC LIMIT ?)",
            (int(keep_rows),),
        )
        removed += int(cur.rowcount or 0)
    if max_age_days > 0:
        cutoff = now_ms() - int(max_age_days) * 86400_000
        cur = conn.execute("DELETE FROM access_log WHERE ts < ?", (cutoff,))
        removed += int(cur.rowcount or 0)
    if removed:
        conn.commit()
        LOG.info("pruned %d old access-log rows", removed)
    return removed


__all__ = ["prune_access_log", "KEEP_ROWS", "MAX_AGE_DAYS"]
