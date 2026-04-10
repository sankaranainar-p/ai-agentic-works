"""
app/agent_log.py — Thread-safe in-memory agent activity log.

Stores the last MAX_ENTRIES log entries.  All public functions are
safe to call from any thread or asyncio task.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

MAX_ENTRIES = 500

_lock = threading.Lock()
_log: list[dict[str, Any]] = []


def append(entry: dict[str, Any]) -> None:
    """Append *entry* to the log, evicting oldest entries beyond MAX_ENTRIES."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        **entry,
    }
    with _lock:
        _log.append(record)
        if len(_log) > MAX_ENTRIES:
            del _log[: len(_log) - MAX_ENTRIES]


def get_recent(n: int = 50) -> list[dict[str, Any]]:
    """Return the *n* most recent log entries (newest last)."""
    with _lock:
        return list(_log[-n:])


def clear() -> None:
    """Remove all entries from the log."""
    with _lock:
        _log.clear()


def count() -> int:
    """Return the current number of entries in the log."""
    with _lock:
        return len(_log)
