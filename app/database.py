"""
app/database.py — Async SQLite persistence for incidents.

DB file: ./data/incidents.db  (relative to project root, created on init)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosqlite

_DB_PATH = Path(__file__).parent.parent / "data" / "incidents.db"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS incidents (
    id                  TEXT PRIMARY KEY,
    started_at          TEXT,
    resolved_at         TEXT,
    source              TEXT,
    alert_text          TEXT,
    category            TEXT,
    severity            TEXT,
    confidence          REAL,
    llm_status          TEXT,
    agreement           INTEGER,
    rca_source          TEXT,
    action_taken        TEXT,
    escalated           INTEGER,
    verification_status TEXT,
    full_json           TEXT
);
"""


async def init_db() -> None:
    """Create the data/ directory and incidents table if they don't exist."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(_CREATE_TABLE)
        await db.commit()


async def save_incident(record: dict[str, Any]) -> None:
    """Insert or replace a full incident record."""
    c = record.get("classification", {})
    rem = record.get("remediation", {})
    ver = record.get("verification", {})

    # llm_status: "used" | "skipped"
    llm_status = "used" if c.get("source") == "llm" else "skipped"
    # agreement: 1 if ML and LLM agreed on category (not stored separately, approximate from source)
    agreement = 1 if c.get("source") == "ml" else 0

    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO incidents
                (id, started_at, resolved_at, source, alert_text,
                 category, severity, confidence,
                 llm_status, agreement, rca_source,
                 action_taken, escalated, verification_status, full_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                record.get("id"),
                record.get("started_at"),
                record.get("resolved_at"),
                record.get("source"),
                record.get("alert_text"),
                c.get("category"),
                c.get("severity"),
                c.get("confidence"),
                llm_status,
                agreement,
                record.get("rca", {}).get("source"),
                rem.get("action_taken"),
                int(bool(rem.get("escalated"))),
                ver.get("status"),
                json.dumps(record),
            ),
        )
        await db.commit()


async def get_incidents(limit: int = 50) -> list[dict[str, Any]]:
    """Return the *limit* most recent incidents, newest last."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT full_json FROM incidents ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
    # Reverse so oldest is first (matches previous list behaviour)
    return [json.loads(row["full_json"]) for row in reversed(rows)]


async def get_stats() -> dict[str, Any]:
    """Compute stats directly from SQLite."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        async with db.execute("SELECT COUNT(*) AS total FROM incidents") as cur:
            total = (await cur.fetchone())["total"]

        if total == 0:
            return {"total": 0}

        async with db.execute(
            "SELECT COUNT(*) AS n FROM incidents WHERE verification_status = 'resolved'"
        ) as cur:
            resolved = (await cur.fetchone())["n"]

        async with db.execute(
            "SELECT category, COUNT(*) AS n FROM incidents GROUP BY category"
        ) as cur:
            by_category = {row["category"]: row["n"] for row in await cur.fetchall()}

        async with db.execute(
            "SELECT severity, COUNT(*) AS n FROM incidents GROUP BY severity"
        ) as cur:
            by_severity = {row["severity"]: row["n"] for row in await cur.fetchall()}

    return {
        "total": total,
        "resolved": resolved,
        "unresolved": total - resolved,
        "by_category": by_category,
        "by_severity": by_severity,
    }
