"""SQLite schema + init() for the audit log.

Append-only enforced via BEFORE DELETE and BEFORE UPDATE triggers (AUDIT-01).
The triggers raise RAISE(ABORT, ...) which causes sqlite3.IntegrityError in
Python callers — NOT OperationalError (verified: SQLite 3.53.0, sqlite3.IntegrityError confirmed).

D-01: Single denormalized 'entries' table with indexed metadata columns and
a canonical-JSON payload column.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

# D-01: Single denormalized table per the plan. All metadata columns indexed
# for the AUDIT-05 filters. Payload is canonical-JSON (rfc8785) of event-specific fields.
_DDL = """
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    algo_version TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    channel_id TEXT,
    envelope_id TEXT,
    timestamp TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_channel    ON entries(channel_id);
CREATE INDEX IF NOT EXISTS idx_entries_envelope   ON entries(envelope_id);
CREATE INDEX IF NOT EXISTS idx_entries_timestamp  ON entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_entries_event_type ON entries(event_type);
"""

# AUDIT-01: append-only enforcement via SQLite triggers.
# RAISE(ABORT, ...) → sqlite3.IntegrityError (NOT OperationalError — verified).
_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS entries_no_delete
    BEFORE DELETE ON entries
BEGIN
    SELECT RAISE(ABORT, 'append-only: entries table is immutable by design');
END;
CREATE TRIGGER IF NOT EXISTS entries_no_update
    BEFORE UPDATE ON entries
BEGIN
    SELECT RAISE(ABORT, 'append-only: entries table is immutable by design');
END;
"""


def connect(path: Path | str) -> sqlite3.Connection:
    """Open (or create) the audit log SQLite database.

    Uses WAL journal mode for better concurrency on macOS / Linux.
    isolation_level=None = autocommit; we manage our own transaction semantics
    via INSERT (atomic at the row level in WAL mode).
    """
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init(conn: sqlite3.Connection) -> None:
    """Create schema and triggers on a fresh connection. Idempotent (IF NOT EXISTS)."""
    conn.executescript(_DDL)
    conn.executescript(_TRIGGERS)
