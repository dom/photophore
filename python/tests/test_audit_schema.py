"""Test audit log schema and append-only trigger behavior (AUDIT-01).

Tests verify:
- Schema created correctly (columns + indexes)
- INSERT succeeds on a fresh connection
- DELETE raises sqlite3.IntegrityError (NOT OperationalError — verified against SQLite 3.53.0)
- UPDATE raises sqlite3.IntegrityError
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from photophore.audit._schema import connect, init


def test_schema_creates_entries_table(tmp_path: Path) -> None:
    conn = connect(tmp_path / "audit.db")
    init(conn)
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='entries'"
    )
    assert cur.fetchone() is not None, "entries table not created"


def test_schema_creates_all_nine_columns(tmp_path: Path) -> None:
    conn = connect(tmp_path / "audit.db")
    init(conn)
    cur = conn.execute("PRAGMA table_info(entries)")
    cols = {row[1] for row in cur.fetchall()}
    expected = {
        "id", "algo_version", "prev_hash", "entry_hash",
        "event_type", "channel_id", "envelope_id", "timestamp", "payload",
    }
    assert expected == cols, f"Missing columns: {expected - cols}"


def test_schema_creates_indexes(tmp_path: Path) -> None:
    conn = connect(tmp_path / "audit.db")
    init(conn)
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='entries'"
    )
    indexes = {row[0] for row in cur.fetchall()}
    required = {
        "idx_entries_channel",
        "idx_entries_envelope",
        "idx_entries_timestamp",
        "idx_entries_event_type",
    }
    assert required.issubset(indexes), f"Missing indexes: {required - indexes}"


def test_insert_succeeds(tmp_path: Path) -> None:
    """Normal INSERT works (the append path)."""
    conn = connect(tmp_path / "audit.db")
    init(conn)
    conn.execute(
        "INSERT INTO entries (id, algo_version, prev_hash, entry_hash, "
        "event_type, channel_id, envelope_id, timestamp, payload) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("id-1", "blake3-v1", "", "deadbeef", "channel.created",
         None, None, "2026-05-09T00:00:00.000Z", "{}"),
    )
    cur = conn.execute("SELECT COUNT(*) FROM entries")
    assert cur.fetchone()[0] == 1


def test_delete_raises_integrity_error(tmp_path: Path) -> None:
    """AUDIT-01: DELETE raises sqlite3.IntegrityError (NOT OperationalError)."""
    conn = connect(tmp_path / "audit.db")
    init(conn)
    conn.execute(
        "INSERT INTO entries (id, algo_version, prev_hash, entry_hash, "
        "event_type, channel_id, envelope_id, timestamp, payload) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("id-1", "blake3-v1", "", "deadbeef", "channel.created",
         None, None, "2026-05-09T00:00:00.000Z", "{}"),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM entries WHERE id = 'id-1'")


def test_update_raises_integrity_error(tmp_path: Path) -> None:
    """AUDIT-01: UPDATE raises sqlite3.IntegrityError."""
    conn = connect(tmp_path / "audit.db")
    init(conn)
    conn.execute(
        "INSERT INTO entries (id, algo_version, prev_hash, entry_hash, "
        "event_type, channel_id, envelope_id, timestamp, payload) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("id-1", "blake3-v1", "", "deadbeef", "channel.created",
         None, None, "2026-05-09T00:00:00.000Z", "{}"),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE entries SET payload = '{}' WHERE id = 'id-1'")


def test_schema_is_idempotent(tmp_path: Path) -> None:
    """init() can be called multiple times without error (IF NOT EXISTS guards)."""
    conn = connect(tmp_path / "audit.db")
    init(conn)
    init(conn)  # second call must not raise
    cur = conn.execute("SELECT COUNT(*) FROM entries")
    assert cur.fetchone()[0] == 0
