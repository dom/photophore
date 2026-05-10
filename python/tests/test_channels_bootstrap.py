"""Test bootstrap() — D-05 keystore-as-truth startup verification.

Tests verify:
- Empty keystore + empty channels.db: bootstrap() returns success (bootstrapped: 0)
- Channel with audit entry + missing channels.db row: bootstrap() rebuilds the row
- Channel in _index with no channel.created audit entry: bootstrap() raises UnauditedChannelError
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import keyring
import pytest

from photophore.audit import AuditLog
from photophore.channels import bootstrap, ChannelStore, ChannelState
from photophore.channels._index import add_to_index, get_index
from photophore.channels._keystore import _set_channel
from photophore.errors import UnauditedChannelError


def test_bootstrap_empty_keystore_returns_zero(
    tmp_path: Path,
    in_memory_keyring: object,
) -> None:
    """bootstrap() on empty keystore + empty audit.db returns {bootstrapped: 0}."""
    audit = AuditLog(tmp_path / "audit.db")
    result = bootstrap(audit, str(tmp_path / "channels.db"))
    assert result == {"bootstrapped": 0, "rebuilt": 0}


def test_bootstrap_halts_on_unaudited_channel(
    tmp_path: Path,
    in_memory_keyring: object,
) -> None:
    """D-05: channel in _index with no channel.created event -> UnauditedChannelError."""
    audit = AuditLog(tmp_path / "audit.db")

    # Seed keystore: channel record + _index entry but NO audit event.
    channel_id = "test-channel-unaudited-id"
    _set_channel(channel_id, {
        "id": channel_id, "local_node": "alice", "remote_node": "bob",
        "ceiling": "tier-1", "key_scheme": "brine", "state": "PROPOSED",
        "created_at": "2026-05-09T00:00:00.000Z", "creator_identity": "alice",
        "description": "", "remote_pubkey_hex": None,
    })
    add_to_index(channel_id)
    # No audit.append(channel.created) — this is the unaudited state

    with pytest.raises(UnauditedChannelError) as exc_info:
        bootstrap(audit, str(tmp_path / "channels.db"))
    assert channel_id in str(exc_info.value)


def test_bootstrap_rebuilds_channels_db_from_keystore(
    tmp_path: Path,
    in_memory_keyring: object,
) -> None:
    """D-05: channel with audit entry but missing channels.db row gets rebuilt."""
    audit = AuditLog(tmp_path / "audit.db")
    channels_db_path = str(tmp_path / "channels.db")

    # Use ChannelStore to create a channel properly (all 3 stores updated).
    store = ChannelStore(tmp_path / "channels.db", audit)
    ch = store.create(
        remote_node="bob", ceiling="tier-1", key_scheme="brine",
        local_node="alice", creator_identity="alice",
    )

    # Now delete channels.db to simulate drift.
    (tmp_path / "channels.db").unlink()
    # Also delete WAL files if they exist
    for wal in [tmp_path / "channels.db-wal", tmp_path / "channels.db-shm"]:
        if wal.exists():
            wal.unlink()

    # bootstrap() must rebuild channels.db from keystore.
    result = bootstrap(audit, channels_db_path)
    assert result["bootstrapped"] == 1
    assert result["rebuilt"] == 1

    # Verify the rebuilt row exists in channels.db.
    conn = sqlite3.connect(channels_db_path)
    cur = conn.execute("SELECT id FROM channels WHERE id = ?", (str(ch.id),))
    row = cur.fetchone()
    conn.close()
    assert row is not None, "channels.db row was not rebuilt"


def test_bootstrap_orphan_in_index_is_removed(
    tmp_path: Path,
    in_memory_keyring: object,
) -> None:
    """bootstrap(): _index has a channel_id with no keystore record -> stripped from index."""
    audit = AuditLog(tmp_path / "audit.db")

    # Add an orphan id to the index (no corresponding keystore record).
    orphan_id = "orphan-channel-no-keystore-record"
    add_to_index(orphan_id)

    # bootstrap() should strip the orphan and NOT raise (not UnauditedChannelError).
    result = bootstrap(audit, str(tmp_path / "channels.db"))
    # bootstrapped counts the initial _index length (1 orphan was present but stripped)
    assert isinstance(result, dict)

    # The orphan should be gone from the index.
    ids = get_index()
    assert orphan_id not in ids
