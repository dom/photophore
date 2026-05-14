"""ChannelStore: channel lifecycle management with D-07 three-step write ordering.

D-04: Three discrete stores:
1. Trust store (python-keyring) — authoritative; accessed via _keystore.py
2. Channel index (channels.db) — derived projection; this file manages the SQLite schema
3. Audit log (audit.db) — witness; referenced via self._audit (AuditLog instance)

D-07 write ordering for channel create/transition/ceiling ops:
  Step 1: keystore.set(channel_record) + _index.add_to_index(channel_id)
  Step 2: audit.append(event)   <- BEFORE step 3; CHAN-05 mandates audit before report
  Step 3: channels.db.upsert(index_row)

If step 2 fails after step 1: bootstrap() halts at next startup (unaudited channel).
If step 3 fails after step 2: bootstrap() rebuilds channels.db from keystore on drift.
"""
from __future__ import annotations

import sqlite3
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..audit._store import AuditLog
from ..core import AuditEventType, ChannelId, ChannelState
from ..errors import ChannelStateError, KeystoreUnavailableError
from ._keystore import _probe_keystore, _get_channel, _set_channel
from ._index import add_to_index
from ._types import Channel

__all__ = [
    "ChannelStore",
    "_connect_channels_db",
    "_dict_to_channel",
    "_upsert_channels_db_raw",
]

# Trust ceiling rank for CHAN-03 raise vs lower detection.
_CEILING_RANK: dict[str, int] = {
    "tier-0": 0,
    "tier-1": 1,
    "tier-2": 2,
}

_CHANNELS_DDL = """
CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY,
    local_node TEXT NOT NULL,
    remote_node TEXT NOT NULL,
    ceiling TEXT NOT NULL,
    key_scheme TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_channels_remote ON channels(remote_node);
CREATE INDEX IF NOT EXISTS idx_channels_state  ON channels(state);
"""


def _connect_channels_db(path: str) -> sqlite3.Connection:
    """Open (or create) the channels index SQLite database."""
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript(_CHANNELS_DDL)
    return conn


def _channel_to_dict(channel: Channel) -> dict[str, Any]:
    """Serialize a Channel to a dict for JSON keystore storage."""
    return {
        "id": str(channel.id),
        "local_node": channel.local_node,
        "remote_node": channel.remote_node,
        "ceiling": channel.ceiling,
        "key_scheme": channel.key_scheme,
        "state": channel.state.value,
        "created_at": channel.created_at,
        "creator_identity": channel.creator_identity,
        "description": channel.description,
        "remote_pubkey_hex": channel.remote_pubkey_hex,
    }


def _dict_to_channel(d: dict[str, Any]) -> Channel:
    """Deserialize a Channel from a keystore dict."""
    return Channel(
        id=ChannelId(str(d["id"])),
        local_node=str(d["local_node"]),
        remote_node=str(d["remote_node"]),
        ceiling=str(d["ceiling"]),
        key_scheme=str(d["key_scheme"]),
        state=ChannelState(str(d["state"])),
        created_at=str(d["created_at"]),
        creator_identity=str(d["creator_identity"]),
        description=str(d.get("description", "")),
        remote_pubkey_hex=str(d["remote_pubkey_hex"]) if d.get("remote_pubkey_hex") else None,
    )


def _upsert_channels_db_raw(conn: sqlite3.Connection, channel: Channel) -> None:
    """Upsert a channels.db row using an existing connection.

    Shared by ChannelStore._upsert_channels_db (step 3 of D-07) and
    bootstrap._rebuild_from_keystore (drift recovery).
    """
    now = (
        datetime.now(tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    conn.execute(
        "INSERT INTO channels "
        "(id, local_node, remote_node, ceiling, key_scheme, state, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "  ceiling=excluded.ceiling, key_scheme=excluded.key_scheme, "
        "  state=excluded.state, updated_at=excluded.updated_at",
        (
            str(channel.id),
            channel.local_node,
            channel.remote_node,
            channel.ceiling,
            channel.key_scheme,
            channel.state.value,
            channel.created_at,
            now,
        ),
    )


class ChannelStore:
    """Channel lifecycle manager using the D-04 three-store model.

    Must be instantiated with an AuditLog that points to a DIFFERENT file than
    the channels.db — D-04 three-store separation (AT-A5 structural defense).
    """

    def __init__(self, channels_db_path: Path | str, audit_log: AuditLog) -> None:
        self._channels_db_path = str(channels_db_path)
        self._conn = _connect_channels_db(self._channels_db_path)
        self._audit = audit_log
        # Isinstance probe — refuse to start if keystore unavailable.
        _probe_keystore()

    @property
    def channels_db_path(self) -> str:
        """Absolute path to channels.db (the derived index, NOT the trust store)."""
        return self._channels_db_path

    def _upsert_channels_db(self, channel: Channel) -> None:
        """Upsert a channels.db row (D-07 step 3)."""
        _upsert_channels_db_raw(self._conn, channel)

    def create(
        self,
        *,
        remote_node: str,
        ceiling: str,
        key_scheme: str,
        local_node: str,
        creator_identity: str,
        description: str = "",
        remote_pubkey_hex: str | None = None,
    ) -> Channel:
        """Create a new channel record using D-07 three-step write ordering.

        CHAN-01: assigns UUIDv4 id, records remote_node, ceiling, key_scheme.
        CHAN-05: audit entry appended BEFORE channels.db upsert.
        """
        channel_id = ChannelId(str(uuid.uuid4()))
        now = (
            datetime.now(tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        channel = Channel(
            id=channel_id,
            local_node=local_node,
            remote_node=remote_node,
            ceiling=ceiling,
            key_scheme=key_scheme,
            state=ChannelState.PROPOSED,
            created_at=now,
            creator_identity=creator_identity,
            description=description,
            remote_pubkey_hex=remote_pubkey_hex,
        )
        # D-07 STEP 1: keystore (authoritative trust store) + _index sentinel.
        _set_channel(channel_id, _channel_to_dict(channel))
        add_to_index(channel_id)  # _index sentinel keeps keystore enumerable

        # D-07 STEP 2: audit append BEFORE reporting success (CHAN-05).
        self._audit.append(
            event_type=AuditEventType.CHANNEL_CREATED,
            channel_id=str(channel_id),
            payload={
                "remote_node": remote_node,
                "ceiling": ceiling,
                "key_scheme": key_scheme,
                "local_node": local_node,
                "creator_identity": creator_identity,
                "created_at": now,
                "description": description,
                "remote_pubkey_hex": remote_pubkey_hex,
            },
        )

        # D-07 STEP 3: channels.db upsert (derived projection).
        self._upsert_channels_db(channel)
        return channel

    def list_channels(self) -> list[Channel]:
        """Return all channels, resolving each from the keystore (W9).

        Reads channels.db for the id list, then resolves each channel's
        authoritative record from the keystore (D-05 keystore-as-truth).
        """
        cur = self._conn.execute("SELECT id FROM channels ORDER BY created_at")
        rows = cur.fetchall()
        out: list[Channel] = []
        for row in rows:
            full_record = _get_channel(str(row[0]))
            if full_record is None:
                raise KeystoreUnavailableError(
                    f"channels.db references missing keystore entry: {row[0]!r}",
                    code="KEYSTORE_UNAVAILABLE",
                )
            out.append(_dict_to_channel(full_record))
        return out

    def show(self, channel_id: ChannelId) -> Channel:
        """Read a single channel from the keystore (authoritative deep read)."""
        record = _get_channel(str(channel_id))
        if record is None:
            raise KeystoreUnavailableError(
                f"channel {channel_id!r} not found in keystore",
                code="KEYSTORE_UNAVAILABLE",
            )
        return _dict_to_channel(record)

    def transition_to(self, channel_id: ChannelId, new_state: ChannelState) -> Channel:
        """Transition a channel to a new state (D-07 write ordering, CHAN-02)."""
        old = self.show(channel_id)
        new = old.transition_to(new_state)  # raises ChannelStateError if invalid (CHAN-02)

        _set_channel(channel_id, _channel_to_dict(new))
        event_map: dict[ChannelState, str] = {
            ChannelState.OPEN: AuditEventType.CHANNEL_OPENED,
            ChannelState.SUSPENDED: AuditEventType.CHANNEL_SUSPENDED,
            ChannelState.CLOSED: AuditEventType.CHANNEL_CLOSED,
            ChannelState.PROPOSED: AuditEventType.CHANNEL_CREATED,
        }
        event = event_map[new_state]
        self._audit.append(
            event_type=event,
            channel_id=str(channel_id),
            payload={"from_state": old.state.value, "to_state": new_state.value},
        )
        self._upsert_channels_db(new)
        return new

    def set_ceiling(self, channel_id: ChannelId, new_ceiling: str) -> Channel:
        """Change the channel's trust ceiling (CHAN-03 distinct event types).

        CHAN-03: ceiling LOWER emits channel.ceiling_lowered;
                 ceiling RAISE emits channel.ceiling_raised (DISTINCT event type).
        """
        old = self.show(channel_id)
        old_rank = _CEILING_RANK.get(old.ceiling, -1)
        new_rank = _CEILING_RANK.get(new_ceiling, -1)
        if new_rank == old_rank:
            return old  # no-op; no audit event
        new = replace(old, ceiling=new_ceiling)
        _set_channel(channel_id, _channel_to_dict(new))
        event = (
            AuditEventType.CHANNEL_CEILING_RAISED
            if new_rank > old_rank
            else AuditEventType.CHANNEL_CEILING_LOWERED
        )
        self._audit.append(
            event_type=event,
            channel_id=str(channel_id),
            payload={"from_ceiling": old.ceiling, "to_ceiling": new_ceiling},
        )
        self._upsert_channels_db(new)
        return new
