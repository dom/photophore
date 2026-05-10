"""bootstrap(): keystore-as-truth startup check (D-05).

Walks the _index sentinel, verifies each channel_id has:
1. A keystore record (_get_channel returns non-None)
2. A channel.created audit entry in the audit log

If condition 1 fails: orphan stripped from _index (index drift, recoverable).
If condition 2 fails: HALT — raise UnauditedChannelError. The node refuses to operate
until manual reconciliation. This is the D-05 "keystore-as-truth" invariant.

bootstrap() also rebuilds channels.db from keystore if drift is detected
(missing rows in channels.db for channels that DO exist in the keystore with valid audit).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ..audit._store import AuditLog
from ..core import AuditEventType
from ..errors import UnauditedChannelError
from ._index import get_index, remove_from_index
from ._keystore import _get_channel
from ._store import _connect_channels_db, _dict_to_channel, _upsert_channels_db_raw

__all__ = ["bootstrap"]


def bootstrap(audit_log: AuditLog, channels_db_path: str) -> dict[str, int]:
    """Verify keystore-channels.db consistency. Halt on unaudited channel.

    Returns: {"bootstrapped": <total keystore channels>, "rebuilt": <channels.db rows rebuilt>}

    Raises UnauditedChannelError if any channel_id in the _index has no channel.created
    audit entry — the node refuses to operate until manual reconciliation (D-05).
    """
    keystore_ids = get_index()
    rebuilt = 0

    conn = _connect_channels_db(channels_db_path)

    for channel_id in keystore_ids:
        # Condition 1: keystore record must exist for this id.
        record = _get_channel(channel_id)
        if record is None:
            # Index is stale (orphan). Remove from _index — safe to recover.
            remove_from_index(channel_id)
            continue

        # Condition 2: channel.created audit entry must exist (CHAN-05 proof).
        events = audit_log.query(
            channel_id=channel_id,
            event_type=AuditEventType.CHANNEL_CREATED,
        )
        if not events:
            raise UnauditedChannelError(
                f"channel {channel_id!r} exists in keystore but has no "
                f"'channel.created' audit entry; halt for manual reconciliation (D-05)",
                code="UNAUDITED_CHANNEL",
            )

        # Rebuild channels.db row from keystore record if missing.
        cur = conn.execute("SELECT id FROM channels WHERE id = ?", (channel_id,))
        if cur.fetchone() is None:
            channel = _dict_to_channel(record)
            _upsert_channels_db_raw(conn, channel)
            rebuilt += 1

    conn.close()
    return {"bootstrapped": len(keystore_ids), "rebuilt": rebuilt}
