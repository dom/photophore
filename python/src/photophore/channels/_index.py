"""_index sentinel — keystore-based channel ID enumeration (D-06).

python-keyring has no enumerate-by-service API. keyring.get_credential(service, None)
does NOT return all usernames for a service. This sentinel is the ONLY way D-05's
"keystore-as-truth" bootstrap can detect channels that exist in the keystore but
are missing from channels.db.

Sentinel location:
- service: "photophore.channel" (same as _keystore._KEYSTORE_SERVICE)
- username: "_index" (constant _INDEX_SENTINEL_KEY)
- value: JSON array of channel_id strings (UUIDv4)

The sentinel is updated atomically with channel creation/deletion as part of the
D-07 three-step write order (inside step 1, before the audit append).
"""
from __future__ import annotations

import json
from typing import Sequence

import keyring

from ._keystore import _KEYSTORE_SERVICE

__all__ = [
    "_INDEX_SENTINEL_KEY",
    "get_index",
    "set_index",
    "add_to_index",
    "remove_from_index",
]

_INDEX_SENTINEL_KEY: str = "_index"


def get_index() -> list[str]:
    """Return the current list of channel_ids from the keystore sentinel."""
    raw = keyring.get_password(_KEYSTORE_SERVICE, _INDEX_SENTINEL_KEY)
    if not raw:
        return []
    return list(str(cid) for cid in json.loads(raw))


def set_index(channel_ids: Sequence[str]) -> None:
    """Overwrite the keystore sentinel with the given list of channel_ids."""
    keyring.set_password(
        _KEYSTORE_SERVICE, _INDEX_SENTINEL_KEY, json.dumps(list(channel_ids))
    )


def add_to_index(channel_id: str) -> None:
    """Append a channel_id to the sentinel (idempotent — won't duplicate)."""
    ids = get_index()
    if channel_id not in ids:
        ids.append(channel_id)
        set_index(ids)


def remove_from_index(channel_id: str) -> None:
    """Remove a channel_id from the sentinel (idempotent — no-op if not found)."""
    ids = [cid for cid in get_index() if cid != channel_id]
    set_index(ids)
