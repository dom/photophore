"""Typed AuditEntry dataclass + serialization helpers.

D-02: Public query() returns list[AuditEntry]; _query_rows() returns raw dicts
(streaming-friendly, used by CLI export). The D-02 round-trip invariant is:
    from_dict(asdict(entry)) == entry

AUDIT-04 payload shape for dispatch events:
    {
        "remote_node": str,
        "tier_per_block": list[str],
        "shadow_ids": list[str],
        "classification_reasons": list[str],
        "dispatch_signature_hash": str | None,
        "receipt_signature_hash": str | None,
    }

The audit log stores this payload shape; the dispatch coordinator populates
it during a real dispatch. Storage-layer tests verify storage + retrieval at
the AuditLog API layer (AUDIT-04 storage scope).
"""
from __future__ import annotations

from dataclasses import asdict as _dc_asdict
from dataclasses import dataclass
from typing import Any, Mapping

from thermocline import canonicalize

__all__ = [
    "AuditEntry",
    "asdict",
    "from_dict",
]


@dataclass(frozen=True)
class AuditEntry:
    """Single immutable audit log entry.

    Fields mirror the 'entries' SQLite table columns (D-01). The payload dict
    holds event-specific fields (D-02 typed query path) parsed from the canonical-JSON
    TEXT column on read.
    """

    id: str
    algo_version: str
    prev_hash: str
    entry_hash: str
    event_type: str
    channel_id: str | None
    envelope_id: str | None
    timestamp: str  # ISO 8601 UTC with "Z" suffix
    payload: dict[str, Any]  # event-specific fields; empty dict for events with no payload

    def to_row(self) -> tuple[Any, ...]:
        """Return a parameter tuple for the INSERT ... VALUES (?,?,?,?,?,?,?,?,?) statement.

        The payload is serialized as canonical-JSON (RFC 8785 / JCS) matching the
        D-03 hash domain. This is the only place payload bytes hit the wire — callers
        never call json.dumps directly (Pitfall 11).
        """
        payload_canonical = canonicalize(self.payload).decode("utf-8")
        return (
            self.id,
            self.algo_version,
            self.prev_hash,
            self.entry_hash,
            self.event_type,
            self.channel_id,
            self.envelope_id,
            self.timestamp,
            payload_canonical,
        )


def asdict(entry: AuditEntry) -> dict[str, Any]:
    """Serialize AuditEntry to a dict suitable for JSON Lines export (AUDIT-06)."""
    return _dc_asdict(entry)


def from_dict(d: Mapping[str, Any]) -> AuditEntry:
    """Deserialize an AuditEntry from a raw dict (D-02 round-trip invariant)."""
    return AuditEntry(
        id=str(d["id"]),
        algo_version=str(d["algo_version"]),
        prev_hash=str(d["prev_hash"]),
        entry_hash=str(d["entry_hash"]),
        event_type=str(d["event_type"]),
        channel_id=str(d["channel_id"]) if d.get("channel_id") is not None else None,
        envelope_id=str(d["envelope_id"]) if d.get("envelope_id") is not None else None,
        timestamp=str(d["timestamp"]),
        payload=dict(d.get("payload") or {}),
    )
