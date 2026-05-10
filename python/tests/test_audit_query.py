"""Test AuditLog query() and _query_rows() (AUDIT-05, D-02, AUDIT-04, AUDIT-08).

Tests verify:
- Filtered query by channel_id (indexed column)
- Filtered query with since/until date range
- JSON1-based filter for shadow_id (payload array)
- JSON1-based filter for tier (payload array)
- D-02 round-trip: from_dict(asdict(entry)) == entry for all event types
- query() raises AuditChainBrokenError on tampered entry (AUDIT-08 verify-on-read)
- AUDIT-04 dispatch-style payload storage + retrieval
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from photophore.audit import AuditLog, AuditEntry, asdict, from_dict
from photophore.audit._chain import verify_entry_hash
from photophore.core import AuditEventType
from photophore.errors import AuditChainBrokenError


def test_query_by_channel_id_filters_correctly(audit_log: AuditLog) -> None:
    """AUDIT-05: query(channel_id=X) returns only entries for channel X."""
    audit_log.append(event_type=AuditEventType.CHANNEL_CREATED, channel_id="ch-A")
    audit_log.append(event_type=AuditEventType.CHANNEL_CREATED, channel_id="ch-B")
    audit_log.append(event_type=AuditEventType.CHANNEL_OPENED, channel_id="ch-A")

    results_a = audit_log.query(channel_id="ch-A")
    results_b = audit_log.query(channel_id="ch-B")

    assert len(results_a) == 2
    assert all(e.channel_id == "ch-A" for e in results_a)
    assert len(results_b) == 1
    assert results_b[0].channel_id == "ch-B"


def test_query_with_since_until_filter(audit_log: AuditLog) -> None:
    """AUDIT-05: combined channel_id + since + until filter."""
    # Append entries with specific timestamps
    e_old = audit_log.append(
        event_type=AuditEventType.CHANNEL_CREATED,
        channel_id="ch-A",
        timestamp="2026-01-01T00:00:00.000Z",
    )
    e_mid = audit_log.append(
        event_type=AuditEventType.CHANNEL_OPENED,
        channel_id="ch-A",
        timestamp="2026-06-01T00:00:00.000Z",
    )
    e_new = audit_log.append(
        event_type=AuditEventType.CHANNEL_SUSPENDED,
        channel_id="ch-A",
        timestamp="2026-12-01T00:00:00.000Z",
    )

    # Filter to mid year only
    results = audit_log.query(
        channel_id="ch-A",
        since="2026-05-01T00:00:00.000Z",
        until="2026-07-01T00:00:00.000Z",
    )
    assert len(results) == 1
    assert results[0].id == e_mid.id


def test_query_shadow_id_filter_uses_json1(audit_log: AuditLog) -> None:
    """AUDIT-05: shadow_id filter uses JSON1 array extraction."""
    audit_log.append(
        event_type=AuditEventType.DISPATCH_PRE,
        channel_id="ch-A",
        envelope_id="env-1",
        payload={"shadow_ids": ["sh-123", "sh-456"], "tiers": ["shared"]},
    )
    audit_log.append(
        event_type=AuditEventType.DISPATCH_PRE,
        channel_id="ch-B",
        envelope_id="env-2",
        payload={"shadow_ids": ["sh-789"], "tiers": ["local"]},
    )

    results_123 = audit_log.query(shadow_id="sh-123")
    results_789 = audit_log.query(shadow_id="sh-789")
    results_none = audit_log.query(shadow_id="sh-999")

    assert len(results_123) == 1
    assert results_123[0].envelope_id == "env-1"
    assert len(results_789) == 1
    assert len(results_none) == 0


def test_query_tier_filter_uses_json1(audit_log: AuditLog) -> None:
    """AUDIT-05: tier filter uses JSON1 array extraction."""
    audit_log.append(
        event_type=AuditEventType.DISPATCH_PRE,
        payload={"tiers": ["local", "shared"]},
    )
    audit_log.append(
        event_type=AuditEventType.DISPATCH_RECEIPT,
        payload={"tiers": ["public"]},
    )

    local_results = audit_log.query(tier="local")
    public_results = audit_log.query(tier="public")

    assert len(local_results) == 1
    assert len(public_results) == 1


def test_d02_round_trip_from_dict_asdict(audit_log: AuditLog) -> None:
    """D-02: from_dict(asdict(entry)) == entry for channel event."""
    entry = audit_log.append(
        event_type=AuditEventType.CHANNEL_CREATED,
        channel_id="ch-1",
        payload={"remote_node": "bob", "ceiling": "tier-1"},
    )
    assert from_dict(asdict(entry)) == entry


def test_d02_round_trip_with_none_fields(audit_log: AuditLog) -> None:
    """D-02: round-trip preserves None channel_id and envelope_id."""
    entry = audit_log.append(
        event_type=AuditEventType.DISPATCH_PRE,
        channel_id=None,
        envelope_id=None,
        payload={},
    )
    assert from_dict(asdict(entry)) == entry


def test_query_raises_audit_chain_broken_on_tampered_entry(
    tmp_path: Path,
    in_memory_keyring: object,
) -> None:
    """AUDIT-08: query() raises AuditChainBrokenError on a tampered row."""
    audit = AuditLog(tmp_path / "audit.db")
    e1 = audit.append(event_type=AuditEventType.CHANNEL_CREATED, channel_id="ch-1")
    e2 = audit.append(event_type=AuditEventType.CHANNEL_OPENED, channel_id="ch-1")

    # Tamper: drop trigger, mutate payload, restore
    db_path = str(tmp_path / "audit.db")
    raw = sqlite3.connect(db_path)
    raw.execute("PRAGMA writable_schema=ON")
    raw.execute("DROP TRIGGER IF EXISTS entries_no_update")
    raw.execute("PRAGMA writable_schema=OFF")
    raw.execute(f"UPDATE entries SET payload='{{\"tampered\": true}}' WHERE id='{e1.id}'")
    raw.commit()
    raw.close()

    # Re-open a fresh AuditLog (new connection)
    fresh_audit = AuditLog(db_path)
    with pytest.raises(AuditChainBrokenError):
        fresh_audit.query(channel_id="ch-1")


def test_audit04_dispatch_payload_round_trip(audit_log: AuditLog) -> None:
    """AUDIT-04: dispatch-style payload stored and retrieved with all 5 required fields."""
    payload = {
        "remote_node": "bob",
        "tier_per_block": ["local", "shared"],
        "shadow_ids": ["sh-1", "sh-2"],
        "classification_reasons": ["explicit_tag", "classifier:default"],
        "dispatch_signature_hash": "abc123",
        "receipt_signature_hash": None,
    }
    entry = audit_log.append(
        event_type=AuditEventType.DISPATCH_PRE,
        channel_id="ch-dispatch",
        envelope_id="env-dispatch",
        payload=payload,
    )
    results = audit_log.query(channel_id="ch-dispatch")
    assert len(results) == 1
    stored = results[0].payload
    assert stored["remote_node"] == "bob"
    assert stored["tier_per_block"] == ["local", "shared"]
    assert stored["shadow_ids"] == ["sh-1", "sh-2"]
    assert stored["classification_reasons"] == ["explicit_tag", "classifier:default"]
    assert stored["dispatch_signature_hash"] == "abc123"
    assert stored["receipt_signature_hash"] is None
