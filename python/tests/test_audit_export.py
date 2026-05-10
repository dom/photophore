"""Test AuditLog.export() JSON Lines shape (AUDIT-06).

Tests verify:
- export() yields one dict per entry
- each dict is a valid single JSON object (parseable)
- algo_version field present on every line
- export() works on an empty log (zero lines)
"""
from __future__ import annotations

import json

from photophore.audit import AuditLog
from photophore.core import AuditEventType


def test_export_yields_one_dict_per_entry(audit_log: AuditLog) -> None:
    """AUDIT-06: export() yields exactly one dict per appended entry."""
    audit_log.append(event_type=AuditEventType.CHANNEL_CREATED, channel_id="ch-1")
    audit_log.append(event_type=AuditEventType.CHANNEL_OPENED, channel_id="ch-1")
    rows = list(audit_log.export())
    assert len(rows) == 2


def test_export_each_row_is_json_serializable(audit_log: AuditLog) -> None:
    """AUDIT-06: each exported dict is a valid JSON object."""
    audit_log.append(
        event_type=AuditEventType.CHANNEL_CREATED,
        channel_id="ch-1",
        payload={"remote_node": "bob"},
    )
    rows = list(audit_log.export())
    assert len(rows) == 1
    # Must round-trip through json without error
    line = json.dumps(rows[0])
    parsed = json.loads(line)
    assert parsed["event_type"] == "channel.created"


def test_export_includes_algo_version_on_every_line(audit_log: AuditLog) -> None:
    """AUDIT-06: algo_version field present on every exported line."""
    audit_log.append(event_type=AuditEventType.CHANNEL_CREATED, channel_id="ch-1")
    audit_log.append(event_type=AuditEventType.CHANNEL_OPENED, channel_id="ch-1")
    for row in audit_log.export():
        assert "algo_version" in row, "algo_version missing from export row"
        assert row["algo_version"] == "blake3-v1"


def test_export_on_empty_log_yields_zero_rows(audit_log: AuditLog) -> None:
    """export() on an empty log is a valid empty iterator."""
    rows = list(audit_log.export())
    assert rows == []


def test_export_row_shape_has_all_required_fields(audit_log: AuditLog) -> None:
    """Each export row has all 9 entry fields."""
    audit_log.append(
        event_type=AuditEventType.DISPATCH_PRE,
        channel_id="ch-1",
        envelope_id="env-1",
        payload={"tier_per_block": ["local"]},
    )
    rows = list(audit_log.export())
    assert len(rows) == 1
    row = rows[0]
    for field in ["id", "algo_version", "prev_hash", "entry_hash",
                  "event_type", "channel_id", "envelope_id", "timestamp", "payload"]:
        assert field in row, f"Field {field!r} missing from export row"
