"""Test AnchorTarget Protocol and NullAnchor (AUDIT-07).

Tests verify:
- AnchorTarget is runtime_checkable
- NullAnchor() is an instance of AnchorTarget (Protocol satisfaction)
- NullAnchor.anchor(entry) returns None
- Passing NullAnchor() to AuditLog(anchor=...) and appending an entry succeeds
"""
from __future__ import annotations

from pathlib import Path

from photophore.audit import AuditLog, AnchorTarget, NullAnchor, AnchorReceipt, AuditEntry
from photophore.core import AuditEventType


def test_anchor_target_is_runtime_checkable() -> None:
    """AnchorTarget must be runtime_checkable (allows isinstance checks)."""
    null = NullAnchor()
    assert isinstance(null, AnchorTarget)


def test_null_anchor_anchor_returns_none(audit_log: AuditLog) -> None:
    """NullAnchor.anchor(entry) returns None (no-op)."""
    entry = audit_log.append(
        event_type=AuditEventType.CHANNEL_CREATED, channel_id="ch-1"
    )
    null = NullAnchor()
    result = null.anchor(entry)
    assert result is None


def test_audit_log_with_null_anchor_appends_successfully(tmp_path: Path) -> None:
    """AUDIT-07 smoke test: AuditLog(anchor=NullAnchor()) + append succeeds."""
    anchor = NullAnchor()
    log = AuditLog(tmp_path / "audit.db", anchor=anchor)
    entry = log.append(event_type=AuditEventType.CHANNEL_CREATED, channel_id="ch-1")
    assert entry.id is not None
    assert entry.algo_version == "blake3-v1"


def test_custom_anchor_receives_entry() -> None:
    """An AnchorTarget implementation receives the AuditEntry on each append."""
    received: list[AuditEntry] = []

    class _CapturingAnchor:
        def anchor(self, entry: AuditEntry) -> AnchorReceipt | None:
            received.append(entry)
            return None

    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        log = AuditLog(
            Path(d) / "audit.db",
            anchor=_CapturingAnchor(),  # type: ignore[arg-type]
        )
        e = log.append(event_type=AuditEventType.CHANNEL_CREATED, channel_id="ch-1")
        assert len(received) == 1
        assert received[0].id == e.id


def test_anchor_receipt_dataclass_exists() -> None:
    """AnchorReceipt is a frozen dataclass with target and timestamp fields."""
    r = AnchorReceipt(target="noop://", timestamp="2026-05-09T00:00:00.000Z")
    assert r.target == "noop://"
    assert r.timestamp == "2026-05-09T00:00:00.000Z"
