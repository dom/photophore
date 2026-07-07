"""AT-A6: Audit log manipulation — chained hashes invalidate on tamper."""
# AT-SURFACE: AT-A6
from __future__ import annotations

import sqlite3

import pytest

from photophore.audit import AuditLog
from photophore.core import AuditEventType


@pytest.mark.at_surface("AT-A6")
def test_audit_log_tamper_invalidates_chain(tmp_path) -> None:
    """Tamper a payload byte; verify_chain returns (False, broken_at).

    Append 5 entries, then drop the append-only update trigger and modify
    entry 3's payload. verify_chain MUST detect and return (False, <id>).
    """
    db_path = tmp_path / "audit.db"
    log = AuditLog(db_path)
    # Use explicit increasing timestamps to ensure the verify_chain walk
    # order matches the write order (audit chain uses
    # `ORDER BY timestamp ASC, id ASC`).
    ids = []
    for i in range(5):
        ts = f"2026-05-11T00:00:0{i}.000Z"
        entry = log.append(
            event_type=AuditEventType.CHANNEL_CREATED,
            channel_id=f"ch{i}",
            payload={"seq": i, "data": f"entry-{i}-payload"},
            timestamp=ts,
        )
        ids.append(entry.id)

    # Sanity: clean chain verifies.
    ok, _ = log.verify_chain()
    assert ok, "AT-A6: pre-tamper chain must verify"

    # Tamper the payload of entry 3 via direct sqlite.
    raw = sqlite3.connect(str(db_path))
    raw.execute("PRAGMA writable_schema=ON")
    raw.execute("DROP TRIGGER IF EXISTS entries_no_update")
    raw.execute(
        "UPDATE entries SET payload = ? WHERE id = ?",
        ('{"tampered": true}', ids[2]),
    )
    raw.commit()
    raw.close()

    fresh = AuditLog(db_path)
    ok, broken_at = fresh.verify_chain()
    assert ok is False, "AT-A6: tampered chain MUST fail verification"
    assert broken_at is not None, "AT-A6: verify_chain MUST identify broken entry"


@pytest.mark.at_surface("AT-A6")
def test_tail_truncation_detected_with_head_anchor(tmp_path, in_memory_keyring) -> None:
    """Deleting the NEWEST entry is detected when a head anchor is configured.

    The hash chain alone cannot see tail truncation (the remaining prefix is
    a valid chain). The head anchor persists the expected head hash + entry
    count out-of-band (platform keystore); verify_chain compares against it.
    """
    from photophore.audit import KeystoreHeadAnchor

    db_path = tmp_path / "audit.db"
    log = AuditLog(db_path, head_anchor=KeystoreHeadAnchor(db_path))
    for i in range(5):
        log.append(
            event_type=AuditEventType.CHANNEL_CREATED,
            channel_id=f"ch{i}",
            payload={"seq": i},
            timestamp=f"2026-05-11T00:00:0{i}.000Z",
        )
    ok, _ = log.verify_chain()
    assert ok, "AT-A6: pre-truncation chain must verify"

    # Truncate the tail: drop the append-only delete trigger, remove the
    # newest row (highest rowid).
    raw = sqlite3.connect(str(db_path))
    raw.execute("DROP TRIGGER IF EXISTS entries_no_delete")
    raw.execute(
        "DELETE FROM entries WHERE rowid = (SELECT MAX(rowid) FROM entries)"
    )
    raw.commit()
    raw.close()

    fresh = AuditLog(db_path, head_anchor=KeystoreHeadAnchor(db_path))
    ok, broken_at = fresh.verify_chain()
    assert ok is False, "AT-A6: tail truncation MUST fail verification"
    assert broken_at is not None


@pytest.mark.at_surface("AT-A6")
def test_full_truncation_detected_with_head_anchor(tmp_path, in_memory_keyring) -> None:
    """Deleting EVERY entry (empty-but-anchored log) is detected."""
    from photophore.audit import KeystoreHeadAnchor

    db_path = tmp_path / "audit.db"
    log = AuditLog(db_path, head_anchor=KeystoreHeadAnchor(db_path))
    log.append(
        event_type=AuditEventType.CHANNEL_CREATED,
        channel_id="ch0",
        payload={"seq": 0},
    )
    raw = sqlite3.connect(str(db_path))
    raw.execute("DROP TRIGGER IF EXISTS entries_no_delete")
    raw.execute("DELETE FROM entries")
    raw.commit()
    raw.close()

    fresh = AuditLog(db_path, head_anchor=KeystoreHeadAnchor(db_path))
    ok, _ = fresh.verify_chain()
    assert ok is False, "AT-A6: full truncation MUST fail verification"


@pytest.mark.at_surface("AT-A6")
def test_tail_truncation_residual_without_head_anchor(tmp_path) -> None:
    """Ring-1 residual, DOCUMENTED: without a head anchor, tail truncation
    is NOT detectable from the chain alone. This test pins the residual so a
    silent behavior change (either direction) is caught.
    """
    db_path = tmp_path / "audit.db"
    log = AuditLog(db_path)
    for i in range(3):
        log.append(
            event_type=AuditEventType.CHANNEL_CREATED,
            channel_id=f"ch{i}",
            payload={"seq": i},
            timestamp=f"2026-05-11T00:00:0{i}.000Z",
        )
    raw = sqlite3.connect(str(db_path))
    raw.execute("DROP TRIGGER IF EXISTS entries_no_delete")
    raw.execute(
        "DELETE FROM entries WHERE rowid = (SELECT MAX(rowid) FROM entries)"
    )
    raw.commit()
    raw.close()

    fresh = AuditLog(db_path)
    ok, _ = fresh.verify_chain()
    assert ok is True, (
        "Ring-1 residual: anchor-less tail truncation is undetectable by design; "
        "if this now fails, update the AT-A6 residual documentation"
    )
