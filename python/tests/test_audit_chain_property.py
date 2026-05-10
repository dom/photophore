"""Hypothesis property test: any single-byte tamper invalidates verify_chain() (AUDIT-08).

This test satisfies:
- AUDIT-08: chain integrity verifiable on read; tampered entry -> verify returns False
- CONF-03: Hypothesis property test with >=100 examples

Two tamper paths (both required by the plan):
1. Payload tamper: modify the payload column of any entry
2. prev_hash tamper: corrupt prev_hash column of any non-head entry

Uses PRAGMA writable_schema=ON + DROP TRIGGER approach to bypass append-only triggers
for the tamper step. This matches the technique documented in the AT-A4 fixture.

Note: tmp_path is a function-scoped fixture reused across Hypothesis examples.
Each example creates its own uniquely-named SQLite file inside tmp_path, so there is
no cross-example state contamination. The HealthCheck.function_scoped_fixture warning
is suppressed intentionally.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from photophore.audit import AuditLog
from photophore.core import AuditEventType


def _seed_entries(log: AuditLog, n: int) -> list[str]:
    """Append n channel.created entries and return their IDs in insertion order."""
    ids: list[str] = []
    for i in range(n):
        entry = log.append(
            event_type=AuditEventType.CHANNEL_CREATED,
            channel_id=f"ch-{i}",
            payload={"seq": i, "data": f"entry-{i}-data-payload-text"},
        )
        ids.append(entry.id)
    return ids


def _drop_update_trigger(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA writable_schema=ON")
    conn.execute("DROP TRIGGER IF EXISTS entries_no_update")
    conn.execute("PRAGMA writable_schema=OFF")


@given(
    # Use flatmap to generate (n_entries, tamper_index) as a correlated pair.
    # Range 2..15 gives sum(1..14)=105 unique pairs, exceeding the 100-example target.
    args=st.integers(min_value=2, max_value=15).flatmap(
        lambda n: st.integers(min_value=0, max_value=n - 1).map(lambda i: (n, i))
    ),
)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_payload_tamper_invalidates_chain(
    tmp_path: Path,
    args: tuple[int, int],
) -> None:
    """AUDIT-08 payload path: tamper payload of any entry -> verify_chain() returns False.

    Each example creates a unique DB file inside tmp_path so there is no cross-example
    contamination despite tmp_path being function-scoped.
    """
    n_entries, tamper_index = args

    db_path = str(tmp_path / f"audit_p_{n_entries}_{tamper_index}.db")
    log = AuditLog(db_path)
    ids = _seed_entries(log, n_entries)

    tamper_id = ids[tamper_index]
    raw = sqlite3.connect(db_path)
    _drop_update_trigger(raw)
    raw.execute(
        "UPDATE entries SET payload = ? WHERE id = ?",
        ('{"tampered": true, "original": false}', tamper_id),
    )
    raw.commit()
    raw.close()

    fresh_log = AuditLog(db_path)
    ok, broken_at = fresh_log.verify_chain()
    assert ok is False, (
        f"Expected chain failure after payload tamper at index {tamper_index} "
        f"out of {n_entries} entries (id={tamper_id[:8]})"
    )
    assert broken_at is not None


@given(
    # tamper_index >= 1 (chain head has no prev_hash to corrupt).
    # Range 3..16 gives 2+3+...+13=104 unique pairs, exceeding the 100-example target.
    args=st.integers(min_value=3, max_value=16).flatmap(
        lambda n: st.integers(min_value=1, max_value=n - 1).map(lambda i: (n, i))
    ),
)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_prev_hash_tamper_invalidates_chain(
    tmp_path: Path,
    args: tuple[int, int],
) -> None:
    """AUDIT-08 prev_hash path: corrupt prev_hash of any non-head entry -> False."""
    n_entries, tamper_index = args

    db_path = str(tmp_path / f"audit_ph_{n_entries}_{tamper_index}.db")
    log = AuditLog(db_path)
    ids = _seed_entries(log, n_entries)

    tamper_id = ids[tamper_index]
    raw = sqlite3.connect(db_path)
    _drop_update_trigger(raw)
    raw.execute(
        "UPDATE entries SET prev_hash = ? WHERE id = ?",
        ("deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000", tamper_id),
    )
    raw.commit()
    raw.close()

    fresh_log = AuditLog(db_path)
    ok, broken_at = fresh_log.verify_chain()
    assert ok is False, (
        f"Expected chain failure after prev_hash tamper at index {tamper_index} "
        f"out of {n_entries} entries"
    )
    assert broken_at is not None
