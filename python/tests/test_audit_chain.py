"""Test BLAKE3 chain hash implementation (AUDIT-02, AUDIT-03, D-03).

Tests verify:
- Chain head prev_hash == "" (AUDIT-03)
- Entry N+1 prev_hash == entry N entry_hash (AUDIT-03)
- Every entry has algo_version == "blake3-v1" (AUDIT-02)
- compute_hash_by_version raises UnsupportedChainAlgoError for unknown versions
- verify_entry_hash returns True for clean entry, False after byte-flip
- Hash domain is blake3(canonicalize(entry minus entry_hash)) (D-03)
"""
from __future__ import annotations

import blake3
import pytest
from thermocline import canonicalize

from photophore.audit import AuditLog
from photophore.audit._chain import (
    _HASH_ALGO_REGISTRY,
    compute_entry_hash,
    compute_hash_by_version,
    verify_entry_hash,
)
from photophore.errors import UnsupportedChainAlgoError


def test_chain_head_prev_hash_is_empty(audit_log: AuditLog) -> None:
    """AUDIT-03: first entry has prev_hash == '' (chain head sentinel)."""
    entry = audit_log.append(event_type="channel.created", channel_id="ch-1")
    assert entry.prev_hash == ""


def test_second_entry_prev_hash_equals_first_entry_hash(audit_log: AuditLog) -> None:
    """AUDIT-03: entry 2 prev_hash == entry 1 entry_hash."""
    e1 = audit_log.append(event_type="channel.created", channel_id="ch-1")
    e2 = audit_log.append(event_type="channel.opened", channel_id="ch-1")
    assert e2.prev_hash == e1.entry_hash


def test_third_entry_prev_hash_equals_second_entry_hash(audit_log: AuditLog) -> None:
    """AUDIT-03: chain links are maintained across 3+ entries."""
    e1 = audit_log.append(event_type="channel.created", channel_id="ch-1")
    e2 = audit_log.append(event_type="channel.opened", channel_id="ch-1")
    e3 = audit_log.append(event_type="channel.suspended", channel_id="ch-1")
    assert e2.prev_hash == e1.entry_hash
    assert e3.prev_hash == e2.entry_hash


def test_every_entry_has_blake3_v1_algo_version(audit_log: AuditLog) -> None:
    """AUDIT-02: every entry carries algo_version == 'blake3-v1'."""
    e1 = audit_log.append(event_type="channel.created", channel_id="ch-1")
    e2 = audit_log.append(event_type="channel.opened", channel_id="ch-1")
    assert e1.algo_version == "blake3-v1"
    assert e2.algo_version == "blake3-v1"


def test_compute_hash_by_version_unknown_raises(  ) -> None:
    """AUDIT-02: unknown algo_version raises UnsupportedChainAlgoError."""
    with pytest.raises(UnsupportedChainAlgoError):
        compute_hash_by_version("blake3-v999", b"data")


def test_algo_registry_has_blake3_v1() -> None:
    """_HASH_ALGO_REGISTRY must contain 'blake3-v1' key."""
    assert "blake3-v1" in _HASH_ALGO_REGISTRY


def test_verify_entry_hash_returns_true_for_clean_entry(audit_log: AuditLog) -> None:
    """verify_entry_hash returns True for an unmodified entry dict."""
    entry = audit_log.append(event_type="channel.created", channel_id="ch-1")
    entry_dict = {
        "id": entry.id,
        "algo_version": entry.algo_version,
        "prev_hash": entry.prev_hash,
        "entry_hash": entry.entry_hash,
        "event_type": entry.event_type,
        "channel_id": entry.channel_id,
        "envelope_id": entry.envelope_id,
        "timestamp": entry.timestamp,
        "payload": entry.payload,
    }
    assert verify_entry_hash(entry_dict) is True


def test_verify_entry_hash_returns_false_after_payload_mutation(audit_log: AuditLog) -> None:
    """verify_entry_hash returns False after any field mutation."""
    entry = audit_log.append(
        event_type="channel.created", channel_id="ch-1",
        payload={"key": "value"},
    )
    entry_dict = {
        "id": entry.id,
        "algo_version": entry.algo_version,
        "prev_hash": entry.prev_hash,
        "entry_hash": entry.entry_hash,
        "event_type": entry.event_type,
        "channel_id": entry.channel_id,
        "envelope_id": entry.envelope_id,
        "timestamp": entry.timestamp,
        "payload": {"key": "TAMPERED"},  # mutated
    }
    assert verify_entry_hash(entry_dict) is False


def test_hash_domain_matches_manual_computation(audit_log: AuditLog) -> None:
    """D-03: entry_hash == blake3(canonicalize(entry minus entry_hash field))."""
    entry = audit_log.append(
        event_type="channel.created", channel_id="ch-test",
        payload={"remote_node": "bob"},
    )
    entry_dict_minus_hash = {
        "id": entry.id,
        "algo_version": entry.algo_version,
        "prev_hash": entry.prev_hash,
        "event_type": entry.event_type,
        "channel_id": entry.channel_id,
        "envelope_id": entry.envelope_id,
        "timestamp": entry.timestamp,
        "payload": entry.payload,
    }
    expected_hash = blake3.blake3(canonicalize(entry_dict_minus_hash)).hexdigest()
    assert entry.entry_hash == expected_hash


def test_compute_entry_hash_refuses_input_with_entry_hash() -> None:
    """compute_entry_hash raises ValueError if entry_hash key is present in input."""
    with pytest.raises(ValueError, match="refuses input"):
        compute_entry_hash({"entry_hash": "should-not-be-here", "id": "x"})


# ---------------------------------------------------------------------------
# MED 7: append() read-then-write must be serialized (threading.Lock).
# sqlite releases the GIL during C-level calls, so two threads can both read
# the same head hash and INSERT siblings, forking the chain.


def test_concurrent_appends_do_not_fork_chain(tmp_path) -> None:
    """Hammer append() from many threads; the chain must stay linear.

    Without serialization two appends can read the same prev_hash and both
    commit, producing two entries with an identical prev_hash (a fork).
    verify_chain() then fails on the second sibling. With the append lock the
    chain stays a single linked list regardless of interleaving.
    """
    import threading

    log = AuditLog(tmp_path / "audit.db")
    n_threads = 8
    appends_per_thread = 25
    barrier = threading.Barrier(n_threads)
    errors: list[BaseException] = []

    def hammer() -> None:
        try:
            barrier.wait()
            for _ in range(appends_per_thread):
                log.append(event_type="channel.created", channel_id="ch-conc")
        except BaseException as exc:  # noqa: BLE001 collect for the assert
            errors.append(exc)

    threads = [threading.Thread(target=hammer) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"append() raised under concurrency: {errors[:3]}"

    entries = log.query(channel_id="ch-conc")
    assert len(entries) == n_threads * appends_per_thread

    # No two entries may share a prev_hash (that is a fork).
    prev_hashes = [e.prev_hash for e in entries]
    assert len(prev_hashes) == len(set(prev_hashes)), (
        "audit chain forked: multiple entries share a prev_hash"
    )

    # Prove the entries form ONE linked list without relying on walk order:
    # exactly one chain head, and every other entry's prev_hash points at an
    # existing entry_hash (with prev_hash uniqueness above, that is a single
    # unbranched chain). verify_chain()'s ordered walk is covered separately
    # (it must walk by rowid, the true append order; see MED 8 tests).
    heads = [e for e in entries if e.prev_hash == ""]
    assert len(heads) == 1, "audit chain must have exactly one head"
    entry_hashes = {e.entry_hash for e in entries}
    non_head_prev = {e.prev_hash for e in entries if e.prev_hash != ""}
    assert non_head_prev <= entry_hashes, (
        "an entry's prev_hash points at a nonexistent entry (dangling link)"
    )


# ---------------------------------------------------------------------------
# MED 8: the chain must be verified and walked in TRUE append order (rowid),
# not by timestamp. Timestamps have millisecond resolution and are
# caller-suppliable, so equal (or lying) timestamps must not scramble the walk.


def test_verify_chain_walks_append_order_despite_equal_timestamps(tmp_path) -> None:
    """Entries sharing one timestamp still verify: rowid is the walk order.

    With ORDER BY timestamp, ties fell back to random UUID ids, so a burst of
    same-millisecond appends produced a scrambled walk whose prev_hash checks
    failed on an INTACT chain (and, worse, a verifier that does not walk true
    append order can be gamed by attacker-chosen timestamps)."""
    log = AuditLog(tmp_path / "audit.db")
    same_ts = "2026-07-07T00:00:00.000Z"
    appended = [
        log.append(
            event_type="channel.created",
            channel_id=f"ch-{i}",
            timestamp=same_ts,
        )
        for i in range(20)
    ]

    ok, head = log.verify_chain()
    assert ok, f"intact chain failed verification under equal timestamps: {head}"
    assert head == appended[-1].entry_hash

    # export()/query() walk the same true append order.
    exported = list(log.export())
    assert [r["id"] for r in exported] == [e.id for e in appended], (
        "export order must be true append order (rowid), not timestamp/id order"
    )


def test_verify_chain_not_fooled_by_backdated_timestamp(tmp_path) -> None:
    """A caller-supplied EARLIER timestamp must not reorder the walk."""
    log = AuditLog(tmp_path / "audit.db")
    log.append(event_type="channel.created", channel_id="ch-a",
               timestamp="2026-07-07T00:00:05.000Z")
    log.append(event_type="channel.created", channel_id="ch-b",
               timestamp="2026-07-07T00:00:01.000Z")  # backdated
    ok, _ = log.verify_chain()
    assert ok, "backdated timestamp reordered the chain walk"
