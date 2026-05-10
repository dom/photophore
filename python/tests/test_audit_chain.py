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

from photophore.audit import AuditLog, AuditEntry
from photophore.audit._chain import (
    _HASH_ALGO_REGISTRY,
    ALGO_VERSION_DEFAULT,
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
