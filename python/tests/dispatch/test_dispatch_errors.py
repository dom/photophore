"""Task 1 tests: DispatchError + DispatchSubcode + asyncio.to_thread shim (D-03, D-11)."""
from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import pytest

from photophore.errors import DispatchError, DispatchSubcode, PhotophoreError


_EXPECTED_SUBCODES: frozenset[str] = frozenset({
    "CHANNEL_RESOLVE_FAILED",
    "CLASSIFICATION_FAILED",
    "SHADOW_GENERATION_FAILED",
    "POLICY_AUTHORING_FAILED",
    "AUDIT_FAILED_PRE",
    "SIGNING_FAILED",
    "TRANSPORT_TIMEOUT",
    "TRANSPORT_REFUSED",
    "RECEIPT_MALFORMED",
    "RECEIPT_INVALID",
    "POLICY_VIOLATED",
    "AUDIT_FAILED_POST",
})

_EXPECTED_RETRYABLE: frozenset[str] = frozenset({
    "AUDIT_FAILED_PRE",
    "SIGNING_FAILED",
    "TRANSPORT_TIMEOUT",
    "TRANSPORT_REFUSED",
    "AUDIT_FAILED_POST",
})


def test_subcodes_present() -> None:
    """All 12 D-03 subcodes exist as StrEnum members with name == value."""
    assert issubclass(DispatchSubcode, StrEnum)
    members = {m.name: m.value for m in DispatchSubcode}
    assert set(members) == _EXPECTED_SUBCODES, (
        f"missing or extra subcodes; got {set(members)}"
    )
    for name, value in members.items():
        assert name == value, f"{name!r} != {value!r} (StrEnum name/value must match)"
    assert len(list(DispatchSubcode)) == 12


def test_dispatcherror_extends_photophoreerror() -> None:
    err = DispatchError(
        "boom",
        subcode=DispatchSubcode.RECEIPT_INVALID,
        stage=8,
    )
    assert isinstance(err, PhotophoreError)
    assert err.code == "RECEIPT_INVALID"
    assert err.subcode is DispatchSubcode.RECEIPT_INVALID
    assert err.stage == 8
    assert err.retryable is False


def test_retryable_subset() -> None:
    """5 retryable, 7 non-retryable; matches D-03 table exactly."""
    for sub in DispatchSubcode:
        err = DispatchError("x", subcode=sub, stage=1)
        expected = sub.name in _EXPECTED_RETRYABLE
        assert err.retryable is expected, (
            f"{sub.name}: expected retryable={expected}, got {err.retryable}"
        )


def test_optional_fields() -> None:
    err = DispatchError(
        "x",
        subcode=DispatchSubcode.AUDIT_FAILED_PRE,
        stage=5,
        envelope_id="env-1",
        channel_id="chan-1",
        audit_entry_hash="hash-1",
    )
    assert err.envelope_id == "env-1"
    assert err.channel_id == "chan-1"
    assert err.audit_entry_hash == "hash-1"
    # Defaults
    err2 = DispatchError("x", subcode=DispatchSubcode.SIGNING_FAILED, stage=6)
    assert err2.envelope_id is None
    assert err2.channel_id is None
    assert err2.audit_entry_hash is None


@pytest.mark.asyncio
async def test_aio_shim_audit_append(tmp_audit_log) -> None:
    """audit_append_async returns the same entry_hash the sync log.append returns.

    Uses a tmp_path-backed real AuditLog (per-method connection model so that
    asyncio.to_thread can call into SQLite from a non-owner thread). Asserts
    the round-trip works inside an asyncio event loop via asyncio.to_thread.
    """
    from photophore.dispatch._aio import audit_append_async

    returned = await audit_append_async(
        tmp_audit_log,
        event_type="dispatch.pre",
        channel_id="chan-1",
        envelope_id="env-1",
        payload={"k": "v"},
    )
    assert isinstance(returned, str)
    assert len(returned) >= 16  # blake3-v1 hex digest
    # Re-query the log to confirm the entry is durable.
    rows = tmp_audit_log.query(channel_id="chan-1")
    assert len(rows) == 1
    assert rows[0].entry_hash == returned


def test_aio_shim_no_async_def_in_phase2() -> None:
    """D-11 invariant: zero `async def` anywhere in the sync-core modules.

    Concatenates each sync-core module's __init__.py and asserts the literal substring
    'async def' is absent. If a future change adds async to sync-core modules, this
    test surfaces it as a deliberate event (D-11 boundary breach).
    """
    src_root = Path(__file__).resolve().parents[2] / "src" / "photophore"
    targets = [
        src_root / "audit" / "__init__.py",
        src_root / "channels" / "__init__.py",
        src_root / "classifier" / "__init__.py",
        src_root / "shadow" / "__init__.py",
        src_root / "policy" / "__init__.py",
    ]
    blob = "\n".join(p.read_text() for p in targets)
    assert "async def" not in blob, "sync-core module __init__ contains async def (D-11 violation)"
