"""Task 2 coordinator tests: 9-step dispatch flow with DispatchError raise-site coverage.

Each test pins a single failure mode (subcode + stage + retryable + audit-write
invariant). Together they cover the 11 numbered raise-sites in
photophore/dispatch/_coordinator.py.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from photophore.audit import AuditLog
from photophore.channels import ChannelStore
from photophore.channels._store import _channel_to_dict, _upsert_channels_db_raw
from photophore.channels._keystore import _set_channel
from photophore.channels._index import add_to_index
from photophore.channels._types import Channel
from photophore.core import ChannelId, ChannelState
from photophore.dispatch import (
    DispatchError,
    DispatchOutcome,
    DispatchSubcode,
    dispatch_async,
)


# --- helpers ---------------------------------------------------------------


def _seed_channel(
    store: ChannelStore,
    *,
    channel_id: str,
    key_scheme: str = "brine",
    state: ChannelState = ChannelState.OPEN,
    ceiling: str = "tier-1",
) -> Channel:
    chan = Channel(
        id=ChannelId(channel_id),
        local_node="alice-node",
        remote_node="pi-forge",
        ceiling=ceiling,
        key_scheme=key_scheme,
        state=state,
        created_at="2026-05-11T00:00:00.000Z",
        creator_identity="test",
        description="seed",
        remote_pubkey_hex=None,
    )
    _set_channel(ChannelId(channel_id), _channel_to_dict(chan))
    add_to_index(ChannelId(channel_id))
    _upsert_channels_db_raw(store._conn, chan)  # type: ignore[attr-defined]
    return chan


def _draft(channel_id: str = "chan-1", envelope_id: str = "env-1",
           key_scheme: str = "brine") -> dict[str, Any]:
    """Minimal valid task draft."""
    return {
        "thermocline": "0.3.1",
        "type": "task",
        "envelope_id": envelope_id,
        "issued_at": "2026-05-11T00:00:00Z",
        "issuer": "alice-node",
        "recipient": "pi-forge",
        "channel_id": channel_id,
        "key_scheme": key_scheme,
        "task": {"type": "data.compute", "instruction": "noop"},
        "context": [],
        "output_contract": {"format": "text/plain"},
        "dispatch_signature": {"key_scheme": key_scheme},
    }


def _good_result(envelope_id: str = "env-1") -> dict[str, Any]:
    """Forge response shape mirroring a real task_result envelope."""
    return {
        "thermocline": "0.3.1",
        "type": "task_result",
        "envelope_id": envelope_id,
        "issued_at": "2026-05-11T00:00:01Z",
        "issuer": "pi-forge",
        "recipient": "alice-node",
        "channel_id": "chan-1",
        "outputs": {"answer": "ok"},
        "persisted_fields": [],
        "returned_fields": ["answer"],
        "receipt_signature": {
            "scheme": "brine",
            "key_scheme": "brine",
            "signer_identity": "pi-forge",
            "bytes_hex": "ab" * 64,
        },
    }


def _ok_receipt(envelope_id: str = "env-1") -> Any:
    """Build a real thermocline.Receipt via the private token (test-only)."""
    from datetime import datetime, timezone
    from thermocline.identity import _RECEIPT_TOKEN, Receipt
    from thermocline.schemes import KeyScheme
    return Receipt(
        envelope_id=envelope_id,
        signature_hash="deadbeef" * 8,
        verified_at=datetime.now(timezone.utc),
        key_scheme=KeyScheme.BRINE,
        _token=_RECEIPT_TOKEN,
    )


def _mock_signature() -> Any:
    from thermocline.identity import Signature
    from thermocline.schemes import KeyScheme
    return Signature(scheme=KeyScheme.BRINE, bytes_=b"\x00" * 64, signer_identity="alice-node")


# --- tests -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_step1_channel_resolve_failed_unknown(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    provider = MagicMock()
    verifier = MagicMock()
    with pytest.raises(DispatchError) as excinfo:
        await dispatch_async(
            channel_id="nope",
            task_draft=_draft(channel_id="nope"),
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )
    assert excinfo.value.subcode is DispatchSubcode.CHANNEL_RESOLVE_FAILED
    assert excinfo.value.stage == 1
    assert excinfo.value.audit_entry_hash is None
    provider.sign.assert_not_called()


@pytest.mark.asyncio
async def test_step1_channel_not_open(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-suspended", state=ChannelState.SUSPENDED)
    provider = MagicMock()
    verifier = MagicMock()
    with pytest.raises(DispatchError) as excinfo:
        await dispatch_async(
            channel_id="chan-suspended",
            task_draft=_draft(channel_id="chan-suspended"),
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )
    assert excinfo.value.subcode is DispatchSubcode.CHANNEL_RESOLVE_FAILED
    assert excinfo.value.stage == 1
    provider.sign.assert_not_called()


@pytest.mark.asyncio
async def test_step5_audit_failed_pre_aborts_before_sign(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """DISP-02: pre-dispatch audit-write failure aborts before signing."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1")
    provider = MagicMock()
    verifier = MagicMock()

    # Patch audit_append_async to fail.
    with patch("photophore.dispatch._coordinator.audit_append_async",
               new=AsyncMock(side_effect=RuntimeError("audit poisoned"))):
        with pytest.raises(DispatchError) as excinfo:
            await dispatch_async(
                channel_id="chan-1",
                task_draft=_draft(),
                audit_log=audit_log,
                channel_store=store,
                identity_provider=provider,
                verifier=verifier,
                forge_url="http://localhost:5000/task",
            )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.AUDIT_FAILED_PRE
    assert err.stage == 5
    assert err.retryable is True
    provider.sign.assert_not_called()


@pytest.mark.asyncio
async def test_step6_signing_failed(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1")
    provider = MagicMock()
    provider.sign.side_effect = RuntimeError("keystore locked")
    verifier = MagicMock()
    with pytest.raises(DispatchError) as excinfo:
        await dispatch_async(
            channel_id="chan-1",
            task_draft=_draft(),
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.SIGNING_FAILED
    assert err.stage == 6
    assert err.retryable is True
    assert err.audit_entry_hash is not None  # pre-dispatch entry was written first
    # And the pre-dispatch entry is in the log.
    rows = audit_log.query(envelope_id="env-1")
    assert len(rows) == 1
    assert rows[0].entry_hash == err.audit_entry_hash


@pytest.mark.asyncio
async def test_step7_transport_timeout(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1")
    provider = MagicMock()
    provider.sign.return_value = _mock_signature()
    verifier = MagicMock()

    # Patch _transport.send_async to raise directly (simulates the mapped error path).
    with patch("photophore.dispatch._coordinator.send_async",
               new=AsyncMock(side_effect=DispatchError(
                   "timeout",
                   subcode=DispatchSubcode.TRANSPORT_TIMEOUT, stage=7,
                   envelope_id="env-1", channel_id="chan-1"))):
        with pytest.raises(DispatchError) as excinfo:
            await dispatch_async(
                channel_id="chan-1",
                task_draft=_draft(),
                audit_log=audit_log,
                channel_store=store,
                identity_provider=provider,
                verifier=verifier,
                forge_url="http://localhost:5000/task",
            )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.TRANSPORT_TIMEOUT
    assert err.stage == 7
    assert err.retryable is True


@pytest.mark.asyncio
async def test_step7_transport_refused(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1")
    provider = MagicMock()
    provider.sign.return_value = _mock_signature()
    verifier = MagicMock()

    with patch("photophore.dispatch._coordinator.send_async",
               new=AsyncMock(side_effect=DispatchError(
                   "refused",
                   subcode=DispatchSubcode.TRANSPORT_REFUSED, stage=7))):
        with pytest.raises(DispatchError) as excinfo:
            await dispatch_async(
                channel_id="chan-1",
                task_draft=_draft(),
                audit_log=audit_log,
                channel_store=store,
                identity_provider=provider,
                verifier=verifier,
                forge_url="http://localhost:5000/task",
            )
    assert excinfo.value.subcode is DispatchSubcode.TRANSPORT_REFUSED
    assert excinfo.value.stage == 7


@pytest.mark.asyncio
async def test_step8_receipt_invalid_no_audit_post(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """DISP-03: receipt-verify failure → no audit-post entry."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1")
    provider = MagicMock()
    provider.sign.return_value = _mock_signature()
    verifier = MagicMock()
    verifier.verify.return_value = None  # tamper signal

    with patch("photophore.dispatch._coordinator.send_async",
               new=AsyncMock(return_value=_good_result())):
        with pytest.raises(DispatchError) as excinfo:
            await dispatch_async(
                channel_id="chan-1",
                task_draft=_draft(),
                audit_log=audit_log,
                channel_store=store,
                identity_provider=provider,
                verifier=verifier,
                forge_url="http://localhost:5000/task",
            )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.RECEIPT_INVALID
    assert err.stage == 8
    # Exactly 1 audit entry (the pre-dispatch one); no post-receipt.
    rows = audit_log.query(envelope_id="env-1")
    assert len(rows) == 1
    assert rows[0].event_type == "dispatch.pre"


@pytest.mark.asyncio
async def test_step8b_policy_violated_no_audit_post(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """POLICY-03: compare_result_against_policy returns False → POLICY_VIOLATED, no audit-post."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    # tier-0 ceiling — policy says strip_before_persist=["*"]; any persisted_fields = violation
    _seed_channel(store, channel_id="chan-1", ceiling="tier-0")
    provider = MagicMock()
    provider.sign.return_value = _mock_signature()
    verifier = MagicMock()
    verifier.verify.return_value = _ok_receipt()

    # Forge returns a result with persisted_fields=["leak"] — tier-0 violation.
    bad_result = _good_result()
    bad_result["persisted_fields"] = ["leak"]
    bad_result["returned_fields"] = ["leak"]

    with patch("photophore.dispatch._coordinator.send_async",
               new=AsyncMock(return_value=bad_result)):
        with pytest.raises(DispatchError) as excinfo:
            await dispatch_async(
                channel_id="chan-1",
                task_draft=_draft(),
                audit_log=audit_log,
                channel_store=store,
                identity_provider=provider,
                verifier=verifier,
                forge_url="http://localhost:5000/task",
            )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.POLICY_VIOLATED
    assert err.stage == 8
    rows = audit_log.query(envelope_id="env-1")
    assert len(rows) == 1, "audit-post must NOT be written when policy is violated"


@pytest.mark.asyncio
async def test_step9_happy_path_two_audit_entries(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """Happy path: pre + post audit entries written; chain link verified; result_body populated."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    # tier-2 ceiling so the policy allows the returned_fields.
    _seed_channel(store, channel_id="chan-1", ceiling="tier-2")
    provider = MagicMock()
    provider.sign.return_value = _mock_signature()
    verifier = MagicMock()
    verifier.verify.return_value = _ok_receipt()
    forge_response = _good_result()
    # tier-2 policy: persist_to_shared=["public_outputs"]; ensure persisted_fields fits.
    forge_response["persisted_fields"] = ["public_outputs"]
    forge_response["returned_fields"] = ["public_outputs"]

    with patch("photophore.dispatch._coordinator.send_async",
               new=AsyncMock(return_value=forge_response)):
        outcome = await dispatch_async(
            channel_id="chan-1",
            task_draft=_draft(),
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )

    assert isinstance(outcome, DispatchOutcome)
    assert outcome.envelope_id == "env-1"
    assert outcome.pre_audit_hash
    assert outcome.post_audit_hash
    assert outcome.pre_audit_hash != outcome.post_audit_hash
    assert outcome.result_body == forge_response
    # Two audit entries, post.prev_hash == pre.entry_hash.
    rows = audit_log.query(envelope_id="env-1")
    assert len(rows) == 2
    pre = next(r for r in rows if r.event_type == "dispatch.pre")
    post = next(r for r in rows if r.event_type == "dispatch.receipt")
    assert post.prev_hash == pre.entry_hash


@pytest.mark.asyncio
async def test_step9_audit_post_failed(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1", ceiling="tier-2")
    provider = MagicMock()
    provider.sign.return_value = _mock_signature()
    verifier = MagicMock()
    verifier.verify.return_value = _ok_receipt()
    forge_response = _good_result()
    forge_response["persisted_fields"] = ["public_outputs"]
    forge_response["returned_fields"] = ["public_outputs"]

    # The pre-dispatch append must succeed (call 1), the post must fail (call 2).
    real_append = audit_log.append
    call_count = {"n": 0}

    def _wrapped(log: AuditLog, **kwargs: Any) -> str:
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("audit-post poisoned")
        # Use the real sync API path to actually write the pre entry.
        entry = real_append(**kwargs)
        return entry.entry_hash

    async def _audit_append(log: AuditLog, **kwargs: Any) -> str:
        # Simulate the shim — but raise on second call.
        return _wrapped(log, **kwargs)

    with patch("photophore.dispatch._coordinator.send_async",
               new=AsyncMock(return_value=forge_response)), \
         patch("photophore.dispatch._coordinator.audit_append_async",
               new=_audit_append):
        with pytest.raises(DispatchError) as excinfo:
            await dispatch_async(
                channel_id="chan-1",
                task_draft=_draft(),
                audit_log=audit_log,
                channel_store=store,
                identity_provider=provider,
                verifier=verifier,
                forge_url="http://localhost:5000/task",
            )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.AUDIT_FAILED_POST
    assert err.stage == 9
    assert err.retryable is True


@pytest.mark.asyncio
async def test_signing_input_uses_canonicalize(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """DISP-04: signing path funnels through thermocline.canonical.canonicalize."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1", ceiling="tier-2")
    provider = MagicMock()
    provider.sign.return_value = _mock_signature()
    verifier = MagicMock()
    verifier.verify.return_value = _ok_receipt()
    forge_response = _good_result()
    forge_response["persisted_fields"] = ["public_outputs"]
    forge_response["returned_fields"] = ["public_outputs"]

    with patch("photophore.dispatch._coordinator.canonicalize",
               wraps=__import__("thermocline").canonicalize) as canon_spy, \
         patch("photophore.dispatch._coordinator.send_async",
               new=AsyncMock(return_value=forge_response)):
        await dispatch_async(
            channel_id="chan-1",
            task_draft=_draft(),
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )
    # canonicalize was used at least once for signing input.
    assert canon_spy.call_count >= 1


def test_no_json_dumps_in_dispatch_module() -> None:
    """DISP-04 grep gate: zero `json.dumps` in any photophore/dispatch/*.py source."""
    import re
    dispatch_dir = Path(__file__).resolve().parents[2] / "src" / "photophore" / "dispatch"
    matches: list[tuple[Path, int, str]] = []
    for py in dispatch_dir.rglob("*.py"):
        for ln, line in enumerate(py.read_text().splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if re.search(r"\bjson\.dumps\b", line):
                matches.append((py, ln, line))
    assert matches == [], f"DISP-04 violation: json.dumps found in {matches}"
