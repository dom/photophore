"""Task 2 AT-A1 tests: step-1 fail-closed against the canonical conformance fixture.

AT-A1 ("channel impersonation") is rejected by the dispatch coordinator at step 1
when the envelope's declared key_scheme does not match the channel registry's
record — before any audit-pre entry, signing, or transport occurs.

Reference: /Users/dom/Projects/dom/thermocline/thermocline/conformance/invalid/
AT-A1-channel-impersonation.json (_phase_wired: 3).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from photophore.audit import AuditLog
from photophore.channels import ChannelStore
from photophore.channels._store import _channel_to_dict, _upsert_channels_db_raw
from photophore.channels._keystore import _set_channel
from photophore.channels._index import add_to_index
from photophore.channels._types import Channel
from photophore.core import ChannelId, ChannelState
from photophore.dispatch import DispatchError, DispatchSubcode, dispatch_async


_AT_A1_FIXTURE_PATH = Path(
    "/Users/dom/Projects/dom/thermocline/thermocline/conformance/invalid/"
    "AT-A1-channel-impersonation.json"
)


def _seed_channel(
    store: ChannelStore,
    *,
    channel_id: str,
    key_scheme: str,
    state: ChannelState = ChannelState.OPEN,
) -> Channel:
    """Insert a channel directly via the keystore+index+db triple, bypassing audit.

    Used in tests that need a channel-store record without exercising the full
    ChannelStore.create() audit-emitting path. The dispatch coordinator only
    reads via store.show() which goes through the keystore (D-04 authoritative).
    """
    chan = Channel(
        id=ChannelId(channel_id),
        local_node="alice-node",
        remote_node="pi-forge",
        ceiling="tier-1",
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


@pytest.mark.asyncio
async def test_at_a1_fixture_rejected(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """AT-A1 fixture: envelope declares key_scheme='brine' but channel is 'none' → reject at step 1."""
    fixture = json.loads(_AT_A1_FIXTURE_PATH.read_text())
    envelope = fixture["envelope"]
    channel_id = fixture["violating_condition"]["channel_id"]
    keystore_scheme = fixture["violating_condition"]["keystore_key_scheme"]  # "none"

    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id=channel_id, key_scheme=keystore_scheme)

    # Mock identity + verifier — they MUST NOT be called for an AT-A1-rejected envelope.
    provider = MagicMock()
    verifier = MagicMock()

    with pytest.raises(DispatchError) as excinfo:
        await dispatch_async(
            channel_id=channel_id,
            task_draft=envelope,
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.CHANNEL_RESOLVE_FAILED
    assert err.stage == 1
    assert err.audit_entry_hash is None  # no pre-dispatch audit was written
    # And no signing happened.
    provider.sign.assert_not_called()
    # And no audit-pre entry exists for this envelope_id.
    rows = audit_log.query(envelope_id=envelope["envelope_id"])
    assert rows == []


@pytest.mark.asyncio
async def test_at_a1_envelope_without_key_scheme_field_rejected(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """T-03-02 fail-closed: envelope omits BOTH dispatch_signature AND top-level
    key_scheme → still rejected at step 1 (None != channel.key_scheme).

    This is the critical AT-A1 invariant — an attacker cannot bypass the guard by
    omitting the key_scheme field.
    """
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-no-scheme", key_scheme="brine")

    # Envelope has NO dispatch_signature block AND NO top-level key_scheme field.
    bare_envelope: dict[str, Any] = {
        "thermocline": "0.3.1",
        "type": "task",
        "envelope_id": "env-bare-no-scheme",
        "issued_at": "2026-05-11T00:00:00Z",
        "issuer": "alice-node",
        "recipient": "pi-forge",
        "channel_id": "chan-no-scheme",
        "task": {"type": "data.compute", "instruction": "noop"},
        "context": [],
        "output_contract": {"format": "text/plain"},
    }
    provider = MagicMock()
    verifier = MagicMock()

    with pytest.raises(DispatchError) as excinfo:
        await dispatch_async(
            channel_id="chan-no-scheme",
            task_draft=bare_envelope,
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.CHANNEL_RESOLVE_FAILED
    assert err.stage == 1
    assert err.audit_entry_hash is None
    provider.sign.assert_not_called()
    # AT-A1 fail-closed: ZERO audit-pre entries written.
    rows = audit_log.query(envelope_id="env-bare-no-scheme")
    assert rows == [], "audit-pre written for AT-A1-rejected envelope (fail-closed violation)"


@pytest.mark.asyncio
async def test_at_a1_unknown_channel_rejected(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """Unknown channel_id → CHANNEL_RESOLVE_FAILED at step 1, no audit-pre, no sign."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)

    draft = {
        "envelope_id": "env-x",
        "type": "task",
        "channel_id": "no-such-channel",
        "dispatch_signature": {"key_scheme": "brine"},
        "context": [],
    }
    provider = MagicMock()
    verifier = MagicMock()
    with pytest.raises(DispatchError) as excinfo:
        await dispatch_async(
            channel_id="no-such-channel",
            task_draft=draft,
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )
    assert excinfo.value.subcode is DispatchSubcode.CHANNEL_RESOLVE_FAILED
    assert excinfo.value.stage == 1
    provider.sign.assert_not_called()
