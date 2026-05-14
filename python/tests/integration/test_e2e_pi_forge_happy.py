"""Photophore → pi-forge happy-path E2E test.

Closes ROADMAP SC1 (full 9-step round trip) and SC3 (pi-forge real brine
round trip). Asserts:
    1. dispatch_async completes without raising.
    2. The DispatchOutcome contains a non-empty receipt_signature_hash.
    3. The audit log contains exactly 2 entries (pre-dispatch + receipt) for
       the envelope_id, and they form a verified chain link.

Real ed25519 dispatch_signature signed by the sovereign and verified by
pi-forge; real ed25519 receipt_signature signed by pi-forge and verified by
the sovereign — the full round-trip is exercised over real HTTP.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest

from photophore.audit import AuditLog
from photophore.channels import ChannelStore, ChannelState
from photophore.channels._store import _channel_to_dict, _upsert_channels_db_raw
from photophore.channels._keystore import _set_channel
from photophore.channels._index import add_to_index
from photophore.channels._types import Channel
from photophore.core import ChannelId
from photophore.dispatch import dispatch_async

from tests.integration.conftest import ForgeHandle, cross_register_keys


def _seed_channel(
    store: ChannelStore,
    *,
    channel_id: str,
    key_scheme: str,
    ceiling: str = "tier-2",
    remote_node: str = "pi-forge",
    local_node: str = "alice-node",
) -> Channel:
    """Insert a channel directly via the keystore+index+db triple (bypasses audit)."""
    chan = Channel(
        id=ChannelId(channel_id),
        local_node=local_node,
        remote_node=remote_node,
        ceiling=ceiling,
        key_scheme=key_scheme,
        state=ChannelState.OPEN,
        created_at="2026-05-11T00:00:00.000Z",
        creator_identity="alice-node",
        description="e2e test channel",
        remote_pubkey_hex=None,
    )
    _set_channel(ChannelId(channel_id), _channel_to_dict(chan))
    add_to_index(ChannelId(channel_id))
    _upsert_channels_db_raw(store._conn, chan)  # type: ignore[attr-defined]
    return chan


def _build_e2e_envelope(
    *, envelope_id: str, channel_id: str, sovereign_identity: str
) -> dict[str, Any]:
    """Build the task envelope to dispatch — tier-2 ceiling, real brine.

    Uses ``thermocline=0.3.1`` (the version Photophore/pi-forge currently emit)
    and ``dispatch_signature.key_scheme="brine"`` (the channel scheme). The
    ``bytes_hex`` field is INTENTIONALLY ABSENT — dispatch_async fills it in
    after step 6 (sign).
    """
    return {
        "thermocline": "0.3.1",
        "type": "task",
        "envelope_id": envelope_id,
        "issued_at": "2026-05-11T00:00:00Z",
        "issuer": sovereign_identity,
        "recipient": "pi-forge",
        "channel_id": channel_id,
        "task": {
            "type": "data.compute",
            "instruction": "Compute pi to the requested number of decimal digits.",
            "parameters": {"digits": 10},
        },
        "context": [
            {
                "tier": 2,
                "role": "task_background",
                "content": "End-to-end integration test; tier-2 only.",
            }
        ],
        "output_contract": {"format": "text/plain"},
        "dispatch_signature": {
            "key_scheme": "brine",
            "signer_identity": sovereign_identity,
        },
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("subprocess_forge", ["pi-forge"], indirect=True)
async def test_pi_forge_happy_path_real_brine_real_http(
    subprocess_forge: ForgeHandle,
    sovereign_provider: tuple[Any, Any, str, bytes],
    tmp_path: Path,
) -> None:
    """Photophore → pi-forge → verified receipt → 2 audit entries with verified chain link.

    Closes SC1 (full 9-step round trip) and SC3 (pi-forge real brine round trip).
    """
    forge = subprocess_forge
    provider, verifier, sov_identity, sov_pubkey = sovereign_provider

    # Cross-register pubkeys: sovereign learns forge pubkey for receipt verify,
    # forge learns sovereign pubkey for dispatch-signature verify.
    cross_register_keys(
        sovereign_provider=provider,
        sovereign_pubkey=sov_pubkey,
        sovereign_identity=sov_identity,
        forge_namespace=forge.namespace,
        forge_identity=forge.identity,
        forge_pubkey_hex=forge.pubkey_hex,
    )

    # Set up the sovereign-side audit log + channel store.
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    channel_id = f"chan-piforge-e2e-{uuid.uuid4().hex[:6]}"
    _seed_channel(
        store,
        channel_id=channel_id,
        key_scheme="brine",
        ceiling="tier-2",
        remote_node=forge.identity,
        local_node=sov_identity,
    )

    envelope_id = f"env-piforge-e2e-{uuid.uuid4().hex[:6]}"
    draft = _build_e2e_envelope(
        envelope_id=envelope_id,
        channel_id=channel_id,
        sovereign_identity=sov_identity,
    )

    outcome = await dispatch_async(
        channel_id=channel_id,
        task_draft=draft,
        audit_log=audit_log,
        channel_store=store,
        identity_provider=provider,
        verifier=verifier,
        forge_url=f"{forge.url}/task",
    )

    # --- happy-path assertions ---
    assert outcome.envelope_id == envelope_id
    # signature_hash is blake2b(canonical_bytes + sig_bytes) hex; 64 bytes -> 128 hex chars.
    assert len(outcome.receipt_signature_hash) >= 64
    assert all(c in "0123456789abcdef" for c in outcome.receipt_signature_hash.lower())
    # 2 audit entries (pre + receipt) — they form one chain link.
    assert outcome.pre_audit_hash
    assert outcome.post_audit_hash
    assert outcome.pre_audit_hash != outcome.post_audit_hash

    # --- audit-log inspection ---
    rows = audit_log.query(envelope_id=envelope_id)
    assert len(rows) == 2, (
        f"expected 2 audit entries (pre + receipt), got {len(rows)}: {rows!r}"
    )
    event_types = sorted(r.event_type for r in rows)
    assert event_types == ["dispatch.pre", "dispatch.receipt"], (
        f"unexpected event types: {event_types!r}"
    )
    # Chain verify across the whole log (1 link in this case).
    audit_log.verify_chain()

    # --- result_body inspection (DispatchOutcome.result_body, populated post-policy-compare) ---
    assert outcome.result_body is not None
    assert outcome.result_body["type"] == "task_result"
    assert outcome.result_body["envelope_id"] == envelope_id
    # pi to 10 digits is the canonical mpmath output.
    pi_str = outcome.result_body["outputs"]["pi"]
    assert pi_str.startswith("3.14159"), f"unexpected pi output: {pi_str!r}"
