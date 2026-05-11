"""Photophore → describe-forge happy-path E2E test (Plan 03-03 Task 1).

Exercises the **core privacy primitive**: a task envelope carrying a tier-1
shadow round-trips through describe-forge into a templated description without
the forge ever reading underlying inline content. Closes ROADMAP SC4
(describe-forge tier-1 wire).

Asserts the normative D-02 template string:
    ``"This forge received a shadow of type '<content_type>' with relevance <relevance>."``

Verifies the DispatchOutcome.result_body field (populated only after both
receipt-verify and policy-compare pass per 03-01 Task 2 WARNING 4).
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
    ceiling: str,
    remote_node: str,
    local_node: str,
) -> Channel:
    chan = Channel(
        id=ChannelId(channel_id),
        local_node=local_node,
        remote_node=remote_node,
        ceiling=ceiling,
        key_scheme=key_scheme,
        state=ChannelState.OPEN,
        created_at="2026-05-11T00:00:00.000Z",
        creator_identity="alice-node",
        description="describe-forge e2e channel",
        remote_pubkey_hex=None,
    )
    _set_channel(ChannelId(channel_id), _channel_to_dict(chan))
    add_to_index(ChannelId(channel_id))
    _upsert_channels_db_raw(store._conn, chan)  # type: ignore[attr-defined]
    return chan


def _build_describe_envelope(
    *,
    envelope_id: str,
    channel_id: str,
    sovereign_identity: str,
    shadow_content_type: str = "document",
    shadow_relevance: float = 0.42,
) -> dict[str, Any]:
    """Build a task envelope with one tier-1 shadow for describe-forge.

    The forge consumes ``context[].tier=1`` blocks whose ``shadow`` dict
    carries the abstracted handle. tier-2 ceiling channels accept tier-1
    inputs but only persist public outputs (so the policy still passes the
    describe-forge response, which surfaces ``outputs.descriptions``).
    """
    return {
        "thermocline": "0.3.1",
        "type": "task",
        "envelope_id": envelope_id,
        "issued_at": "2026-05-11T00:00:00Z",
        "issuer": sovereign_identity,
        "recipient": "describe-forge",
        "channel_id": channel_id,
        "task": {
            "type": "shadow.describe",
            "instruction": "Produce templated descriptions for the tier-1 shadows.",
        },
        "context": [
            {
                "tier": 1,
                "kind": "shadow",
                "shadow": {
                    "shadow_id": "test-s1",
                    "content_type": shadow_content_type,
                    "relevance": shadow_relevance,
                    "abstraction": "a tier-1 doc abstraction",
                },
            }
        ],
        "output_contract": {"format": "text/plain"},
        "dispatch_signature": {
            "key_scheme": "brine",
            "signer_identity": sovereign_identity,
        },
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("subprocess_forge", ["describe-forge"], indirect=True)
async def test_describe_forge_happy_path_tier1_shadow(
    subprocess_forge: ForgeHandle,
    sovereign_provider: tuple[Any, Any, str, bytes],
    tmp_path: Path,
) -> None:
    """describe-forge produces D-02 normative description for tier-1 shadow input.

    Closes SC4 (describe-forge tier-1 wire). The DispatchOutcome.result_body
    field is the documented executor-inspection path; do NOT scrape forge
    stdout, do NOT rummage in the audit-log payload.
    """
    forge = subprocess_forge
    provider, verifier, sov_identity, sov_pubkey = sovereign_provider

    cross_register_keys(
        sovereign_provider=provider,
        sovereign_pubkey=sov_pubkey,
        sovereign_identity=sov_identity,
        forge_namespace=forge.namespace,
        forge_identity=forge.identity,
        forge_pubkey_hex=forge.pubkey_hex,
    )

    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    channel_id = f"chan-describe-e2e-{uuid.uuid4().hex[:6]}"
    _seed_channel(
        store,
        channel_id=channel_id,
        key_scheme="brine",
        # tier-2 ceiling: policy permits public outputs (describe-forge's
        # response surfaces outputs.descriptions). tier-0 would trigger
        # POLICY_VIOLATED — covered by Task 2's test_e2e_policy_violated.
        ceiling="tier-2",
        remote_node=forge.identity,
        local_node=sov_identity,
    )

    envelope_id = f"env-describe-e2e-{uuid.uuid4().hex[:6]}"
    draft = _build_describe_envelope(
        envelope_id=envelope_id,
        channel_id=channel_id,
        sovereign_identity=sov_identity,
        shadow_content_type="document",
        shadow_relevance=0.42,
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

    # --- normative D-02 string assertion ---
    assert outcome.result_body is not None
    assert outcome.result_body["type"] == "task_result"
    descriptions = outcome.result_body["outputs"]["descriptions"]
    assert isinstance(descriptions, list)
    assert len(descriptions) == 1, f"expected 1 description, got {descriptions!r}"
    first = descriptions[0]
    expected = (
        "This forge received a shadow of type 'document' with relevance 0.42."
    )
    assert first["description"] == expected, (
        f"D-02 normative string mismatch:\nexpected: {expected!r}\nactual:   {first['description']!r}"
    )
    assert first["shadow_id"] == "test-s1"

    # --- real-brine receipt assertion ---
    assert outcome.receipt_signature_hash
    assert len(outcome.receipt_signature_hash) >= 64

    # --- audit chain ---
    rows = audit_log.query(envelope_id=envelope_id)
    assert len(rows) == 2
    audit_log.verify_chain()
