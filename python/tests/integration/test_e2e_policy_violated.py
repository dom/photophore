"""Policy-violated E2E test — POLICY-03 closure.

describe-forge returns a result whose ``outputs`` contains keys that, under
the v0.1 derivation rule, count as persisted_fields. Under a tier-0 channel
ceiling the policy template forbids any persistence — so the result violates
the authored ResultPolicy and dispatch must raise POLICY_VIOLATED.

# v0.1 derivation: persisted_fields = list(result["outputs"].keys());
#                  returned_fields  = list(result["outputs"].keys())
Forges that omit explicit ``persisted_fields`` / ``returned_fields`` get the
conservative derivation from outputs. The dispatch coordinator applies this
rule at step 8b when the forge response does not surface those fields.
"""
from __future__ import annotations

import asyncio
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
from photophore.dispatch import DispatchError, DispatchSubcode, dispatch_async

from tests.integration.conftest import ForgeHandle, cross_register_keys


def _seed_channel(
    store: ChannelStore,
    *,
    channel_id: str,
    ceiling: str,
    key_scheme: str = "brine",
    remote_node: str = "describe-forge",
    local_node: str = "alice-node",
) -> Channel:
    chan = Channel(
        id=ChannelId(channel_id),
        local_node=local_node,
        remote_node=remote_node,
        ceiling=ceiling,
        key_scheme=key_scheme,
        state=ChannelState.OPEN,
        created_at="2026-05-11T00:00:00.000Z",
        creator_identity=local_node,
        description="policy-violated test channel",
        remote_pubkey_hex=None,
    )
    _set_channel(ChannelId(channel_id), _channel_to_dict(chan))
    add_to_index(ChannelId(channel_id))
    _upsert_channels_db_raw(store._conn, chan)  # type: ignore[attr-defined]
    return chan


@pytest.mark.asyncio
@pytest.mark.parametrize("subprocess_forge", ["describe-forge"], indirect=True)
async def test_policy_violated_e2e_describe_forge_tier0_channel(
    subprocess_forge: ForgeHandle,
    sovereign_provider: tuple[Any, Any, str, bytes],
    tmp_path: Path,
) -> None:
    """Tier-0 channel + describe-forge response with non-empty outputs.

    Concrete construction: channel ceiling=tier-0 produces ResultPolicy
    ``persist_to_shared=[]``, ``return_only=[]``, ``strip_before_persist=["*"]``
    per the policy template. describe-forge's response has
    ``outputs={"descriptions": [...], "note": None}`` — non-empty. Under the
    v0.1 derivation rule, ``persisted_fields = list(outputs.keys())
    = ["descriptions", "note"]``. The tier-0 policy says NOTHING may be
    persisted (the "*" wildcard) — violation. POLICY-03 closure.

    # v0.1 derivation: persisted_fields = list(result["outputs"].keys());
    #                  returned_fields  = list(result["outputs"].keys())
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
    channel_id = f"chan-policy-violated-{uuid.uuid4().hex[:6]}"
    _seed_channel(
        store,
        channel_id=channel_id,
        ceiling="tier-0",  # tier-0: strip_before_persist=["*"]; NOTHING may be persisted.
        remote_node=forge.identity,
        local_node=sov_identity,
    )

    envelope_id = f"env-policy-violated-{uuid.uuid4().hex[:6]}"
    draft = {
        "thermocline": "0.3.1",
        "type": "task",
        "envelope_id": envelope_id,
        "issued_at": "2026-05-11T00:00:00Z",
        "issuer": sov_identity,
        "recipient": "describe-forge",
        "channel_id": channel_id,
        "task": {
            "type": "shadow.describe",
            "instruction": "Produce templated descriptions.",
        },
        "context": [
            {
                "tier": 1,
                "kind": "shadow",
                "shadow": {
                    "shadow_id": "test-s1",
                    "content_type": "document",
                    "relevance": 0.5,
                },
            }
        ],
        "output_contract": {"format": "text/plain"},
        "dispatch_signature": {
            "key_scheme": "brine",
            "signer_identity": sov_identity,
        },
    }

    with pytest.raises(DispatchError) as excinfo:
        await dispatch_async(
            channel_id=channel_id,
            task_draft=draft,
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url=f"{forge.url}/task",
        )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.POLICY_VIOLATED
    assert err.stage == 8
    assert err.retryable is False, (
        "POLICY-03: POLICY_VIOLATED is non-retryable — retrying with the same "
        "envelope produces the same policy authoring + same forge response"
    )

    # POLICY-03 closure: exactly 1 audit entry (the pre-dispatch one). No audit-post.
    rows = audit_log.query(envelope_id=envelope_id)
    assert len(rows) == 1, (
        f"expected exactly 1 audit entry (pre-dispatch only), got {len(rows)}: "
        f"{[r.event_type for r in rows]!r}"
    )
    assert rows[0].event_type == "dispatch.pre"
