"""Dispatch-time privacy enforcement tests.

The coordinator MUST enforce its own classification results (the shadow
membrane cannot delegate stripping/shadowing to the caller):

- a block classified tier-0 (local) is hard-dropped: its raw content never
  appears in the signed envelope bytes
- a tier-1 block carrying raw content is emitted ONLY as a freshly generated
  shadow (shadow_generate wired in via the coordinator)
- a block whose effective tier exceeds the channel trust ceiling blocks the
  whole dispatch, fail closed, before signing
"""
# AT-SURFACE: AT-A3
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from thermocline import canonicalize

from photophore.audit import AuditLog
from photophore.channels import ChannelStore
from photophore.dispatch import DispatchError, DispatchSubcode, dispatch_async
from tests.dispatch.test_dispatch_coordinator import (
    _draft,
    _good_result,
    _mock_signature,
    _ok_receipt,
    _seed_channel,
)

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
_PRIVATE_PARAGRAPH = (
    "Quarterly finance narrative with client names and internal projections."
)


def _wire_mocks() -> tuple[MagicMock, MagicMock]:
    provider = MagicMock()
    provider.sign.return_value = _mock_signature()
    verifier = MagicMock()
    verifier.verify.return_value = _ok_receipt()
    return provider, verifier


def _result_ok() -> dict[str, Any]:
    result = _good_result()
    result["persisted_fields"] = []
    result["returned_fields"] = []
    return result


@pytest.mark.asyncio
@pytest.mark.at_surface("AT-A3")
async def test_classified_tier0_content_never_emitted(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """A raw block whose content classifies local (credential) is hard-dropped.

    The signed envelope bytes MUST NOT contain the credential, even though the
    caller declared the block tier-2.
    """
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1", ceiling="tier-2")
    provider, verifier = _wire_mocks()

    draft = _draft()
    draft["context"] = [
        {"tier": 2, "role": "background", "content": f"deploy key {_AWS_KEY} for prod"},
    ]

    send_mock = AsyncMock(return_value=_result_ok())
    with patch("photophore.dispatch._coordinator.send_async", new=send_mock):
        outcome = await dispatch_async(
            channel_id="chan-1",
            task_draft=draft,
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )

    signed_envelope = send_mock.call_args.kwargs["signed_envelope"]
    wire_bytes = canonicalize(signed_envelope)
    assert _AWS_KEY.encode() not in wire_bytes, (
        "tier-0 classified content leaked into the signed envelope bytes"
    )
    assert signed_envelope["context"] == [], (
        "tier-0 classified block must be hard-dropped from context[]"
    )
    assert any("tier-0" in w for w in outcome.warnings), (
        "dropping a tier-0 block must surface a warning"
    )


@pytest.mark.asyncio
@pytest.mark.at_surface("AT-A3")
async def test_declared_tier0_block_dropped_even_if_content_innocuous(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """An issuer-declared tier-0 block never crosses, whatever its content."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1", ceiling="tier-2")
    provider, verifier = _wire_mocks()

    draft = _draft()
    draft["context"] = [
        {"tier": 0, "role": "note", "content": "innocuous but issuer says local"},
    ]

    send_mock = AsyncMock(return_value=_result_ok())
    with patch("photophore.dispatch._coordinator.send_async", new=send_mock):
        await dispatch_async(
            channel_id="chan-1",
            task_draft=draft,
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )

    signed_envelope = send_mock.call_args.kwargs["signed_envelope"]
    wire_bytes = canonicalize(signed_envelope)
    assert b"innocuous but issuer says local" not in wire_bytes
    assert signed_envelope["context"] == []


@pytest.mark.asyncio
@pytest.mark.at_surface("AT-A3")
async def test_tier1_content_emitted_only_as_fresh_shadow(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """A tier-1 block carrying raw content crosses ONLY as a generated shadow."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1", ceiling="tier-2")
    provider, verifier = _wire_mocks()

    draft = _draft()
    draft["context"] = [
        {
            "tier": 1,
            "role": "notes",
            "content": _PRIVATE_PARAGRAPH,
            "content_type": "document",
        },
    ]

    send_mock = AsyncMock(return_value=_result_ok())
    with patch("photophore.dispatch._coordinator.send_async", new=send_mock):
        await dispatch_async(
            channel_id="chan-1",
            task_draft=draft,
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )

    signed_envelope = send_mock.call_args.kwargs["signed_envelope"]
    wire_bytes = canonicalize(signed_envelope)
    assert _PRIVATE_PARAGRAPH.encode() not in wire_bytes, (
        "tier-1 raw content leaked into the signed envelope bytes"
    )
    context = signed_envelope["context"]
    assert len(context) == 1
    block = context[0]
    assert "content" not in block, "tier-1 block must not carry raw content"
    shadow = block.get("shadow")
    assert isinstance(shadow, dict), "tier-1 block must carry a shadow substructure"
    assert shadow.get("shadow_id"), "generated shadow must carry a fresh shadow_id"
    assert shadow.get("abstraction"), "generated shadow must carry an abstraction"
    assert _PRIVATE_PARAGRAPH not in str(shadow.get("abstraction"))
    # The generated shadow_id is recorded in the pre-dispatch audit payload.
    rows = audit_log.query(envelope_id="env-1", event_type="dispatch.pre")
    assert len(rows) == 1
    assert shadow["shadow_id"] in rows[0].payload.get("shadow_ids", [])


@pytest.mark.asyncio
async def test_tier1_shadow_only_block_preserved(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """A tier-1 block already carrying only a shadow reference passes through."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1", ceiling="tier-2")
    provider, verifier = _wire_mocks()

    draft = _draft()
    draft["context"] = [
        {
            "tier": 1,
            "kind": "shadow",
            "role": "notes",
            "shadow": {
                "shadow_id": "pre-existing-shadow",
                "content_type": "document",
                "abstraction": "document of length class short",
                "relevance": 0.5,
            },
        },
    ]

    send_mock = AsyncMock(return_value=_result_ok())
    with patch("photophore.dispatch._coordinator.send_async", new=send_mock):
        await dispatch_async(
            channel_id="chan-1",
            task_draft=draft,
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url="http://localhost:5000/task",
        )

    signed_envelope = send_mock.call_args.kwargs["signed_envelope"]
    assert signed_envelope["context"][0]["shadow"]["shadow_id"] == "pre-existing-shadow"


@pytest.mark.asyncio
async def test_shadow_generation_hard_fail_aborts_dispatch(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """Irreversibility hard-fail on shadow generation aborts before signing."""
    from photophore.errors import ShadowIrreversibilityError

    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1", ceiling="tier-2")
    provider, verifier = _wire_mocks()

    draft = _draft()
    draft["context"] = [
        {"tier": 1, "role": "notes", "content": _PRIVATE_PARAGRAPH},
    ]

    with patch(
        "photophore.dispatch._coordinator.shadow_generate_async",
        new=AsyncMock(side_effect=ShadowIrreversibilityError("leaky abstraction")),
    ):
        with pytest.raises(DispatchError) as excinfo:
            await dispatch_async(
                channel_id="chan-1",
                task_draft=draft,
                audit_log=audit_log,
                channel_store=store,
                identity_provider=provider,
                verifier=verifier,
                forge_url="http://localhost:5000/task",
            )
    assert excinfo.value.subcode is DispatchSubcode.SHADOW_GENERATION_FAILED
    assert excinfo.value.stage == 3
    provider.sign.assert_not_called()


def test_fail_closed_backstop_rejects_surviving_local_content() -> None:
    """The post-enforcement invariant check aborts on any raw local leftovers."""
    from photophore.dispatch._coordinator import _assert_context_fail_closed

    with pytest.raises(DispatchError) as excinfo:
        _assert_context_fail_closed(
            [{"tier": 2, "role": "background", "content": f"key {_AWS_KEY}"}],
            rules=None,
            channel_id="chan-1",
            envelope_id="env-1",
        )
    assert excinfo.value.subcode is DispatchSubcode.CLASSIFICATION_FAILED

    with pytest.raises(DispatchError):
        _assert_context_fail_closed(
            [{"tier": 1, "role": "notes", "content": "raw content on a tier-1 block"}],
            rules=None,
            channel_id="chan-1",
            envelope_id="env-1",
        )

    with pytest.raises(DispatchError):
        _assert_context_fail_closed(
            [{"tier": 0, "role": "notes", "content": "declared local"}],
            rules=None,
            channel_id="chan-1",
            envelope_id="env-1",
        )
