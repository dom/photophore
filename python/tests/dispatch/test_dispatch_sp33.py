"""SP-3.3 dispatch-signature wire contract (thermocline 0.4.0).

The forge side verifies via thermocline.verify_envelope: it resets
``dispatch_signature.sig`` to "" and canonicalizes the WHOLE envelope. The
coordinator must therefore sign an envelope whose signature block carries all
non-sig fields (including ``node_id``) with ``sig=""``, then place the hex
signature into ``sig`` on the wire. The legacy ``bytes_hex`` field is gone.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from thermocline import verify_envelope
from thermocline.identity import BrineProvider, Verifier

from photophore.audit import AuditLog
from photophore.channels import ChannelStore
from tests.dispatch.test_dispatch_coordinator import (
    _draft,
    _good_result,
    _seed_channel,
)


@pytest.mark.asyncio
async def test_signed_envelope_verifies_via_thermocline_verify_envelope(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """End-to-end wire check: a real brine signature verifies per SP-3.3."""
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_channel(store, channel_id="chan-1", ceiling="tier-2")

    provider = BrineProvider(keyring_service="thermocline.brine.sp33-test")
    provider.generate(identity="alice-node")
    verifier = Verifier()
    verifier.register(provider)

    result: dict[str, Any] = _good_result()
    result["persisted_fields"] = []
    result["returned_fields"] = []

    send_mock = AsyncMock(return_value=result)
    # Receipt verification is not under test here; stub the verifier's
    # verify() only for the receipt call by patching at the coordinator
    # level after capturing the signed envelope is not possible, so use a
    # forwarding wrapper object instead.

    class _ReceiptStubVerifier:
        def verify(self, *, envelope: dict[str, Any], signature: Any) -> Any:
            from tests.dispatch.test_dispatch_coordinator import _ok_receipt

            return _ok_receipt()

    from photophore.dispatch import dispatch_async

    with patch("photophore.dispatch._coordinator.send_async", new=send_mock):
        await dispatch_async(
            channel_id="chan-1",
            task_draft=_draft(),
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=_ReceiptStubVerifier(),
            forge_url="http://localhost:5000/task",
        )

    signed_envelope = send_mock.call_args.kwargs["signed_envelope"]
    sig_block = signed_envelope["dispatch_signature"]
    # SP-3.3 wire shape: sig carries the hex signature; node_id binds the
    # signer; the legacy bytes_hex field is gone.
    assert isinstance(sig_block.get("sig"), str) and sig_block["sig"], (
        "dispatch_signature.sig must carry the hex signature"
    )
    assert sig_block.get("node_id") == "alice-node"
    assert sig_block.get("key_scheme") == "brine"
    assert "bytes_hex" not in sig_block, "legacy bytes_hex must not be emitted"

    # The forge-side check: verify_envelope succeeds against the wire bytes.
    receipt = verify_envelope(signed_envelope, verifier, allow_unsigned=False)
    assert receipt is not None, (
        "signed envelope must verify via thermocline.verify_envelope (SP-3.3)"
    )
    assert receipt.verified_identity == "alice-node"
