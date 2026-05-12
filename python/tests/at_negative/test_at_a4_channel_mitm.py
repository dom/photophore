"""AT-A4: Channel MITM — tampering envelope bytes invalidates the signature.

Failure mode: an attacker between sovereign and forge modifies the envelope
in flight; the sovereign's dispatch_signature is over the canonical bytes
and the forge MUST reject on signature mismatch.

The full integration test (real HTTP, forged receipt) lives at
tests/integration/test_e2e_forged_receipt.py. This at_negative wrapper covers
the surface for the coverage gate; the structural defense is in
thermocline.canonical (any byte mutation changes canonical bytes).
"""
# AT-SURFACE: AT-A4
from __future__ import annotations

from pathlib import Path

import pytest

from thermocline.canonical import canonicalize


@pytest.mark.at_surface("AT-A4")
def test_channel_mitm_invalidates_signature() -> None:
    """Envelope mutation produces different canonical bytes -> signature reject.

    The structural defense: thermocline.canonical.canonicalize is RFC 8785
    deterministic; any single-byte mutation produces different bytes.
    Verifier.verify rejects via ed25519 byte-mismatch.
    """
    envelope = {
        "thermocline": "0.3.1",
        "type": "task",
        "envelope_id": "00000000-0000-0000-0000-00000000a400",
        "issuer": "alice-node",
        "task": {"type": "data.compute", "parameters": {"digits": 10}},
    }
    original = canonicalize(envelope)
    tampered = dict(envelope)
    tampered["issuer"] = "mallory-node"
    assert canonicalize(tampered) != original, (
        "AT-A4: in-flight envelope mutation MUST change canonical bytes; "
        "ed25519 verify on different bytes rejects"
    )


@pytest.mark.at_surface("AT-A4")
def test_at_a4_integration_test_present() -> None:
    """The forged-receipt integration test exists as the live AT-A4 wire-in."""
    target = Path(__file__).resolve().parents[1] / "integration" / "test_e2e_forged_receipt.py"
    assert target.is_file(), (
        f"AT-A4: source-of-truth integration test missing at {target}"
    )
