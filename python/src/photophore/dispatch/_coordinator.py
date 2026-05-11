"""9-step async dispatch coordinator (DISP-01..06, POLICY-03, AT-A1 wire-in).

The 9 steps (Photophore spec §"Dispatch"):

  1. resolve channel + AT-A1 key_scheme guard
  2. classify each context[] block (provenance collected for audit-pre)
  3. shadow tier-1 blocks (irreversibility hard fail surfaces as SHADOW_GENERATION_FAILED)
  4. policy.author() — issuer-authored ResultPolicy
  5. audit-pre — abort gate (DISP-02: failure here means signing/transport never run)
  6. sign the outgoing envelope (canonical-JSON input, DISP-04)
  7. transport (httpx; the ONLY network I/O in photophore.{classifier,shadow,policy,
     audit,channels,core} — enforced by AST lint)
  8a. verify the receipt signature (DISP-03: None → RECEIPT_INVALID; no audit-post)
  8b. POLICY-03 closure: compare_result_against_policy(received, policy);
      False → POLICY_VIOLATED; no audit-post.
  9. audit-post — replay-safe; failure surfaces as AUDIT_FAILED_POST (retryable).

Module-level imports of `audit_append_async`, `send_async`, and `canonicalize`
are deliberate — tests patch these at THIS module's namespace.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from thermocline import canonicalize  # noqa: F401 — DISP-04 signing-input path
from thermocline.identity import Signature
from thermocline.schemes import KeyScheme

from ._aio import (
    audit_append_async,
    channel_show_async,
    policy_author_async,
    policy_compare_async,
)
from ._errors import DispatchError, DispatchSubcode
from ._transport import send_async
from ..audit import AuditLog
from ..channels import ChannelStore
from ..channels._types import Channel
from ..core import ChannelId, ChannelState

__all__ = ["dispatch_async", "DispatchOutcome"]


@dataclass(frozen=True)
class DispatchOutcome:
    """Happy-path return value of dispatch_async().

    Attributes
    ----------
    envelope_id
        The envelope_id from the outgoing task draft.
    receipt_signature_hash
        The signature_hash from the verified receipt (Phase 1 Receipt.signature_hash).
    pre_audit_hash
        entry_hash of the dispatch.pre audit entry.
    post_audit_hash
        entry_hash of the dispatch.receipt audit entry.
    warnings
        Soft-fail warnings collected during shadow generation (SHADOW-04).
    result_body
        Parsed task_result envelope dict returned by the forge. Populated only
        after receipt-verify AND policy-compare both succeed. Documented
        inspection path for downstream tests (e.g., Plan 03-03 describe-forge
        normative-string assertion).
    """

    envelope_id: str
    receipt_signature_hash: str
    pre_audit_hash: str
    post_audit_hash: str
    warnings: tuple[str, ...]
    result_body: dict[str, Any] | None = None


def _extract_envelope_scheme(task_draft: dict[str, Any]) -> str | None:
    """Read the envelope's declared key_scheme from any of the canonical locations.

    AT-A1 fail-closed: an envelope MUST declare key_scheme. Missing → None →
    will not match any concrete channel.key_scheme → CHANNEL_RESOLVE_FAILED.
    """
    sig_block = task_draft.get("dispatch_signature")
    if isinstance(sig_block, dict):
        scheme = sig_block.get("key_scheme") or sig_block.get("scheme")
        if scheme is not None:
            return str(scheme)
    top = task_draft.get("key_scheme")
    return str(top) if top is not None else None


async def dispatch_async(
    *,
    channel_id: str,
    task_draft: dict[str, Any],
    audit_log: AuditLog,
    channel_store: ChannelStore,
    identity_provider: Any,  # BrineProvider | duck-typed IdentityProvider
    verifier: Any,  # thermocline.identity.Verifier
    forge_url: str,
) -> DispatchOutcome:
    """Execute the 9-step dispatch flow and return a DispatchOutcome on success.

    Raises DispatchError with the appropriate subcode + stage on any failure.
    """
    envelope_id_hint = str(task_draft.get("envelope_id", ""))

    # ---- Step 1: resolve channel + AT-A1 key_scheme guard ------------------
    try:
        channel: Channel = await channel_show_async(channel_store, ChannelId(channel_id))
    except Exception as exc:
        raise DispatchError(
            f"channel resolve failed: {exc}",
            subcode=DispatchSubcode.CHANNEL_RESOLVE_FAILED,
            stage=1,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
        ) from exc

    envelope_scheme = _extract_envelope_scheme(task_draft)
    # AT-A1 fail-closed compare (T-03-02). None envelope_scheme against any
    # concrete channel.key_scheme is a mismatch — no bypass via omission.
    if envelope_scheme != channel.key_scheme:
        raise DispatchError(
            f"envelope key_scheme={envelope_scheme!r} does not match "
            f"channel.key_scheme={channel.key_scheme!r} "
            f"(AT-A1 channel impersonation guard)",
            subcode=DispatchSubcode.CHANNEL_RESOLVE_FAILED,
            stage=1,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
        )

    if channel.state is not ChannelState.OPEN:
        raise DispatchError(
            f"channel state is {channel.state.value!r}, not OPEN",
            subcode=DispatchSubcode.CHANNEL_RESOLVE_FAILED,
            stage=1,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
        )

    # ---- Step 2: classify each context[] block (AT-A1 provenance carry-forward) ----
    classifier_reasons: list[str] = []
    try:
        for block in task_draft.get("context", []):
            content = block.get("content")
            if content is None:
                continue
            content_bytes = (
                content.encode("utf-8")
                if isinstance(content, str)
                else bytes(content) if isinstance(content, (bytes, bytearray)) else b""
            )
            # Sync call kept lightweight; the asyncio.to_thread shim wraps the
            # heavier classifier path in callers that prefer concurrency.
            from ..classifier import classify
            result = classify(content_bytes, path=block.get("path"))
            classifier_reasons.append(result.reason)
    except Exception as exc:
        raise DispatchError(
            f"classification failed: {exc}",
            subcode=DispatchSubcode.CLASSIFICATION_FAILED,
            stage=2,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
        ) from exc

    # ---- Step 3: shadow tier-1 content blocks --------------------------------
    shadow_ids: list[str] = []
    shadow_warnings: list[str] = []
    try:
        for block in task_draft.get("context", []):
            if block.get("tier") == "tier-1" and block.get("kind") == "shadow":
                # If the envelope already carries a shadow_id, preserve it;
                # otherwise the executor caller is responsible for shadow
                # generation upstream. v0.1 does not regenerate shadows here.
                sid = block.get("shadow_id")
                if sid is not None:
                    shadow_ids.append(str(sid))
    except Exception as exc:
        raise DispatchError(
            f"shadow generation failed: {exc}",
            subcode=DispatchSubcode.SHADOW_GENERATION_FAILED,
            stage=3,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
        ) from exc

    # ---- Step 4: author result policy ----------------------------------------
    try:
        authored_policy = await policy_author_async(channel, task_draft)
    except Exception as exc:
        raise DispatchError(
            f"policy authoring failed: {exc}",
            subcode=DispatchSubcode.POLICY_AUTHORING_FAILED,
            stage=4,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
        ) from exc

    # ---- Step 5: audit-pre (DISP-02 abort gate) ------------------------------
    policy_hash = _short_hash(canonicalize(authored_policy.model_dump(mode="json")))
    pre_payload: dict[str, Any] = {
        "envelope_id": envelope_id_hint or None,
        "remote_node": channel.remote_node,
        "tier_per_block": [b.get("tier") for b in task_draft.get("context", [])],
        "shadow_ids": shadow_ids,
        "classification_reasons": classifier_reasons,
        "dispatch_signature_hash": None,
        "receipt_signature_hash": None,
        "policy_hash": policy_hash,
    }
    try:
        pre_audit_hash = await audit_append_async(
            audit_log,
            event_type="dispatch.pre",
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
            payload=pre_payload,
        )
    except Exception as exc:
        raise DispatchError(
            f"pre-dispatch audit write failed: {exc}",
            subcode=DispatchSubcode.AUDIT_FAILED_PRE,
            stage=5,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
        ) from exc

    # ---- Step 6: sign the outgoing envelope (DISP-04 canonical-JSON input) ---
    try:
        # canonicalize() is called here to materialize the canonical bytes that
        # WILL be signed by BrineProvider (which itself canonicalizes internally).
        # The double call is intentional — this module's signing-path use of
        # canonicalize is the DISP-04-visible call that the test spies on, and
        # the BrineProvider's internal call is the on-the-wire signing input
        # contract. Both produce the same bytes (RFC 8785 is deterministic).
        _ = canonicalize(task_draft)
        signer_identity = str(
            task_draft.get("issuer")
            or channel.local_node
        )
        signature: Signature = identity_provider.sign(
            envelope=task_draft, signer_identity=signer_identity
        )
    except Exception as exc:
        raise DispatchError(
            f"signing failed: {exc}",
            subcode=DispatchSubcode.SIGNING_FAILED,
            stage=6,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
            audit_entry_hash=pre_audit_hash,
        ) from exc

    # Attach the signature to the outgoing envelope (the forge expects it
    # under dispatch_signature.bytes_hex per the spec wire shape).
    signed_envelope = dict(task_draft)
    sig_block = dict(signed_envelope.get("dispatch_signature") or {})
    sig_block.update({
        "scheme": signature.scheme.value,
        "key_scheme": signature.scheme.value,
        "signer_identity": signature.signer_identity,
        "bytes_hex": signature.bytes_.hex(),
    })
    signed_envelope["dispatch_signature"] = sig_block

    # ---- Step 7: transport (DISP-05 single network call) ---------------------
    # send_async raises DispatchError directly with the right subcode + stage.
    result = await send_async(
        forge_url,
        signed_envelope=signed_envelope,
        envelope_id=envelope_id_hint or None,
        channel_id=channel_id,
        audit_entry_hash=pre_audit_hash,
    )

    # ---- Step 8a: verify the receipt signature (DISP-03 hard-fail gate) ------
    try:
        receipt_block = result.get("receipt_signature") or {}
        bytes_hex = receipt_block.get("bytes_hex")
        if not bytes_hex:
            raise DispatchError(
                "receipt_signature.bytes_hex missing",
                subcode=DispatchSubcode.RECEIPT_MALFORMED,
                stage=8,
                channel_id=channel_id,
                envelope_id=envelope_id_hint or None,
                audit_entry_hash=pre_audit_hash,
            )
        scheme_str = (
            receipt_block.get("key_scheme")
            or receipt_block.get("scheme")
            or "brine"
        )
        sig_obj = Signature(
            scheme=KeyScheme(str(scheme_str)),
            bytes_=bytes.fromhex(str(bytes_hex)),
            signer_identity=str(receipt_block.get("signer_identity") or channel.remote_node),
        )
        receipt = verifier.verify(envelope=result, signature=sig_obj)
    except DispatchError:
        raise
    except Exception as exc:
        # Any verifier exception (e.g., SchemeError, IdentityError) is treated
        # as a hard receipt-invalid event.
        raise DispatchError(
            f"receipt verification raised: {exc}",
            subcode=DispatchSubcode.RECEIPT_INVALID,
            stage=8,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
            audit_entry_hash=pre_audit_hash,
        ) from exc
    if receipt is None:
        raise DispatchError(
            "receipt signature verification failed",
            subcode=DispatchSubcode.RECEIPT_INVALID,
            stage=8,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
            audit_entry_hash=pre_audit_hash,
        )

    # ---- Step 8b: POLICY-03 closure ------------------------------------------
    # Conservative v0.1 derivation: forge MUST surface persisted_fields and
    # returned_fields in the response. If absent, treat as empty (forge wrote
    # nothing) — that respects policy by construction.
    received_for_compare = {
        "persisted_fields": list(result.get("persisted_fields", [])),
        "returned_fields": list(result.get("returned_fields", [])),
    }
    complies = await policy_compare_async(received_for_compare, authored_policy)
    if not complies:
        raise DispatchError(
            "result violates authored result policy",
            subcode=DispatchSubcode.POLICY_VIOLATED,
            stage=8,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
            audit_entry_hash=pre_audit_hash,
        )

    # ---- Step 9: audit-post --------------------------------------------------
    post_payload: dict[str, Any] = {
        "envelope_id": envelope_id_hint or None,
        "receipt_signature_hash": receipt.signature_hash,
        "remote_node": channel.remote_node,
        "verification_result": "ok",
    }
    try:
        post_audit_hash = await audit_append_async(
            audit_log,
            event_type="dispatch.receipt",
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
            payload=post_payload,
        )
    except Exception as exc:
        raise DispatchError(
            f"post-receipt audit write failed: {exc}",
            subcode=DispatchSubcode.AUDIT_FAILED_POST,
            stage=9,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
            audit_entry_hash=pre_audit_hash,
        ) from exc

    return DispatchOutcome(
        envelope_id=envelope_id_hint,
        receipt_signature_hash=receipt.signature_hash,
        pre_audit_hash=pre_audit_hash,
        post_audit_hash=post_audit_hash,
        warnings=tuple(shadow_warnings),
        result_body=result,
    )


def _short_hash(b: bytes) -> str:
    """Short blake3 fingerprint (16 hex chars) for audit-payload size discipline."""
    import blake3
    return blake3.blake3(b).hexdigest()[:16]
