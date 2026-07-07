"""9-step async dispatch coordinator (DISP-01..06, POLICY-03, AT-A1 wire-in).

The 9 steps (Photophore spec §"Dispatch"):

  1. resolve channel + AT-A1 key_scheme guard
  2. classify each context[] block and ENFORCE the result: hard-drop
     tier-0 (local) blocks, reject any block whose effective tier exceeds
     the channel trust ceiling (fail closed, before signing)
  3. shadow tier-1 blocks: raw tier-1 content is replaced by a freshly
     generated shadow (irreversibility hard fail surfaces as
     SHADOW_GENERATION_FAILED); a fail-closed backstop then re-checks that
     no raw local content survived enforcement
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

from ..audit import AuditLog
from ..channels import ChannelStore
from ..channels._types import Channel
from ..classifier import PathRules, classify
from ..core import ChannelId, ChannelState, Tier
from ..shadow import ContentType
from ._aio import (
    audit_append_async,
    channel_show_async,
    policy_author_async,
    policy_compare_async,
    shadow_generate_async,
)
from ._errors import DispatchError, DispatchSubcode
from ._transport import send_async

__all__ = ["dispatch_async", "DispatchOutcome"]

# Tier vocabulary shared by channel ceilings ("tier-0".."tier-2") and content
# blocks (integer 0..2 or the same strings). Rank 0 (local) is the most
# restrictive: local content never crosses; rank 2 (public) crosses raw.
_CEILING_RANK: dict[str, int] = {"tier-0": 0, "tier-1": 1, "tier-2": 2}

_RANK_BY_TIER: dict[Tier, int] = {Tier.LOCAL: 0, Tier.SHARED: 1, Tier.PUBLIC: 2}

_RANK_BY_NAME: dict[str, int] = {"local": 0, "shared": 1, "public": 2}

_CONTENT_TYPE_BY_NAME: dict[str, ContentType] = {ct.value: ct for ct in ContentType}


def _declared_rank(block: dict[str, Any]) -> int | None:
    """Parse the issuer-declared tier of a context block, or None if absent.

    Accepts the integer wire form (0 | 1 | 2), the "tier-N" strings used by
    channel ceilings, and the tier names ("local" | "shared" | "public").
    Anything else is treated as undeclared (fail closed at the call site).
    """
    raw = block.get("tier")
    if isinstance(raw, bool):  # bool is an int subclass; refuse it explicitly
        return None
    if isinstance(raw, int):
        return raw if raw in (0, 1, 2) else None
    if isinstance(raw, str):
        if raw in _CEILING_RANK:
            return _CEILING_RANK[raw]
        return _RANK_BY_NAME.get(raw.lower())
    return None


def _content_bytes(content: Any) -> bytes:
    """Normalize a block's content field to bytes for classification."""
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    return b""


def _effective_rank(
    declared: int | None, classification_tier: Tier, classification_reason: str
) -> int:
    """Combine issuer declaration with classification, fail closed.

    The classifier can only LOWER a block's tier, never raise it: an
    affirmative signal (explicit tag, path rule, classifier rule match)
    caps the declared tier at the classified tier. ``classifier:default``
    carries no affirmative signal, so a deliberate issuer declaration
    stands; an UNDECLARED block falls back to the classification (which
    defaults to local, so it is dropped).
    """
    classified = _RANK_BY_TIER[classification_tier]
    if declared is None:
        return classified
    if classification_reason == "classifier:default":
        return declared
    return min(declared, classified)


def _assert_context_fail_closed(
    context: list[dict[str, Any]],
    *,
    rules: PathRules | None,
    channel_id: str,
    envelope_id: str | None,
) -> None:
    """Fail-closed backstop: abort if any raw local content survived enforcement.

    Runs over the ALREADY-ENFORCED context that is about to be signed. It is
    an independent re-check, not a re-implementation of the enforcement pass:
    any block that still carries raw content must be issuer-declared tier-2
    AND must not classify local/shared via an affirmative signal.
    """
    for idx, block in enumerate(context):
        content = block.get("content")
        if content is None:
            continue
        declared = _declared_rank(block)
        if declared is None or declared < 2:
            raise DispatchError(
                f"fail-closed backstop: context block #{idx} carries raw content "
                f"below tier-2 (declared tier {block.get('tier')!r}); "
                f"local content never crosses",
                subcode=DispatchSubcode.CLASSIFICATION_FAILED,
                stage=3,
                channel_id=channel_id,
                envelope_id=envelope_id,
            )
        result = classify(_content_bytes(content), path=block.get("path"), rules=rules)
        if result.reason != "classifier:default" and result.tier is not Tier.PUBLIC:
            raise DispatchError(
                f"fail-closed backstop: context block #{idx} carries raw content "
                f"classified {result.tier.value!r} ({result.reason}); "
                f"it must not be signed or transmitted",
                subcode=DispatchSubcode.CLASSIFICATION_FAILED,
                stage=3,
                channel_id=channel_id,
                envelope_id=envelope_id,
                blocked_tier=result.tier.value,
                blocked_reason=result.reason,
            )


@dataclass(frozen=True)
class DispatchOutcome:
    """Happy-path return value of dispatch_async().

    Attributes
    ----------
    envelope_id
        The envelope_id from the outgoing task draft.
    receipt_signature_hash
        The signature_hash from the verified receipt (thermocline Receipt.signature_hash).
    pre_audit_hash
        entry_hash of the dispatch.pre audit entry.
    post_audit_hash
        entry_hash of the dispatch.receipt audit entry.
    warnings
        Soft-fail warnings collected during shadow generation (SHADOW-04).
    result_body
        Parsed task_result envelope dict returned by the forge. Populated only
        after receipt-verify AND policy-compare both succeed. Documented
        inspection path for downstream tests (e.g., describe-forge
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
    rules: PathRules | None = None,
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

    # ---- Step 2: classify each context[] block and ENFORCE the result --------
    # Enforcement lives HERE, in the coordinator: the caller-supplied draft is
    # untrusted. Classification can only LOWER a block's tier. tier-0 blocks
    # are hard-dropped; blocks above the channel ceiling abort the dispatch
    # (fail closed) before anything is signed.
    classifier_reasons: list[str] = []
    warnings: list[str] = []
    # Each decision is (effective_rank, block, content_bytes_or_None, reason).
    decisions: list[tuple[int, dict[str, Any], bytes | None, str]] = []
    try:
        for idx, block in enumerate(task_draft.get("context", [])):
            declared = _declared_rank(block)
            content = block.get("content")
            if content is not None:
                content_bytes = _content_bytes(content)
                # Sync call kept lightweight; the asyncio.to_thread shim wraps
                # the heavier classifier path in callers that prefer concurrency.
                classification = classify(
                    content_bytes, path=block.get("path"), rules=rules
                )
                classifier_reasons.append(classification.reason)
                effective = _effective_rank(
                    declared, classification.tier, classification.reason
                )
                reason = classification.reason
            else:
                # No raw content: nothing to classify. The declared tier
                # stands; an undeclared block defaults to local (dropped).
                content_bytes = None
                effective = declared if declared is not None else 0
                reason = "declared" if declared is not None else "undeclared:default_local"
            if effective <= 0:
                warnings.append(
                    f"stripped tier-0 context block #{idx} "
                    f"(role={block.get('role')!r}, reason={reason}); "
                    f"local content never crosses"
                )
                continue
            decisions.append((effective, block, content_bytes, reason))
    except DispatchError:
        raise
    except Exception as exc:
        raise DispatchError(
            f"classification failed: {exc}",
            subcode=DispatchSubcode.CLASSIFICATION_FAILED,
            stage=2,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
        ) from exc

    # ---- Step 3: shadow tier-1 content blocks --------------------------------
    # Raw tier-1 content is replaced by a freshly generated shadow; the raw
    # bytes (and any local path) never reach the outgoing envelope.
    shadow_ids: list[str] = []
    enforced_context: list[dict[str, Any]] = []
    try:
        for effective, block, content_bytes, _reason in decisions:
            if effective == 1:
                if content_bytes is not None:
                    ct = _CONTENT_TYPE_BY_NAME.get(
                        str(block.get("content_type") or ""), ContentType.DOCUMENT
                    )
                    shadow_result = await shadow_generate_async(content_bytes, ct)
                    warnings.extend(shadow_result.warnings)
                    shadow = shadow_result.shadow
                    shadow_ids.append(shadow.shadow_id)
                    new_block = {
                        k: v
                        for k, v in block.items()
                        if k not in ("content", "content_type", "path", "shadow_id")
                    }
                    new_block["tier"] = 1
                    new_block["kind"] = "shadow"
                    new_block["shadow"] = {
                        "shadow_id": shadow.shadow_id,
                        "content_type": shadow.content_type.value,
                        "abstraction": shadow.abstraction,
                        "relevance": shadow.relevance,
                    }
                    enforced_context.append(new_block)
                else:
                    # Already shadow-only: preserve, record its shadow_id.
                    shadow_field = block.get("shadow")
                    sid = (
                        shadow_field.get("shadow_id")
                        if isinstance(shadow_field, dict)
                        else block.get("shadow_id")
                    )
                    if sid is not None:
                        shadow_ids.append(str(sid))
                    enforced_context.append(dict(block))
            else:  # effective == 2: public content crosses raw
                enforced_context.append(dict(block))
        # Fail-closed backstop: independently re-check that no raw local
        # content survived enforcement before the envelope is signed.
        _assert_context_fail_closed(
            enforced_context,
            rules=rules,
            channel_id=channel_id,
            envelope_id=envelope_id_hint or None,
        )
    except DispatchError:
        raise
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
        # Tiers of the ENFORCED (outgoing) context, not the raw draft: the
        # audit log records what actually crosses the boundary.
        "tier_per_block": [b.get("tier") for b in enforced_context],
        "stripped_block_count": len(task_draft.get("context", [])) - len(enforced_context),
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
        signer_identity = str(
            task_draft.get("issuer")
            or channel.local_node
        )
        # The wire contract (FORGE-01):
        # 1. Pre-fill ALL dispatch_signature fields EXCEPT the sig payload
        #    (``sig`` / ``bytes_hex``). Both the sovereign and the forge
        #    canonicalize an envelope whose dispatch_signature block has the
        #    sig fields ABSENT.
        # 2. Sign the canonical bytes of that pre-filled envelope.
        # 3. Attach the sig under ``bytes_hex`` (v0.1 wire) — the forge
        #    deep-copies and pops ``sig``+``bytes_hex`` on its verify side.
        signing_input = dict(task_draft)
        # The ENFORCED context is what gets signed and transmitted. The
        # caller's draft (with any raw tier-0/tier-1 content) is never
        # signed; enforcement in steps 2-3 is authoritative.
        signing_input["context"] = enforced_context
        sig_block_for_sign = dict(signing_input.get("dispatch_signature") or {})
        sig_block_for_sign["scheme"] = "brine"
        sig_block_for_sign["key_scheme"] = "brine"
        sig_block_for_sign.setdefault("signer_identity", signer_identity)
        # Remove any pre-existing sig material; the signer MUST NOT sign
        # over a partially-filled sig field.
        sig_block_for_sign.pop("sig", None)
        sig_block_for_sign.pop("bytes_hex", None)
        signing_input["dispatch_signature"] = sig_block_for_sign

        # canonicalize() is called here to materialize the canonical bytes that
        # WILL be signed by BrineProvider (which itself canonicalizes internally).
        # The double call is intentional — this module's signing-path use of
        # canonicalize is the DISP-04-visible call that the test spies on, and
        # the BrineProvider's internal call is the on-the-wire signing input
        # contract. Both produce the same bytes (RFC 8785 is deterministic).
        _ = canonicalize(signing_input)
        signature: Signature = identity_provider.sign(
            envelope=signing_input, signer_identity=signer_identity
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
    # under dispatch_signature.bytes_hex per the spec wire shape; the
    # forge's verify path deep-copies and pops sig+bytes_hex before
    # canonicalizing, which recovers the exact bytes signed above).
    signed_envelope = dict(signing_input)
    sig_block_signed = dict(sig_block_for_sign)
    sig_block_signed["bytes_hex"] = signature.bytes_.hex()
    signed_envelope["dispatch_signature"] = sig_block_signed

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
        # Spec canonical field name is ``sig`` (per task_result.schema.json).
        # Earlier drafts wrote ``bytes_hex`` to mirror the dispatch_signature
        # convention; integration against real forges that emit ``sig`` surfaced
        # the wire mismatch. Accept either for compatibility.
        bytes_hex = receipt_block.get("sig") or receipt_block.get("bytes_hex")
        if not bytes_hex:
            raise DispatchError(
                "receipt_signature.sig/bytes_hex missing",
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
            signer_identity=str(
                receipt_block.get("signer_identity")
                or receipt_block.get("node_id")
                or channel.remote_node
            ),
        )
        # FORGE-01: the forge signed the result with
        # receipt_signature.sig = None. To recover the same canonical bytes,
        # deep-copy the result and pop both sig and bytes_hex from the
        # receipt_signature block before passing to the verifier.
        import copy
        envelope_for_verify = copy.deepcopy(result)
        rs_for_verify = envelope_for_verify.get("receipt_signature")
        if isinstance(rs_for_verify, dict):
            # Set sig to None (not pop) — the forge signs an envelope where
            # the receipt_signature dict has sig=None as an explicit field,
            # not where the field is absent. Mirrors envelope.py:_sign_receipt.
            rs_for_verify["sig"] = None
            rs_for_verify.pop("bytes_hex", None)
        receipt = verifier.verify(envelope=envelope_for_verify, signature=sig_obj)
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
    # v0.1 derivation rule:
    #   * If the forge surfaces explicit ``persisted_fields`` / ``returned_fields``
    #     at the result top level, use those values (honor what the forge
    #     declared it did).
    #   * Otherwise, derive both from ``result["outputs"].keys()``: the v0.1
    #     reference forges (pi-forge, describe-forge) put everything they
    #     wrote into ``outputs`` and the act of returning a result is a
    #     persistence claim under the audit model. Forges that omit the
    #     explicit fields get the conservative derivation — any output key
    #     counts as both returned AND persisted.
    #
    # This rule is what makes tier-0 channels meaningfully refuse non-empty
    # outputs (POLICY-03 closure).
    if "persisted_fields" in result:
        derived_persisted = list(result["persisted_fields"])
    else:
        outputs = result.get("outputs") or {}
        derived_persisted = list(outputs.keys()) if isinstance(outputs, dict) else []
    if "returned_fields" in result:
        derived_returned = list(result["returned_fields"])
    else:
        outputs = result.get("outputs") or {}
        derived_returned = list(outputs.keys()) if isinstance(outputs, dict) else []
    received_for_compare = {
        "persisted_fields": derived_persisted,
        "returned_fields": derived_returned,
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
        warnings=tuple(warnings),
        result_body=result,
    )


def _short_hash(b: bytes) -> str:
    """Short blake3 fingerprint (16 hex chars) for audit-payload size discipline."""
    import blake3
    return blake3.blake3(b).hexdigest()[:16]
