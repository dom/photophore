"""Result policy authoring per POLICY-01 + POLICY-02.

POLICY-01: author() ignores any result_policy field in the input draft. The issuer
node authors the policy; the draft cannot promote itself.

POLICY-02: policy is derived from channel ceiling + envelope output_contract. v0.1
ships task-envelope authoring only; manifest authoring (job envelopes) is v0.2.

POLICY-03: compare_result_against_policy() helper returns False when received result
violates authored policy. Phase 2 ships the helper + fixture; Phase 3 wires it into
the dispatch coordinator's step-9 receipt-comparison (DISP-03 verify-before-append).
"""
from __future__ import annotations

from typing import Any, Mapping

from thermocline import ResultPolicy

from ..channels._types import Channel
from ..errors import PolicyError

# Ceiling -> ResultPolicy template (POLICY-02).
# Ceilings arrive from Channel.ceiling as "tier-0" | "tier-1" | "tier-2".
# These templates represent the v0.1 policy derivation logic; Phase 3/4 may
# extend with output_contract-type sensitivity.
_CEILING_TO_POLICY_TEMPLATE: dict[str, dict[str, list[str]]] = {
    "tier-0": {
        # No content crosses. Strip everything before persistence.
        "persist_to_shared": [],
        "return_only": [],
        "strip_before_persist": ["*"],
    },
    "tier-1": {
        # Shadows only cross. Return shadow references; strip raw content.
        "persist_to_shared": [],
        "return_only": ["shadow_refs"],
        "strip_before_persist": ["content", "raw_output"],
    },
    "tier-2": {
        # Public content can cross. Persist public outputs.
        "persist_to_shared": ["public_outputs"],
        "return_only": [],
        "strip_before_persist": [],
    },
}


def author(channel: Channel, envelope_draft: Mapping[str, Any]) -> ResultPolicy:
    """Author the result_policy for an outgoing task envelope.

    POLICY-01: any ``result_policy`` field in ``envelope_draft`` is IGNORED.
    The draft cannot promote its own policy — the issuer node authors authoritatively.

    POLICY-02: derived from channel.ceiling + envelope output_contract.
    v0.1 derives from ceiling only; the output_contract is a hook for v0.2 extension.

    Args:
        channel: the resolved Channel (must be in OPEN state for actual dispatch;
            author() does not enforce state — that is the Phase 3 dispatch coordinator's
            responsibility).
        envelope_draft: the task envelope draft dict (PRE-signing, as a Mapping).
            The ``result_policy`` field, if present, is STRUCTURALLY NOT CONSULTED.

    Returns:
        ResultPolicy (Pydantic v2 model from thermocline-py).

    Raises:
        PolicyError: if the channel's ceiling value is not in the expected set.
    """
    # POLICY-01: the draft's result_policy field is structurally ignored —
    # issuer authors authoritatively from channel ceiling. Do not consult
    # the draft's policy field at all.
    template = _CEILING_TO_POLICY_TEMPLATE.get(channel.ceiling)
    if template is None:
        raise PolicyError(
            f"unknown channel ceiling {channel.ceiling!r}; "
            f"expected one of {sorted(_CEILING_TO_POLICY_TEMPLATE)}"
        )
    # POLICY-02: v0.1 derives from ceiling only.
    # Future hook: incorporate envelope_draft.get("output_contract", {}).get("type")
    # for v0.2 binary/composite output types.
    return ResultPolicy(
        persist_to_shared=list(template["persist_to_shared"]),
        return_only=list(template["return_only"]),
        strip_before_persist=list(template["strip_before_persist"]),
    )


def compare_result_against_policy(
    received_result: Mapping[str, Any],
    authored_policy: ResultPolicy,
) -> bool:
    """Return True if received_result respects authored_policy; False if it violates.

    POLICY-03: full integration is Phase 3 (dispatch coordinator step 9 — verify-receipt
    then compare-result). Phase 2 ships the comparison helper; Phase 3 wires it.

    The ``received_result`` dict is expected to carry two keys produced by the forge:
      ``persisted_fields``: list[str] — fields the forge wrote to shared storage
      ``returned_fields``: list[str] — fields the forge included in its response body

    v0.1 semantics:
      - If ``strip_before_persist`` contains ``"*"``, the forge MUST NOT persist any field
        (tier-0 channel: nothing crosses). Any non-empty ``persisted_fields`` is a violation.
      - If ``strip_before_persist`` lists specific field names, none of those fields may
        appear in ``persisted_fields``.
      - If ``return_only`` is non-empty, all fields in ``returned_fields`` must be in the
        union of return_only ∪ persist_to_shared (the "allowed return set").
      - If ``persist_to_shared`` is non-empty, every field in ``persisted_fields`` must be
        in the ``persist_to_shared`` list.

    Returns:
        True  — the result respects the authored policy.
        False — the result violates at least one policy rule.
    """
    persisted_fields: set[str] = set(received_result.get("persisted_fields", []))
    returned_fields: set[str] = set(received_result.get("returned_fields", []))

    # Rule: strip_before_persist = ["*"] means NOTHING may be persisted.
    if "*" in authored_policy.strip_before_persist:
        if persisted_fields:
            return False  # tier-0 violation: forge persisted something

    # Rule: specific stripped fields must not appear in persisted_fields.
    for stripped_field in authored_policy.strip_before_persist:
        if stripped_field == "*":
            continue
        if stripped_field in persisted_fields:
            return False  # named field was persisted despite strip directive

    # Rule: if return_only is set, returned_fields must be a subset of allowed.
    if authored_policy.return_only:
        allowed_return = (
            set(authored_policy.return_only) | set(authored_policy.persist_to_shared)
        )
        if returned_fields - allowed_return:
            return False  # returned a field outside the allowed union

    # Rule: if persist_to_shared is set, persisted_fields must be a subset.
    if authored_policy.persist_to_shared:
        allowed_persist = set(authored_policy.persist_to_shared)
        if persisted_fields - allowed_persist:
            return False  # persisted a field outside the allowed list

    return True


__all__ = ["author", "compare_result_against_policy"]
