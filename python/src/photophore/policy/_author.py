"""Result policy authoring per POLICY-01 + POLICY-02.

POLICY-01: author() ignores any result_policy field in the input draft. The issuer
node authors the policy; the draft cannot promote itself.

POLICY-02: policy is derived from channel ceiling + envelope output_contract. v0.1
ships task-envelope authoring only; manifest authoring (job envelopes) is v0.2.

POLICY-03: compare_result_against_policy() helper returns False when received result
violates authored policy. The dispatch coordinator wires the helper into its
step-9 receipt-comparison (DISP-03 verify-before-append).
"""
from __future__ import annotations

from typing import Any, Mapping

from thermocline import ResultPolicy

from ..channels._types import Channel
from ..errors import PolicyError

# Ceiling -> ResultPolicy template (POLICY-02).
# Ceilings arrive from Channel.ceiling as "tier-0" | "tier-1" | "tier-2".
# These templates represent the v0.1 policy derivation logic; later versions
# may extend with output_contract-type sensitivity.
_CEILING_TO_POLICY_TEMPLATE: dict[str, dict[str, list[str]]] = {
    "tier-0": {
        # No content crosses. Strip everything before persistence.
        "persist_to_shared": [],
        "return_only": [],
        "strip_before_persist": ["*"],
    },
    "tier-1": {
        # Shadows only cross. Only the permitted shadow-reference field name
        # may persist or return; every other field name fails closed. The
        # strip list is retained as redundant defense in depth (the old
        # name-blacklist alone let a forge persist any field it simply named
        # differently, e.g. "secret_dump").
        "persist_to_shared": ["shadow_refs"],
        "return_only": ["shadow_refs"],
        "strip_before_persist": ["content", "raw_output"],
    },
    "tier-2": {
        # Public content can cross. v0.1 template: no field-name restrictions;
        # any forge-declared output is allowed to be persisted/returned. The
        # privacy guarantee at tier-2 is "you knew it was public when you
        # authored the channel; persisting any output named by the forge is
        # within scope". A future v0.2 may add field-name allow-lists when
        # output_contract types stabilize.
        #
        # Permissiveness is opted into EXPLICITLY with the "*" wildcard.
        # Empty allow-lists mean "nothing may cross" (fail closed), so tier-2
        # cannot rely on an empty list to mean "no restriction". An earlier
        # draft surfaced a placeholder ``["public_outputs"]`` allow-list,
        # which combined with the v0.1 derivation rule (persisted_fields =
        # outputs.keys when forge omits the explicit field) caused tier-2
        # happy-path dispatches against real forges (pi-forge
        # outputs={"pi", "digits_computed", "algorithm"}; describe-forge
        # outputs={"descriptions", "note"}) to falsely trip POLICY-03.
        "persist_to_shared": ["*"],
        "return_only": ["*"],
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
            author() does not enforce state — that is the dispatch coordinator's
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

    POLICY-03: full integration runs in the dispatch coordinator step 9
    (verify-receipt then compare-result). This module supplies the helper.

    The ``received_result`` dict is expected to carry two keys produced by the forge:
      ``persisted_fields``: list[str] — fields the forge wrote to shared storage
      ``returned_fields``: list[str] — fields the forge included in its response body

    v0.1 semantics:
      - If ``strip_before_persist`` contains ``"*"``, the forge MUST NOT persist any field
        (tier-0 channel: nothing crosses). Any non-empty ``persisted_fields`` is a violation.
      - If ``strip_before_persist`` lists specific field names, none of those fields may
        appear in ``persisted_fields``.
      - ``returned_fields`` must ALWAYS be a subset of return_only ∪ persist_to_shared
        (the "allowed return set"). An EMPTY allowed return set means the forge may
        return NOTHING (fail closed); tier-0 authors return_only=[] with exactly that
        meaning. A "*" entry in the allowed return set means returns are unrestricted
        (tier-2 opts in explicitly).
      - ``persisted_fields`` must ALWAYS be a subset of ``persist_to_shared`` (an
        allow-list of field names, NOT a blacklist). An EMPTY allow-list means the
        forge may persist NOTHING (fail closed); a "*" entry means persistence is
        unrestricted (tier-2 opts in explicitly).

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

    # Rule: returned_fields must ALWAYS be a subset of the allowed return set.
    # An empty allowed set means "return nothing" (tier-0 fail-closed, MED 5);
    # a "*" entry means unrestricted (tier-2 opts in explicitly).
    allowed_return = (
        set(authored_policy.return_only) | set(authored_policy.persist_to_shared)
    )
    if "*" not in allowed_return and returned_fields - allowed_return:
        return False  # returned a field outside the allowed set (or set is empty)

    # Rule: persisted_fields must ALWAYS be a subset of the persist allow-list.
    # An empty allow-list means "persist nothing" (fail closed, MED 6); a "*"
    # entry means unrestricted (tier-2 opts in explicitly). This is an
    # allow-list, not a name-blacklist: unknown field names are rejected.
    allowed_persist = set(authored_policy.persist_to_shared)
    if "*" not in allowed_persist and persisted_fields - allowed_persist:
        return False  # persisted a field outside the allow-list (or list is empty)

    return True


__all__ = ["author", "compare_result_against_policy"]
