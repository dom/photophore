"""Tests for compare_result_against_policy() — POLICY-03 (negative test fixture).

Verifies that the helper returns False when a received_result violates the authored policy,
and True when the result respects the policy.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from photophore.channels._types import Channel
from photophore.core import ChannelId, ChannelState
from photophore.policy import ResultPolicy, author, compare_result_against_policy

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _make_channel(ceiling: str) -> Channel:
    return Channel(
        id=ChannelId("00000000-0000-4000-8000-000000000001"),
        local_node="alice",
        remote_node="bob",
        ceiling=ceiling,
        key_scheme="brine",
        state=ChannelState.OPEN,
        created_at="2026-05-09T00:00:00Z",
        creator_identity="alice",
    )


def _load_draft(filename: str) -> dict[str, Any]:
    return json.loads((_FIXTURES / filename).read_text())


class TestCompareResultViolation:
    """POLICY-03: negative tests — violations return False."""

    def test_tier0_violation_any_persisted_field(self) -> None:
        """tier-0: strip_before_persist=["*"]; any persisted field is a violation."""
        channel = _make_channel("tier-0")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)

        # Forge mistakenly persisted something
        violating_result = {"persisted_fields": ["raw_output"], "returned_fields": []}
        assert compare_result_against_policy(violating_result, policy) is False

    def test_tier0_compliant_no_persisted_fields(self) -> None:
        """tier-0: no persisted_fields is compliant."""
        channel = _make_channel("tier-0")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)

        compliant_result = {"persisted_fields": [], "returned_fields": []}
        assert compare_result_against_policy(compliant_result, policy) is True

    def test_tier0_violation_any_returned_field(self) -> None:
        """tier-0: return_only=[] means return NOTHING; raw content in the
        response body is a violation, not "no restriction" (MED 5)."""
        channel = _make_channel("tier-0")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert policy.return_only == []

        violating_result = {
            "persisted_fields": [],
            "returned_fields": ["content"],  # raw content returned on a tier-0 channel
        }
        assert compare_result_against_policy(violating_result, policy) is False, (
            "tier-0 return_only=[] must reject ANY returned field (fail closed)"
        )

    def test_tier2_returns_remain_permissive_via_wildcard(self) -> None:
        """tier-2 opts in to unrestricted returns EXPLICITLY (wildcard), so the
        empty-list fail-closed semantics cannot silently open other tiers."""
        channel = _make_channel("tier-2")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert "*" in policy.return_only

        result = {"persisted_fields": [], "returned_fields": ["pi", "digits_computed"]}
        assert compare_result_against_policy(result, policy) is True

    def test_tier1_violation_returned_outside_shadow_refs(self) -> None:
        """tier-1: return_only=["shadow_refs"]; returning raw_output is a violation."""
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)

        # Forge returned a field outside the allowed return set
        violating_result = {
            "persisted_fields": [],
            "returned_fields": ["raw_output"],  # not in return_only ∪ persist_to_shared
        }
        assert compare_result_against_policy(violating_result, policy) is False

    def test_tier1_violation_persisted_stripped_field(self) -> None:
        """tier-1: strip_before_persist contains 'content'; persisting 'content' is a violation."""
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert "content" in policy.strip_before_persist

        violating_result = {
            "persisted_fields": ["content"],  # stripped field was persisted
            "returned_fields": ["shadow_refs"],
        }
        assert compare_result_against_policy(violating_result, policy) is False

    def test_tier1_violation_unknown_persisted_field_fails_closed(self) -> None:
        """tier-1: persistence is an ALLOW-LIST of shadow-reference field names.

        The old name-blacklist (content, raw_output) let a forge persist any
        field it simply named differently (e.g. "secret_dump"). Unknown field
        names must fail closed (MED 6)."""
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)

        violating_result = {
            "persisted_fields": ["secret_dump"],  # not a permitted shadow-ref field
            "returned_fields": ["shadow_refs"],
        }
        assert compare_result_against_policy(violating_result, policy) is False, (
            "tier-1 must reject persisted field names outside the shadow-ref allow-list"
        )

    def test_tier1_compliant_persisting_shadow_refs(self) -> None:
        """tier-1: persisting the permitted shadow-reference field is compliant."""
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)

        result = {
            "persisted_fields": ["shadow_refs"],
            "returned_fields": ["shadow_refs"],
        }
        assert compare_result_against_policy(result, policy) is True

    def test_tier1_compliant(self) -> None:
        """tier-1: shadow_refs returned only, nothing persisted = compliant."""
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)

        compliant_result = {
            "persisted_fields": [],
            "returned_fields": ["shadow_refs"],
        }
        assert compare_result_against_policy(compliant_result, policy) is True

    def test_tier2_compliant_any_persisted_fields(self) -> None:
        """The v0.1 tier-2 template is permissive: persist_to_shared=["*"];
        any forge-declared persisted fields are allowed."""
        channel = _make_channel("tier-2")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        # tier-2 v0.1: explicit wildcard = permissive.
        assert policy.persist_to_shared == ["*"]

        # Both arbitrary field names and the legacy "public_outputs" placeholder
        # are compliant; the policy declines to enumerate at this tier.
        for persisted in (["arbitrary_field"], ["pi", "digits_computed"], []):
            result = {"persisted_fields": persisted, "returned_fields": []}
            assert compare_result_against_policy(result, policy) is True, (
                f"tier-2 v0.1 should accept {persisted!r}"
            )


class TestPolicy03InjectedPolicyFixture:
    """POLICY-03 fixture test: load injected-policy fixture, author real policy,
    build a violating result, assert False."""

    def test_injected_policy_vs_authored_policy(self) -> None:
        """Full POLICY-03 negative fixture flow:
        1. Load draft with injected overly-permissive policy.
        2. Author the real policy from channel ceiling (tier-0 — the most
           restrictive tier; tier-2's v0.1 template is permissive).
        3. Verify authored policy != injected policy (POLICY-01).
        4. Build a received_result that would satisfy the INJECTED policy
           but VIOLATES the AUTHORED (channel-derived) policy.
        5. Assert compare_result_against_policy returns False.
        """
        draft = _load_draft("task-draft-with-injected-policy.json")
        injected_policy = ResultPolicy(**draft["result_policy"])

        # Tier-0 channel — strict: strip_before_persist=["*"]; NOTHING may persist.
        channel = _make_channel("tier-0")
        authored = author(channel, draft)

        # POLICY-01: authored != injected
        assert authored != injected_policy, "POLICY-01: authored policy must differ from injected"

        # Injected policy permits persist_to_shared=["EVERYTHING"]. Any non-empty
        # persisted_fields would satisfy it. Tier-0 forbids ALL persistence.
        violating_result = {
            "persisted_fields": ["EVERYTHING"],
            "returned_fields": [],
        }
        # Satisfies injected: "EVERYTHING" in injected.persist_to_shared
        assert "EVERYTHING" in injected_policy.persist_to_shared

        # Violates authored tier-0: strip_before_persist=["*"] forbids any persistence.
        assert "*" in authored.strip_before_persist
        assert compare_result_against_policy(violating_result, authored) is False
