"""Tests for compare_result_against_policy() — POLICY-03 (negative test fixture).

Verifies that the helper returns False when a received_result violates the authored policy,
and True when the result respects the policy.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

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

    def test_tier2_violation_persisted_outside_allowed(self) -> None:
        """tier-2: persist_to_shared=["public_outputs"]; persisting 'private_data' violates."""
        channel = _make_channel("tier-2")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert "public_outputs" in policy.persist_to_shared

        violating_result = {
            "persisted_fields": ["private_data"],  # not in persist_to_shared
            "returned_fields": [],
        }
        assert compare_result_against_policy(violating_result, policy) is False

    def test_tier2_compliant_allowed_persist(self) -> None:
        """tier-2: persisting 'public_outputs' is compliant."""
        channel = _make_channel("tier-2")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)

        compliant_result = {
            "persisted_fields": ["public_outputs"],
            "returned_fields": [],
        }
        assert compare_result_against_policy(compliant_result, policy) is True


class TestPolicy03InjectedPolicyFixture:
    """POLICY-03 fixture test: load injected-policy fixture, author real policy,
    build a violating result, assert False."""

    def test_injected_policy_vs_authored_policy(self) -> None:
        """Full POLICY-03 negative fixture flow:
        1. Load draft with injected overly-permissive policy.
        2. Author the real policy from channel ceiling (tier-2).
        3. Verify authored policy != injected policy (POLICY-01).
        4. Build a received_result that would satisfy the INJECTED (overly permissive) policy
           but VIOLATES the AUTHORED (channel-derived) policy.
        5. Assert compare_result_against_policy returns False.
        """
        draft = _load_draft("task-draft-with-injected-policy.json")
        injected_policy = ResultPolicy(**draft["result_policy"])

        # Tier-2 channel
        channel = _make_channel("tier-2")
        authored = author(channel, draft)

        # POLICY-01: authored != injected
        assert authored != injected_policy, "POLICY-01: authored policy must differ from injected"

        # The injected policy permits persist_to_shared=["EVERYTHING"]:
        # a forge that persists "EVERYTHING" would satisfy the injected policy
        # but "EVERYTHING" is not in authored.persist_to_shared (it's ["public_outputs"]).
        violating_result = {
            "persisted_fields": ["EVERYTHING"],
            "returned_fields": [],
        }
        # Satisfies injected: "EVERYTHING" in injected.persist_to_shared
        assert "EVERYTHING" in injected_policy.persist_to_shared

        # Violates authored: "EVERYTHING" not in authored.persist_to_shared
        assert compare_result_against_policy(violating_result, authored) is False
