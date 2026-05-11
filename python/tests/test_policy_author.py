"""Tests for policy.author() — POLICY-01 (ignore draft policy) + POLICY-02 (ceiling derivation).

Uses the channel_store fixture from conftest.py to create real channels.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from photophore.channels import Channel, ChannelStore
from photophore.core import ChannelId, ChannelState
from photophore.policy import ResultPolicy, author

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _make_channel(ceiling: str) -> Channel:
    """Build a minimal Channel with the given ceiling (no store needed for author())."""
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


class TestAuthorTier0:
    def test_tier0_produces_strip_all(self) -> None:
        channel = _make_channel("tier-0")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert isinstance(policy, ResultPolicy)
        assert "*" in policy.strip_before_persist

    def test_tier0_persist_to_shared_empty(self) -> None:
        channel = _make_channel("tier-0")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert policy.persist_to_shared == []

    def test_tier0_return_only_empty(self) -> None:
        channel = _make_channel("tier-0")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert policy.return_only == []


class TestAuthorTier1:
    def test_tier1_produces_return_only_shadow_refs(self) -> None:
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert "shadow_refs" in policy.return_only

    def test_tier1_strips_raw_content(self) -> None:
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert "content" in policy.strip_before_persist or "raw_output" in policy.strip_before_persist

    def test_tier1_persist_to_shared_empty(self) -> None:
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert policy.persist_to_shared == []


class TestAuthorTier2:
    def test_tier2_persist_to_shared_is_permissive(self) -> None:
        """Tier-2 v0.1 template: empty persist_to_shared (no field-name restriction).

        Plan 03-03 deviation: previously surfaced ``["public_outputs"]`` as a
        placeholder allow-list. Combined with the Plan 03-03 v0.1 derivation
        rule (persisted_fields = outputs.keys when forge omits the explicit
        field), this caused tier-2 happy-path dispatches against real forges
        (whose output keys aren't "public_outputs") to falsely trip
        POLICY-03. Empty lists here mean "no allow-list rule applies".
        """
        channel = _make_channel("tier-2")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert policy.persist_to_shared == [], (
            "tier-2 v0.1 template should be permissive (no field-name allow-list)"
        )

    def test_tier2_strip_before_persist_empty(self) -> None:
        channel = _make_channel("tier-2")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert policy.strip_before_persist == []


class TestAuthorPolicy01IgnoresDraftPolicy:
    """POLICY-01: author() MUST ignore any result_policy field in the draft."""

    def test_injected_policy_is_ignored(self) -> None:
        channel = _make_channel("tier-2")
        draft = _load_draft("task-draft-with-injected-policy.json")

        # The injected policy is: persist_to_shared=["EVERYTHING"]
        assert draft.get("result_policy", {}).get("persist_to_shared") == ["EVERYTHING"]

        authored = author(channel, draft)

        # The authored policy must NOT be the injected one
        assert authored.persist_to_shared != ["EVERYTHING"], (
            "POLICY-01 violated: author() returned the injected policy instead of the "
            "channel-derived policy"
        )

    def test_authored_differs_from_injected(self) -> None:
        # Tier-2 channel authored policy (Plan 03-03): persist_to_shared=[]
        # Injected policy: persist_to_shared=["EVERYTHING"]
        # The authored policy must NEVER reflect the injected draft.
        channel = _make_channel("tier-2")
        draft = _load_draft("task-draft-with-injected-policy.json")
        authored = author(channel, draft)

        injected_persist = set(draft["result_policy"]["persist_to_shared"])
        authored_persist = set(authored.persist_to_shared)
        assert authored_persist != injected_persist

    def test_no_draft_policy_field_also_succeeds(self) -> None:
        # Drift: author() must work even when the draft has no result_policy field
        channel = _make_channel("tier-0")
        draft = _load_draft("task-draft.json")
        assert "result_policy" not in draft
        policy = author(channel, draft)
        assert "*" in policy.strip_before_persist

    def test_deterministic_same_channel_same_draft(self) -> None:
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        p1 = author(channel, draft)
        p2 = author(channel, draft)
        assert p1 == p2  # ResultPolicy is frozen, equality by field values


class TestAuthorReturnsResultPolicy:
    def test_returns_result_policy_type(self) -> None:
        from thermocline import ResultPolicy as RP
        channel = _make_channel("tier-1")
        draft = _load_draft("task-draft.json")
        policy = author(channel, draft)
        assert isinstance(policy, RP)

    def test_unknown_ceiling_raises_policy_error(self) -> None:
        from photophore.errors import PolicyError
        channel = _make_channel("tier-99")  # invalid ceiling
        draft = _load_draft("task-draft.json")
        with pytest.raises(PolicyError):
            author(channel, draft)
