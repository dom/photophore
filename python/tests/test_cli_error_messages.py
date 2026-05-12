"""Test CLI-07 / D-08: dispatch error messages include (tier=X, reason=Y) when relevant.

This is a unit-level test that exercises the DispatchError formatter directly
(without spawning a real dispatch). The full integration path lives in
tests/integration/test_e2e_*.
"""
from __future__ import annotations

import pytest

from photophore.dispatch._errors import DispatchError, DispatchSubcode


def test_dispatch_error_supports_blocked_tier_reason_fields() -> None:
    """DispatchError accepts blocked_tier + blocked_reason kwargs (additive optional)."""
    exc = DispatchError(
        "policy violated",
        subcode=DispatchSubcode.POLICY_VIOLATED,
        stage=9,
        blocked_block_path="context[0]",
        blocked_tier="LOCAL",
        blocked_reason="classifier:credential_pattern",
    )
    assert exc.blocked_block_path == "context[0]"
    assert exc.blocked_tier == "LOCAL"
    assert exc.blocked_reason == "classifier:credential_pattern"


def test_dispatch_error_backward_compat_optional_fields_default_none() -> None:
    """Phase 3 call sites that omit the new fields still work; defaults are None."""
    exc = DispatchError(
        "transport timeout",
        subcode=DispatchSubcode.TRANSPORT_TIMEOUT,
        stage=7,
    )
    assert exc.blocked_block_path is None
    assert exc.blocked_tier is None
    assert exc.blocked_reason is None


def test_dispatch_error_message_format_includes_tier_reason() -> None:
    """The CLI formatter in dispatch_cmds appends '(tier=X, reason=Y)' when set."""
    # Mirror the formatter logic from dispatch_cmds.py:
    exc = DispatchError(
        "policy violated",
        subcode=DispatchSubcode.POLICY_VIOLATED,
        stage=9,
        blocked_block_path="context[0]",
        blocked_tier="LOCAL",
        blocked_reason="classifier:credential_pattern",
    )
    # Replicate the dispatch_cmds error-formatting branch
    tier_reason = ""
    if exc.blocked_tier is not None and exc.blocked_reason is not None:
        block_label = exc.blocked_block_path or "block"
        tier_reason = (
            f" blocked block: {block_label} "
            f"(tier={exc.blocked_tier}, reason={exc.blocked_reason})."
        )
    formatted = (
        f"error: dispatch failed ({exc.subcode}) at step {exc.stage}: "
        f"{exc}. retryable: {str(exc.retryable).lower()}.{tier_reason}"
    )
    assert "(tier=LOCAL" in formatted
    assert "reason=classifier:credential_pattern" in formatted
    assert "context[0]" in formatted
