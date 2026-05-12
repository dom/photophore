# CONF-03 invariant: classifier default fallthrough → LOCAL
"""Hypothesis property tests for the default_tier() invariant (CLASS-06, CONF-03).

Tests:
1. Any content with no explicit tag classifies as LOCAL (may hit classifier rule or default).
2. Innocuous content with no credential/PII shape hits classifier:default exactly.

Run with @settings(max_examples=200, deadline=None) to satisfy CONF-03 forward-coverage.
"""
from __future__ import annotations

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from photophore.classifier import classify
from photophore.core import Tier


@given(content=st.binary(min_size=0, max_size=10_000))
@settings(max_examples=200, deadline=None)
def test_unmatched_content_classifies_as_local(content: bytes) -> None:
    """Any content with no explicit tag classifies as LOCAL via either classifier rule or default.

    CLASS-06 invariant: the default is LOCAL, period. The rule-based classifier also only
    signals LOCAL (never SHARED or PUBLIC from inference alone — CLASS-04).
    """
    assume(b"@photophore:" not in content)
    result = classify(content, path=None, rules=None)
    assert result.tier == Tier.LOCAL  # never SHARED, never PUBLIC


@given(content=st.text(alphabet="abc ", min_size=0, max_size=100).map(str.encode))
@settings(max_examples=200, deadline=None)
def test_innocuous_content_hits_default_branch(content: bytes) -> None:
    """Content with no credential/PII shape and no explicit tag hits classifier:default.

    This sub-property is stricter: by using only 'abc ' characters, we guarantee no
    credential/PII pattern can match, so the default branch (Priority 4) MUST fire.
    The reason must be exactly "classifier:default" — proving default_tier() is called.
    """
    assume(b"@photophore:" not in content)
    result = classify(content, path=None, rules=None)
    assert result.tier == Tier.LOCAL
    assert result.reason == "classifier:default", (
        f"Expected default branch with reason 'classifier:default'; got {result.reason!r}"
    )
