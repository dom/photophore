"""AT-A3: Classifier evasion — crafted content MUST default to LOCAL.

Failure mode: content designed to bypass credential/PII/file-type patterns
MUST be classified LOCAL (CLASS-04 zero-trust default). The classifier
NEVER infers SHARED or PUBLIC from content alone; it only signals LOCAL.
"""
# AT-SURFACE: AT-A3
from __future__ import annotations

import pytest

from photophore.classifier import classify
from photophore.core import Tier


@pytest.mark.at_surface("AT-A3")
def test_classifier_evasion_defaults_to_local() -> None:
    """Crafted content with hidden credential-like substring stays LOCAL."""
    crafted = b"normal looking text with hidden p4ssw0rd123 buried in prose"
    result = classify(crafted, path=None, rules=None)
    assert result.tier == Tier.LOCAL, (
        f"AT-A3: crafted content classified as {result.tier!r} with reason "
        f"{result.reason!r}; classifier MUST default to LOCAL (CLASS-04 zero-trust)"
    )


@pytest.mark.at_surface("AT-A3")
def test_classifier_evasion_never_promotes_to_public() -> None:
    """Innocuous-looking text NEVER classifies as PUBLIC; classifier never up-tiers."""
    crafted = b"completely innocuous-looking text attacker-controlled"
    result = classify(crafted, path=None, rules=None)
    assert result.tier != Tier.PUBLIC, (
        "AT-A3: classifier MUST NEVER infer-promote to PUBLIC"
    )
    assert result.tier != Tier.SHARED, (
        "AT-A3: classifier MUST NEVER infer-promote to SHARED"
    )
