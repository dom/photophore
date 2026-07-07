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


@pytest.mark.at_surface("AT-A3")
def test_embedded_public_tag_cannot_promote_private_path(tmp_path) -> None:
    """@photophore:public INSIDE a ~/Private/** secret stays LOCAL.

    Tags ride in untrusted content bytes: anything that can write into a
    file (email body, downloaded doc, prompt injection) could plant one.
    An embedded tag may only LOWER the tier, never raise it above what the
    path rule / classifier assigns (fail closed).
    """
    from photophore.classifier import load_rules

    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "version: 0.1\n"
        "rules:\n"
        "  - pattern: \"**/Private/**\"\n"
        "    tier: local\n"
        "    reason: private-tree\n"
        "  - pattern: \"**\"\n"
        "    tier: local\n"
        "    reason: default\n"
    )
    rules = load_rules(rules_file)
    result = classify(
        b"@photophore:public my darkest secret",
        path="/home/user/Private/secret.txt",
        rules=rules,
    )
    assert result.tier is Tier.LOCAL, (
        f"AT-A3: embedded @photophore:public must NOT promote content out of a "
        f"local path rule; got {result!r}"
    )


@pytest.mark.at_surface("AT-A3")
def test_embedded_tag_cannot_promote_without_rules() -> None:
    """Without path rules the classifier default is LOCAL; a tag cannot raise it."""
    for tag in (b"@photophore:public data", b"@photophore:shared data"):
        result = classify(tag, path=None, rules=None)
        assert result.tier is Tier.LOCAL, (
            f"AT-A3: {tag!r} self-promoted to {result.tier!r}; embedded tags "
            f"must never raise the tier"
        )


@pytest.mark.at_surface("AT-A3")
def test_embedded_tag_cannot_override_pii_detection() -> None:
    """A public tag next to detected PII/credentials stays LOCAL."""
    crafted = b"@photophore:public AKIAIOSFODNN7EXAMPLE"
    result = classify(crafted, path=None, rules=None)
    assert result.tier is Tier.LOCAL


@pytest.mark.at_surface("AT-A3")
def test_embedded_tag_may_lower_tier(tmp_path) -> None:
    """@photophore:local inside shared-path content LOWERS the tier (allowed)."""
    from photophore.classifier import load_rules

    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "version: 0.1\n"
        "rules:\n"
        "  - pattern: \"docs/**\"\n"
        "    tier: shared\n"
        "    reason: shared-docs\n"
        "  - pattern: \"**\"\n"
        "    tier: local\n"
        "    reason: default\n"
    )
    rules = load_rules(rules_file)
    result = classify(
        b"@photophore:local please keep this home",
        path="docs/notes.md",
        rules=rules,
    )
    assert result.tier is Tier.LOCAL
    assert result.reason == "explicit_tag"
