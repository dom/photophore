"""Priority-order tests for classify(): pins the CLASS-01 contract (hardened).

Also serves as the behavioral wire for the AT-A3 conformance fixture:
  - AT-A3 (hardened): an embedded tag may only LOWER the tier, never raise it
    above the base assignment. Tags live in untrusted content bytes.
  - Path rule wins over rule-based classifier.
  - Without a path rule match, rule-based classifier fires.
  - Without any of the above, default_tier() returns LOCAL.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from photophore.classifier import classify, load_rules
from photophore.classifier._types import Classification
from photophore.core import Tier

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def loaded_rules():
    """Load the standard test fixture rules (env-credentials, keys, shared-docs, catch-all)."""
    return load_rules(FIXTURES / "rules-valid.yaml")


# ---------------------------------------------------------------------------
# AT-A3 behavioral wire: embedded tag must NOT win over the path rule


def test_at_a3_embedded_tag_does_not_beat_path_rule(loaded_rules) -> None:
    """AT-A3 (hardened): @photophore:public inside .env content stays LOCAL.

    The tag is parsed from content bytes, which are untrusted: anything that
    can write into the file (email body, downloaded doc, prompt injection)
    could plant it. The path rule is the trusted, issuer-configured signal,
    so the tag may not raise the tier above it. Fail closed.
    """
    result = classify(b"@photophore:public secret data", path="/x/.env", rules=loaded_rules)
    assert result == Classification(tier=Tier.LOCAL, reason="path_rule:env-credentials"), (
        f"AT-A3: embedded tag must NOT promote above the path rule; got {result}"
    )


def test_at_a3_without_tag_path_rule_applies(loaded_rules) -> None:
    """AT-A3 complement: without explicit tag, path rule (Priority 2) fires for .env."""
    result = classify(b"sensitive content", path="/x/.env", rules=loaded_rules)
    assert result.reason.startswith("path_rule:"), (
        f"Without explicit tag, path rule must fire; got {result}"
    )
    assert result.tier is Tier.LOCAL


# ---------------------------------------------------------------------------
# Priority transitions: all four branches in order


def test_embedded_tag_never_raises_above_path_rule(loaded_rules) -> None:
    """@photophore:shared inside a local-path file stays LOCAL (lower-only)."""
    result = classify(b"@photophore:shared text", path="/x/.env", rules=loaded_rules)
    assert result.tier is Tier.LOCAL
    assert result.reason == "path_rule:env-credentials"


def test_embedded_tag_may_lower_below_path_rule(loaded_rules) -> None:
    """@photophore:local inside shared-docs content lowers SHARED to LOCAL."""
    result = classify(b"@photophore:local text", path="docs/api/guide.md", rules=loaded_rules)
    assert result.tier is Tier.LOCAL
    assert result.reason == "explicit_tag"


def test_priority_2_wins_over_3(loaded_rules) -> None:
    """Path rule (Priority 2) wins over rule-based classifier (Priority 3).

    Content has a PII match (SSN), but .env path rule fires first.
    """
    result = classify(b"my SSN is 123-45-6789", path="/x/.env", rules=loaded_rules)
    assert result.reason.startswith("path_rule:"), (
        f"Path rule must fire before rule-based classifier; got {result}"
    )


def test_priority_3_fires_without_path_rule(loaded_rules) -> None:
    """Rule-based classifier (Priority 3) fires when there's no matching path rule.

    Content has a credential match; path is in notes.txt which only matches catch-all -> local.
    So: no explicit tag, catch-all path rule matches, but wait — path rule DOES match the
    catch-all, so the reason should be path_rule:default (Priority 2 via catch-all).
    To test Priority 3 we need rules=None.
    """
    # With rules=None, Priority 2 is skipped, so classifier rule fires
    result = classify(b"DATABASE_URL=postgres://x:y@h/db", path="/x/notes.txt", rules=None)
    assert result.tier is Tier.LOCAL
    assert result.reason.startswith("classifier:"), (
        f"Rule-based classifier must fire when no rules loaded; got {result}"
    )
    assert result.reason != "classifier:default", (
        f"Should hit a specific rule, not default; got {result}"
    )


def test_priority_4_default_fires(loaded_rules) -> None:
    """Default (Priority 4): no explicit tag, no specific path rule match (catch-all -> local),
    no classifier match -> returns classifier:default.
    """
    # With rules=None (no path rules) and no credential content -> default
    result = classify(b"hello world", path="/x/notes.txt", rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="classifier:default")


def test_all_priorities_verified(loaded_rules) -> None:
    """Compact verification of the hardened priority ladder in sequence."""
    # Embedded tag cannot promote: base path rule wins over @photophore:public
    r1 = classify(b"@photophore:public data", path="/x/.env", rules=loaded_rules)
    assert r1.reason == "path_rule:env-credentials"
    assert r1.tier is Tier.LOCAL

    # P2: path rule (no explicit tag, .env matches env-credentials)
    r2 = classify(b"plain content", path="/x/.env", rules=loaded_rules)
    assert r2.reason == "path_rule:env-credentials"

    # P3: rule-based classifier (no explicit tag, no rules)
    r3 = classify(b"AKIAIOSFODNN7EXAMPLE", path="/x/notes.txt", rules=None)
    assert r3.reason == "classifier:credential_aws_key"

    # P4: default (no explicit tag, no rules, no classifier match)
    r4 = classify(b"harmless text", path="/x/notes.txt", rules=None)
    assert r4.reason == "classifier:default"
