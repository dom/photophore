"""Priority-order tests for classify() — pins the CLASS-01 contract.

Also serves as the behavioral wire for the AT-A3 conformance fixture:
  - AT-A3: explicit tag wins over path rule (intended behavior per CLASS-01).
  - Without explicit tag, path rule wins over rule-based classifier.
  - Without explicit tag or path rule match, rule-based classifier fires.
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
# AT-A3 behavioral wire: explicit tag wins over path rule (Priority 1 > Priority 2)


def test_at_a3_explicit_tag_wins_over_path_rule(loaded_rules) -> None:
    """AT-A3: @photophore:public tag in tier-0 content wins over .env path rule.

    This is INTENDED behavior per CLASS-01: explicit tags are issuer-authored signals,
    the highest-priority classification. An attacker who can inject a forged
    @photophore:public tag has issuer-node access — a different threat (AT-A1).
    """
    result = classify(b"@photophore:public secret data", path="/x/.env", rules=loaded_rules)
    assert result == Classification(tier=Tier.PUBLIC, reason="explicit_tag"), (
        f"AT-A3: explicit tag must win over path rule; got {result}"
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


def test_priority_1_wins(loaded_rules) -> None:
    """Explicit tag beats path rule, classifier, AND default."""
    result = classify(b"@photophore:shared text", path="/x/.env", rules=loaded_rules)
    assert result.tier is Tier.SHARED
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


def test_all_four_priorities_verified(loaded_rules) -> None:
    """Compact verification of all four priority levels in sequence."""
    # P1: explicit tag
    r1 = classify(b"@photophore:public data", path="/x/.env", rules=loaded_rules)
    assert r1.reason == "explicit_tag"

    # P2: path rule (no explicit tag, .env matches env-credentials)
    r2 = classify(b"plain content", path="/x/.env", rules=loaded_rules)
    assert r2.reason == "path_rule:env-credentials"

    # P3: rule-based classifier (no explicit tag, no rules)
    r3 = classify(b"AKIAIOSFODNN7EXAMPLE", path="/x/notes.txt", rules=None)
    assert r3.reason == "classifier:credential_aws_key"

    # P4: default (no explicit tag, no rules, no classifier match)
    r4 = classify(b"harmless text", path="/x/notes.txt", rules=None)
    assert r4.reason == "classifier:default"
