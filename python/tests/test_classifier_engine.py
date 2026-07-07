"""Tests for the classify() engine — priority order, all four branches (Task 3)."""
from __future__ import annotations

from pathlib import Path

import pytest

from photophore.classifier import classify, load_rules
from photophore.classifier._types import Classification
from photophore.core import Tier

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def loaded_rules():
    return load_rules(FIXTURES / "rules-valid.yaml")


# ---------------------------------------------------------------------------
# Priority 4 (default): unmatched content -> classifier:default


def test_classify_no_args_returns_local_default() -> None:
    """Unmatched content with no args returns (Tier.LOCAL, 'classifier:default')."""
    result = classify(b"hello world", path=None, rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="classifier:default")


def test_classify_empty_bytes_returns_local_default() -> None:
    result = classify(b"", path=None, rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="classifier:default")


# ---------------------------------------------------------------------------
# Explicit Tag (CLASS-02, hardened): embedded tags may only LOWER the tier.
# Tags ride in untrusted content bytes, so they can never raise the base
# assignment (path rule / classifier / default), only restrict below it.


def test_classify_explicit_tag_public_cannot_promote() -> None:
    """@photophore:public cannot raise above the LOCAL base assignment (AT-A3)."""
    result = classify(b"@photophore:public hello", path=None, rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="classifier:default")


def test_classify_explicit_tag_local() -> None:
    """@photophore:local confirms the LOCAL base tier (lower-or-equal is honored)."""
    result = classify(b"@photophore:local content", path=None, rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="explicit_tag")


def test_classify_explicit_tag_shared_cannot_promote() -> None:
    """@photophore:shared cannot raise above the LOCAL base assignment (AT-A3)."""
    result = classify(b"@photophore:shared content", path=None, rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="classifier:default")


def test_classify_explicit_tag_lowers_shared_path(loaded_rules) -> None:
    """@photophore:local inside shared-docs content lowers SHARED to LOCAL."""
    result = classify(
        b"@photophore:local content", path="docs/api/guide.md", rules=loaded_rules
    )
    assert result == Classification(tier=Tier.LOCAL, reason="explicit_tag")


# ---------------------------------------------------------------------------
# Priority 2: Path Rule (CLASS-03)


def test_classify_path_rule_env(loaded_rules) -> None:
    """Path rule matches .env file -> (LOCAL, 'path_rule:env-credentials')."""
    result = classify(b"hello", path="/x/.env", rules=loaded_rules)
    assert result == Classification(tier=Tier.LOCAL, reason="path_rule:env-credentials")


def test_classify_path_rule_wins_over_priority3(loaded_rules) -> None:
    """Path rule (Priority 2) wins over rule-based classifier (Priority 3)."""
    # Content has a PII match, but .env path rule triggers first
    result = classify(b"123-45-6789", path="/x/.env", rules=loaded_rules)
    assert result.reason.startswith("path_rule:")


def test_classify_path_rule_shared_docs(loaded_rules) -> None:
    result = classify(b"markdown content", path="docs/api/guide.md", rules=loaded_rules)
    assert result == Classification(tier=Tier.SHARED, reason="path_rule:shared-docs")


# ---------------------------------------------------------------------------
# Priority 3: Rule-based Classifier (CLASS-04)


def test_classify_credential_pem() -> None:
    """PEM header in content triggers classifier:credential_pem — Priority 3."""
    content = b"-----BEGIN PRIVATE KEY-----\nabc...\n-----END PRIVATE KEY-----"
    result = classify(content, path="/x/notes.txt", rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="classifier:credential_pem")


def test_classify_aws_key() -> None:
    result = classify(b"AKIAIOSFODNN7EXAMPLE", path=None, rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="classifier:credential_aws_key")


def test_classify_ssn() -> None:
    result = classify(b"my SSN is 123-45-6789", path=None, rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="classifier:pii_ssn")


def test_classify_email() -> None:
    result = classify(b"contact alice@example.com please", path=None, rules=None)
    assert result == Classification(tier=Tier.LOCAL, reason="classifier:pii_email")


# ---------------------------------------------------------------------------
# Classifier never returns PUBLIC from inference


def test_classify_classifier_never_public() -> None:
    """Rule-based classifier NEVER produces Tier.PUBLIC output (CLASS-04)."""
    cases = [
        (b"AKIAIOSFODNN7EXAMPLE", None),
        (b"123-45-6789", None),
        (b"alice@example.com", None),
        (b"-----BEGIN PRIVATE KEY-----\nMIIE...", None),
    ]
    for content, path in cases:
        result = classify(content, path=path, rules=None)
        assert result.tier is not Tier.PUBLIC, (
            f"classifier returned PUBLIC for {content[:30]!r}: {result}"
        )


# ---------------------------------------------------------------------------
# No Tier.LOCAL literal in _engine.py default branch (CLASS-06 gate)


def test_engine_has_no_tier_local_literals() -> None:
    """Ensure _engine.py doesn't use Tier.LOCAL literal in the default branch (CLASS-06)."""
    engine_src = (
        Path(__file__).resolve().parent.parent / "src" / "photophore" / "classifier" / "_engine.py"
    ).read_text()
    assert "Tier.LOCAL" not in engine_src, (
        "CLASS-06: _engine.py must call default_tier() — not use Tier.LOCAL literal"
    )
