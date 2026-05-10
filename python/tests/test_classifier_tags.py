"""Tests for explicit-tag parser, default_tier, Classification, and Reason types (Task 1)."""
from __future__ import annotations

import pytest

from photophore.classifier import (
    Classification,
    Reason,
    default_tier,
    parse_explicit_tag,
)
from photophore.core import Tier


# ---------------------------------------------------------------------------
# parse_explicit_tag tests


@pytest.mark.parametrize(
    "content, expected_tier",
    [
        (b"@photophore:local some text", Tier.LOCAL),
        (b"@photophore:shared some text", Tier.SHARED),
        (b"@photophore:public hello", Tier.PUBLIC),
    ],
)
def test_parse_explicit_tag_basic(content: bytes, expected_tier: Tier) -> None:
    assert parse_explicit_tag(content) is expected_tier


@pytest.mark.parametrize(
    "content, expected_tier",
    [
        (b"@photophore:LOCAL some text", Tier.LOCAL),
        (b"@photophore:SHARED some text", Tier.SHARED),
        (b"@photophore:PUBLIC hello", Tier.PUBLIC),
        (b"@photophore:Local hello", Tier.LOCAL),
        (b"@photophore:sHaReD hello", Tier.SHARED),
        (b"@PHOTOPHORE:public hello", Tier.PUBLIC),  # CLASS-02: whole tag is case-insensitive
    ],
)
def test_parse_explicit_tag_case_insensitive(content: bytes, expected_tier: Tier | None) -> None:
    # CLASS-02: case-insensitive tag recognition (re.IGNORECASE on full pattern)
    result = parse_explicit_tag(content)
    assert result is expected_tier


def test_parse_explicit_tag_no_tag() -> None:
    assert parse_explicit_tag(b"no tag here") is None


def test_parse_explicit_tag_empty() -> None:
    assert parse_explicit_tag(b"") is None


def test_parse_explicit_tag_invalid_utf8_returns_none() -> None:
    """Invalid UTF-8 must NOT raise — returns None gracefully."""
    result = parse_explicit_tag(b"\x80\x81\x82")
    assert result is None


def test_parse_explicit_tag_invalid_tier_returns_none() -> None:
    """@photophore:invalid_tier must return None — only the three valid tier names match."""
    result = parse_explicit_tag(b"@photophore:invalid_tier")
    assert result is None


def test_parse_explicit_tag_invalid_tier_internal_only() -> None:
    """@photophore:internal is not a valid tier."""
    result = parse_explicit_tag(b"@photophore:internal")
    assert result is None


def test_parse_explicit_tag_first_match_wins() -> None:
    """First occurrence wins when multiple tags are present."""
    result = parse_explicit_tag(b"@photophore:local then @photophore:public")
    assert result is Tier.LOCAL


def test_parse_explicit_tag_mid_content() -> None:
    """Tag recognized anywhere in content."""
    result = parse_explicit_tag(b"some prefix @photophore:shared more text")
    assert result is Tier.SHARED


# ---------------------------------------------------------------------------
# default_tier tests (CLASS-06)


def test_default_tier_returns_local() -> None:
    assert default_tier() is Tier.LOCAL


def test_default_tier_never_returns_shared_or_public() -> None:
    """Calling default_tier() 1000 times must never return SHARED or PUBLIC."""
    for _ in range(1000):
        result = default_tier()
        assert result is not Tier.SHARED, "default_tier() returned SHARED — CLASS-06 violation"
        assert result is not Tier.PUBLIC, "default_tier() returned PUBLIC — CLASS-06 violation"


# ---------------------------------------------------------------------------
# Classification frozen dataclass tests


def test_classification_is_frozen_and_hashable() -> None:
    c = Classification(tier=Tier.LOCAL, reason="classifier:default")
    # frozen — cannot set attributes
    with pytest.raises((AttributeError, TypeError)):
        c.tier = Tier.PUBLIC  # type: ignore[misc]
    # hashable
    s = {c}
    assert c in s


def test_classification_equality() -> None:
    c1 = Classification(tier=Tier.LOCAL, reason="classifier:default")
    c2 = Classification(tier=Tier.LOCAL, reason="classifier:default")
    assert c1 == c2


def test_classification_inequality() -> None:
    c1 = Classification(tier=Tier.LOCAL, reason="classifier:default")
    c2 = Classification(tier=Tier.PUBLIC, reason="explicit_tag")
    assert c1 != c2


# ---------------------------------------------------------------------------
# Reason enum tests (CLASS-05)


def test_reason_classifier_default_value() -> None:
    assert Reason.CLASSIFIER_DEFAULT.value == "classifier:default"


def test_reason_explicit_tag_value() -> None:
    assert Reason.EXPLICIT_TAG.value == "explicit_tag"


def test_reason_path_rule_value() -> None:
    assert Reason.PATH_RULE.value == "path_rule"


def test_reason_classifier_rule_value() -> None:
    assert Reason.CLASSIFIER_RULE.value == "classifier"


# ---------------------------------------------------------------------------
# Import surface test


def test_import_surface() -> None:
    """Verify the expected public API is importable from photophore.classifier."""
    from photophore.classifier import (  # noqa: F401
        Classification,
        PathRule,
        PathRules,
        Reason,
        default_tier,
        parse_explicit_tag,
    )
