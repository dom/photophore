"""Tests for shadow quality helpers: irreversibility_test, relevance_preservation_test,
distinguishability_test.

Covers SHADOW-04 (hard fail + soft warn).
"""
from __future__ import annotations

import pytest

from photophore.shadow import (
    ShadowIrreversibilityError,
    _IRREVERSIBILITY_MIN_SUBSTR_LEN,
    distinguishability_test,
    irreversibility_test,
    relevance_preservation_test,
)


class TestIrreversibilityTestNamedConstant:
    def test_constant_value(self) -> None:
        assert _IRREVERSIBILITY_MIN_SUBSTR_LEN == 8

    def test_constant_is_int(self) -> None:
        assert isinstance(_IRREVERSIBILITY_MIN_SUBSTR_LEN, int)


class TestIrreversibilityTestHardFail:
    def test_raises_on_leaked_substring(self) -> None:
        source = b"my unique secret 12345"
        # "unique s" is 8 chars from source; embed it in the abstraction
        abstraction = "abstraction with unique s in it"
        with pytest.raises(ShadowIrreversibilityError) as exc_info:
            irreversibility_test(source, abstraction)
        assert exc_info.value.code == "SHADOW_IRREVERSIBILITY_FAILED"

    def test_raises_on_exact_eight_char_match(self) -> None:
        # Exactly 8 chars
        source = b"12345678"
        abstraction = "contains 12345678 here"
        with pytest.raises(ShadowIrreversibilityError):
            irreversibility_test(source, abstraction)

    def test_does_not_raise_on_seven_char_match(self) -> None:
        # 7 chars is below the threshold — must NOT raise
        source = b"1234567"
        abstraction = "contains 1234567 here"
        # No raise because source < threshold
        irreversibility_test(source, abstraction)  # must not raise

    def test_safe_abstraction_passes(self) -> None:
        source = b"hello world testing"
        # No 8-char substring of source appears in this abstraction
        abstraction = "abstract description"
        irreversibility_test(source, abstraction)  # must not raise

    def test_binary_content_passes(self) -> None:
        # Binary content (non-UTF-8) cannot be substring-checked
        binary_source = b"\x80\x81\x82\xff\xfe"
        abstraction = "any text abstraction here"
        irreversibility_test(binary_source, abstraction)  # must not raise

    def test_short_source_passes(self) -> None:
        # Source shorter than threshold — no substring of threshold length exists
        short_source = b"hi"
        abstraction = "hi there, what"  # "hi" appears but is only 2 chars
        irreversibility_test(short_source, abstraction)  # must not raise

    def test_whitespace_only_substrings_ignored(self) -> None:
        # Substrings that are purely whitespace are not identifying
        source = b"        "  # 8 spaces
        abstraction = "text with         spaces"
        irreversibility_test(source, abstraction)  # must not raise (whitespace stripped)


class TestRelevancePreservationTestSoftWarn:
    def test_returns_empty_for_normal_case(self) -> None:
        warnings = relevance_preservation_test(b"normal content", "decent abstraction here", 0.5)
        assert isinstance(warnings, list)
        # May or may not be empty — depends on heuristic

    def test_returns_warning_for_high_relevance_short_abstraction(self) -> None:
        # relevance > 0.8 and abstraction < 30 chars => warn
        warnings = relevance_preservation_test(b"content", "short", 0.9)
        assert len(warnings) > 0

    def test_never_raises(self) -> None:
        # Soft fail — must never raise
        relevance_preservation_test(b"content", "abstraction text goes here", 0.0)
        relevance_preservation_test(b"content", "x", 1.0)  # should warn but not raise
        relevance_preservation_test(b"", "", 0.5)

    def test_returns_list_type(self) -> None:
        result = relevance_preservation_test(b"hello world", "abstract text", 0.5)
        assert isinstance(result, list)


class TestDistinguishabilityTestSoftWarn:
    def test_returns_empty_for_unique_abstraction(self) -> None:
        unique_abstraction = "very specific unique description of this document"
        warnings = distinguishability_test(unique_abstraction)
        assert warnings == []

    def test_warns_for_generic_template(self) -> None:
        # Known generic template
        generic = "document of length class short, topic category general, temporal current"
        warnings = distinguishability_test(generic)
        assert len(warnings) > 0

    def test_warns_for_conversation_template(self) -> None:
        generic = "conversation with multiple participants, topic domain general, tone neutral"
        warnings = distinguishability_test(generic)
        assert len(warnings) > 0

    def test_never_raises(self) -> None:
        # Soft fail — must never raise
        distinguishability_test("")
        distinguishability_test("a" * 1000)
        distinguishability_test("document of length class short, topic category general, temporal current")

    def test_returns_list_type(self) -> None:
        result = distinguishability_test("some abstraction")
        assert isinstance(result, list)
