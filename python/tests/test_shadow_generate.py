"""Tests for the generate() main entry point.

Covers SHADOW-01, SHADOW-02, SHADOW-04 (hard-fail dispatch abort), SHADOW-06.
"""
from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest

from photophore.shadow import (
    ContentType,
    Shadow,
    ShadowIrreversibilityError,
    ShadowResult,
    generate,
)


class TestGenerateHappyPath:
    def test_returns_shadow_result(self) -> None:
        result = generate(b"hello", ContentType.DOCUMENT, relevance=0.5)
        assert isinstance(result, ShadowResult)

    def test_shadow_tier_is_one(self) -> None:
        result = generate(b"hello world", ContentType.DOCUMENT, relevance=0.5)
        assert result.shadow.tier == 1

    def test_shadow_id_is_uuidv4(self) -> None:
        result = generate(b"hello world", ContentType.CODE, relevance=0.5)
        shadow_id = result.shadow.shadow_id
        assert len(shadow_id) == 36  # UUID4 string: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        parsed = uuid.UUID(shadow_id, version=4)
        assert str(parsed) == shadow_id

    def test_shadow_content_type_matches(self) -> None:
        # Use a PEM-style credential — its abstraction ("credential of type private-key")
        # does not contain any 8-char substring of the source bytes.
        result = generate(b"-----BEGIN PRIVATE KEY-----\nzzzzzzzzzz", ContentType.CREDENTIAL, relevance=0.5)
        assert result.shadow.content_type == ContentType.CREDENTIAL

    def test_shadow_relevance_matches(self) -> None:
        result = generate(b"hello", ContentType.IDENTITY, relevance=0.7)
        assert result.shadow.relevance == 0.7

    def test_warnings_is_tuple(self) -> None:
        result = generate(b"hello world", ContentType.DOCUMENT, relevance=0.5)
        assert isinstance(result.warnings, tuple)

    def test_default_relevance(self) -> None:
        result = generate(b"hello world", ContentType.FILE)
        assert result.shadow.relevance == 0.5

    def test_all_six_content_types(self) -> None:
        for ct in ContentType:
            result = generate(b"sample content for testing", ct, relevance=0.5)
            assert isinstance(result, ShadowResult)
            assert result.shadow.tier == 1
            assert result.shadow.content_type == ct


class TestGenerateHardFail:
    def test_raises_irreversibility_error_on_leaky_abstraction(self) -> None:
        """generate() with a mocked strategy that leaks content must raise."""
        content = b"my unique secret 12345"
        # Mock _generate_abstraction to return an abstraction that leaks a substring
        leaky = "unique s text"  # "unique s" is 8 chars and appears in source above
        with patch(
            "photophore.shadow._generate._generate_abstraction",
            return_value=leaky,
        ):
            with pytest.raises(ShadowIrreversibilityError) as exc_info:
                generate(content, ContentType.DOCUMENT, relevance=0.5)
            assert exc_info.value.code == "SHADOW_IRREVERSIBILITY_FAILED"

    def test_no_shadow_id_burned_on_hard_fail(self) -> None:
        """shadow_id (uuid.uuid4()) is called AFTER irreversibility check — so a
        hard-fail must not burn a UUID. We verify by checking uuid4 was not called."""
        content = b"leakable content here"
        leaky = "leakable"  # too short (8 chars exactly: "leakable")
        with patch(
            "photophore.shadow._generate._generate_abstraction",
            return_value=leaky,
        ), patch("photophore.shadow._generate.uuid") as mock_uuid:
            with pytest.raises(ShadowIrreversibilityError):
                generate(content, ContentType.DOCUMENT)
            mock_uuid.uuid4.assert_not_called()


class TestGenerateTwoCallsDistinctIds:
    def test_two_calls_identical_input_produce_distinct_ids(self) -> None:
        """SHADOW-01: same content dispatched twice produces different shadow_ids."""
        r1 = generate(b"hello world", ContentType.DOCUMENT, relevance=0.5)
        r2 = generate(b"hello world", ContentType.DOCUMENT, relevance=0.5)
        assert r1.shadow.shadow_id != r2.shadow.shadow_id

    def test_100_calls_produce_100_distinct_ids(self) -> None:
        """Behavioral confirmation of SHADOW-06 (no caching)."""
        ids = [
            generate(b"hello world", ContentType.CODE, relevance=0.5).shadow.shadow_id
            for _ in range(100)
        ]
        assert len(set(ids)) == 100
