"""Tests for per-content-type abstraction strategies.

Covers SHADOW-03 (spec table MUST / MUST NOT signals for each of 6 types).
"""
from __future__ import annotations

import pytest

from photophore.shadow import ContentType, _generate_abstraction


class TestDocumentStrategy:
    def test_includes_length_class(self) -> None:
        # short document (< 1000 bytes)
        short = _generate_abstraction(b"x" * 50, ContentType.DOCUMENT)
        assert "short" in short

        medium = _generate_abstraction(b"x" * 5_000, ContentType.DOCUMENT)
        assert "medium" in medium

        long_ = _generate_abstraction(b"x" * 100_000, ContentType.DOCUMENT)
        assert "long" in long_

    def test_includes_topic_category(self) -> None:
        result = _generate_abstraction(b"some document content", ContentType.DOCUMENT)
        assert "topic" in result.lower() or "category" in result.lower()

    def test_includes_temporal_indicator(self) -> None:
        result = _generate_abstraction(b"doc", ContentType.DOCUMENT)
        assert "temporal" in result.lower() or "current" in result.lower()

    def test_does_not_include_filename(self) -> None:
        # strategy does not receive a filename; verify it does not emit one either
        result = _generate_abstraction(b"doc content here", ContentType.DOCUMENT)
        assert ".txt" not in result and ".doc" not in result

    def test_returns_string(self) -> None:
        result = _generate_abstraction(b"hello", ContentType.DOCUMENT)
        assert isinstance(result, str)
        assert len(result) > 0


class TestConversationStrategy:
    def test_includes_participant_count(self) -> None:
        result = _generate_abstraction(b"alice: hi\nbob: hello", ContentType.CONVERSATION)
        # Strategy mentions "participants" or "participant"
        assert "participant" in result.lower()

    def test_includes_topic_domain(self) -> None:
        result = _generate_abstraction(b"conversation content", ContentType.CONVERSATION)
        assert "topic" in result.lower() or "domain" in result.lower()

    def test_includes_tone(self) -> None:
        result = _generate_abstraction(b"conversation", ContentType.CONVERSATION)
        assert "tone" in result.lower() or "neutral" in result.lower() or "formal" in result.lower()

    def test_does_not_include_quotes(self) -> None:
        # The abstraction must not verbatim quote content
        content = b"Alice said: this is a secret"
        result = _generate_abstraction(content, ContentType.CONVERSATION)
        # The full quote must not appear
        assert "this is a secret" not in result


class TestCredentialStrategy:
    def test_private_key_type(self) -> None:
        content = b"-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----"
        result = _generate_abstraction(content, ContentType.CREDENTIAL)
        # Strategy uses "pem-encoded-key" to identify the type
        assert "pem-encoded-key" in result or "key" in result.lower()
        # MUST NOT include the key material
        assert "xxx" not in result

    def test_api_token_type(self) -> None:
        content = b"sk-abcdefghij1234567890"
        result = _generate_abstraction(content, ContentType.CREDENTIAL)
        assert "bearer-token" in result or "token" in result.lower()
        # MUST NOT include the token value
        assert "abcdefghij1234567890" not in result

    def test_cloud_api_key_type(self) -> None:
        content = b"AKIA1234567890ABCDEF"
        result = _generate_abstraction(content, ContentType.CREDENTIAL)
        assert "cloud-access-key" in result or "cloud" in result.lower()

    def test_generic_credential(self) -> None:
        # Uses non-credential vocabulary so irreversibility test passes
        content = b"xmzqwop9876543210abcdef"
        result = _generate_abstraction(content, ContentType.CREDENTIAL)
        # Strategy emits "auth-secret of class opaque" for unrecognized credential
        assert "auth-secret" in result or "opaque" in result.lower() or "class" in result.lower()

    def test_does_not_include_value(self) -> None:
        # Critical: MUST NOT include the credential value
        secret_value = b"my-super-secret-password-123456"
        result = _generate_abstraction(secret_value, ContentType.CREDENTIAL)
        # The actual password must NOT appear in the abstraction
        assert "my-super-secret-password-123456" not in result


class TestFileStrategy:
    def test_includes_file_category(self) -> None:
        result = _generate_abstraction(b"\x89PNG\r\n\x1a\n", ContentType.FILE)
        assert "file" in result.lower() or "category" in result.lower()

    def test_includes_size_class(self) -> None:
        result = _generate_abstraction(b"x" * 500, ContentType.FILE)
        assert "short" in result or "size" in result.lower()

    def test_does_not_include_filename(self) -> None:
        result = _generate_abstraction(b"binary file contents", ContentType.FILE)
        # Strategy receives no filename; must not emit one
        assert ".png" not in result and ".jpg" not in result and ".pdf" not in result


class TestIdentityStrategy:
    def test_includes_identity_type(self) -> None:
        result = _generate_abstraction(b"John Doe, john@example.com", ContentType.IDENTITY)
        assert "identity" in result.lower()
        assert "person" in result.lower() or "type" in result.lower()

    def test_does_not_include_identity_value(self) -> None:
        # MUST NOT include identity value
        content = b"John Doe"
        result = _generate_abstraction(content, ContentType.IDENTITY)
        assert "John" not in result
        assert "Doe" not in result

    def test_does_not_include_contact_info(self) -> None:
        content = b"john@example.com, +1-555-1234"
        result = _generate_abstraction(content, ContentType.IDENTITY)
        assert "example.com" not in result
        assert "555-1234" not in result


class TestCodeStrategy:
    def test_includes_complexity(self) -> None:
        short_code = b"x = 1"
        result = _generate_abstraction(short_code, ContentType.CODE)
        assert "complex" in result.lower() or "short" in result.lower()

    def test_includes_domain(self) -> None:
        result = _generate_abstraction(b"def foo(): pass", ContentType.CODE)
        assert "domain" in result.lower()

    def test_does_not_include_function_names(self) -> None:
        content = b"def my_secret_function(): return 42"
        result = _generate_abstraction(content, ContentType.CODE)
        # MUST NOT include function names
        assert "my_secret_function" not in result

    def test_does_not_include_variable_names(self) -> None:
        content = b"secret_variable = 'password123'"
        result = _generate_abstraction(content, ContentType.CODE)
        assert "secret_variable" not in result
        assert "password123" not in result


class TestAllSixStrategiesProduceStrings:
    def test_all_strategies_return_nonempty_string(self) -> None:
        content = b"sample content for testing"
        for ct in ContentType:
            result = _generate_abstraction(content, ct)
            assert isinstance(result, str), f"strategy for {ct} returned non-str"
            assert len(result) > 0, f"strategy for {ct} returned empty string"
