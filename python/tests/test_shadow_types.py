"""Tests for shadow type definitions (Shadow, ContentType, ShadowResult).

Covers: SHADOW-02 (Shadow fields), SHADOW-03 (6 content types).
"""
from __future__ import annotations

import uuid
import pytest

from photophore.shadow import ContentType, Shadow, ShadowResult


class TestContentType:
    def test_has_exactly_six_members(self) -> None:
        assert len(ContentType) == 6

    def test_members(self) -> None:
        members = {m.value for m in ContentType}
        assert members == {
            "document",
            "conversation",
            "credential",
            "file",
            "identity",
            "code",
        }

    def test_document(self) -> None:
        assert ContentType.DOCUMENT.value == "document"

    def test_conversation(self) -> None:
        assert ContentType.CONVERSATION.value == "conversation"

    def test_credential(self) -> None:
        assert ContentType.CREDENTIAL.value == "credential"

    def test_file(self) -> None:
        assert ContentType.FILE.value == "file"

    def test_identity(self) -> None:
        assert ContentType.IDENTITY.value == "identity"

    def test_code(self) -> None:
        assert ContentType.CODE.value == "code"


class TestShadow:
    def _make(self, **kwargs: object) -> Shadow:
        defaults: dict[str, object] = {
            "shadow_id": str(uuid.uuid4()),
            "content_type": ContentType.DOCUMENT,
            "abstraction": "doc abstract",
            "relevance": 0.5,
            "tier": 1,
        }
        defaults.update(kwargs)
        return Shadow(**defaults)  # type: ignore[arg-type]

    def test_constructs_ok(self) -> None:
        s = self._make()
        assert s.tier == 1
        assert s.relevance == 0.5
        assert s.content_type == ContentType.DOCUMENT

    def test_is_frozen(self) -> None:
        s = self._make()
        with pytest.raises((AttributeError, TypeError)):
            s.tier = 2  # type: ignore[misc]

    def test_tier_must_be_one(self) -> None:
        with pytest.raises(ValueError, match="tier must be 1"):
            self._make(tier=0)
        with pytest.raises(ValueError, match="tier must be 1"):
            self._make(tier=2)

    def test_relevance_bounds_low(self) -> None:
        with pytest.raises(ValueError, match="relevance"):
            self._make(relevance=-0.1)

    def test_relevance_bounds_high(self) -> None:
        with pytest.raises(ValueError, match="relevance"):
            self._make(relevance=1.1)

    def test_relevance_boundary_values(self) -> None:
        s0 = self._make(relevance=0.0)
        assert s0.relevance == 0.0
        s1 = self._make(relevance=1.0)
        assert s1.relevance == 1.0

    def test_shadow_id_uuidv4_shape(self) -> None:
        shadow_id = str(uuid.uuid4())
        s = self._make(shadow_id=shadow_id)
        parsed = uuid.UUID(s.shadow_id, version=4)
        assert str(parsed) == shadow_id


class TestShadowResult:
    def test_constructs(self) -> None:
        shadow = Shadow(
            shadow_id=str(uuid.uuid4()),
            content_type=ContentType.DOCUMENT,
            abstraction="abstract",
            relevance=0.5,
            tier=1,
        )
        result = ShadowResult(shadow=shadow, warnings=("warn1",))
        assert result.shadow is shadow
        assert result.warnings == ("warn1",)

    def test_empty_warnings(self) -> None:
        shadow = Shadow(
            shadow_id=str(uuid.uuid4()),
            content_type=ContentType.CODE,
            abstraction="abstract",
            relevance=0.9,
            tier=1,
        )
        result = ShadowResult(shadow=shadow, warnings=())
        assert result.warnings == ()

    def test_is_frozen(self) -> None:
        shadow = Shadow(
            shadow_id=str(uuid.uuid4()),
            content_type=ContentType.FILE,
            abstraction="abstract",
            relevance=0.3,
            tier=1,
        )
        result = ShadowResult(shadow=shadow, warnings=())
        with pytest.raises((AttributeError, TypeError)):
            result.warnings = ("x",)  # type: ignore[misc]
