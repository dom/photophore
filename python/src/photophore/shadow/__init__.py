"""photophore.shadow — shadow generation module.

Public API:
  generate(content, content_type, relevance=0.5) -> ShadowResult
  Shadow, ShadowResult, ContentType — value types
  ShadowIrreversibilityError — hard-fail exception (dispatch must abort)
  irreversibility_test, relevance_preservation_test, distinguishability_test — quality helpers

SHADOW-06: no caching anywhere in this module. grep gate in tests/test_shadow_no_caching.py
asserts zero occurrences of @lru_cache, @functools.cache, _shadow_cache.
"""
from __future__ import annotations

from ._generate import generate
from ._quality import (
    _IRREVERSIBILITY_MIN_SUBSTR_LEN,
    distinguishability_test,
    irreversibility_test,
    relevance_preservation_test,
)
from ._strategies import _generate_abstraction
from ._types import ContentType, Shadow, ShadowResult
from ..errors import ShadowIrreversibilityError

__all__ = [
    "generate",
    "Shadow",
    "ShadowResult",
    "ContentType",
    "ShadowIrreversibilityError",
    "irreversibility_test",
    "relevance_preservation_test",
    "distinguishability_test",
    "_IRREVERSIBILITY_MIN_SUBSTR_LEN",
    "_generate_abstraction",
]
