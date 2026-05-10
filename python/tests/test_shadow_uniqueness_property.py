"""Hypothesis property test for shadow_id uniqueness (SHADOW-02, SHADOW-06, AT-A2).

Required structure (B3 inner-loop invariant):
  @given outer case (from Hypothesis) × 100 inner generate() calls with IDENTICAL inputs
  = >=10,000 total generate() calls, all shadow_ids distinct.

This proves no content-keyed caching exists — a module-level @lru_cache would cause
100 calls with the same key to return the SAME shadow_id, failing the assertion.
"""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from photophore.shadow import ContentType, generate


@given(
    content=st.binary(min_size=8, max_size=200),
    content_type=st.sampled_from(list(ContentType)),
)
@settings(max_examples=100, deadline=None)
def test_shadow_id_uniqueness(content: bytes, content_type: ContentType) -> None:
    """100 calls with IDENTICAL (content, content_type) inputs produce 100 distinct shadow_ids.

    AT-A2 behavioral wire: verifies that a shadow-correlation attack (using shadow_id
    to track content across dispatches) is structurally impossible because each
    shadow_id is fresh per dispatch — never cached or deterministically derived from content.

    B3 inner loop: the 100 inner calls are the mandatory structure that detects
    content-keyed caching. Without this inner loop, a simple per-call cache would pass.
    """
    ids = [
        generate(content, content_type, relevance=0.5).shadow.shadow_id
        for _ in range(100)
    ]
    assert len(set(ids)) == 100, (
        f"Expected 100 distinct shadow_ids for identical inputs "
        f"(content_type={content_type}), got {len(set(ids))} distinct. "
        f"This indicates shadow caching is present (SHADOW-06 violation / AT-A2)."
    )
