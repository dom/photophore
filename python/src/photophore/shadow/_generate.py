"""generate() — main shadow generation entry point per SHADOW-01..06.

Order of operations per spec:
  1. _generate_abstraction(content, content_type) — per-type strategy (SHADOW-03)
  2. irreversibility_test() — HARD FAIL raises ShadowIrreversibilityError (SHADOW-04)
  3. relevance_preservation_test() + distinguishability_test() — SOFT WARN -> warnings (SHADOW-04)
  4. shadow_id = str(uuid.uuid4()) — ALWAYS fresh per call (SHADOW-01, SHADOW-02, SHADOW-06)
  5. Return ShadowResult(shadow, warnings) (OQ-3)

NO CACHING: no module-level shadow cache, no @lru_cache, no @functools.cache.
SHADOW-06 verified by grep gate in test_shadow_no_caching.py AND behavioral test
(100 identical-input calls produce 100 distinct shadow_ids).
"""
from __future__ import annotations

import uuid

from ._quality import (
    distinguishability_test,
    irreversibility_test,
    relevance_preservation_test,
)
from ._strategies import _generate_abstraction
from ._types import ContentType, Shadow, ShadowResult


def generate(
    content: bytes, content_type: ContentType, relevance: float = 0.5
) -> ShadowResult:
    """Generate a fresh shadow per SHADOW-01..06.

    Args:
        content: source content bytes (NEVER stored or cached by this function).
        content_type: one of the 6 spec-mandated ContentType categories.
        relevance: declared relevance to the dispatch; float in [0.0, 1.0].

    Returns:
        ShadowResult(shadow, warnings) where:
          - shadow: a Shadow with a fresh UUIDv4 shadow_id and tier=1.
          - warnings: tuple of soft-fail diagnostic strings (may be empty).

    Raises:
        ShadowIrreversibilityError: when the abstraction leaks any source substring
            of length >= 8 chars (SHADOW-04 hard fail — dispatch must abort).
        ValueError: when relevance is outside [0.0, 1.0] (passed to Shadow constructor).
    """
    # Step 1: abstraction via per-type strategy (closed enum + match in _strategies.py).
    abstraction = _generate_abstraction(content, content_type)

    # Step 2: irreversibility check — HARD FAIL. Must run BEFORE shadow_id is generated
    # so that a leaky abstraction never reaches the caller with any ID attached.
    irreversibility_test(content, abstraction)

    # Step 3: soft-warn quality tests — collect diagnostics but do NOT abort.
    warnings: list[str] = []
    warnings.extend(relevance_preservation_test(content, abstraction, relevance))
    warnings.extend(distinguishability_test(abstraction))

    # Step 4: fresh UUIDv4 shadow_id — called LAST to avoid burning an ID on a
    # hard-fail path. SHADOW-01, SHADOW-02, SHADOW-06: every call produces a new ID.
    shadow_id = str(uuid.uuid4())

    shadow = Shadow(
        shadow_id=shadow_id,
        content_type=content_type,
        abstraction=abstraction,
        relevance=relevance,
        tier=1,
    )
    return ShadowResult(shadow=shadow, warnings=tuple(warnings))


__all__ = ["generate"]
