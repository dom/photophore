"""AT-A2: Shadow inference — shadow IDs MUST be unique per dispatch."""
# AT-SURFACE: AT-A2
from __future__ import annotations

import pytest

from photophore.shadow import ContentType, generate


@pytest.mark.at_surface("AT-A2")
def test_shadow_uniqueness_single_dispatch() -> None:
    """100 generations with identical inputs produce 100 distinct shadow_ids.

    AT-A2 behavioral wire: verifies a shadow-correlation attack (using
    shadow_id to track content across dispatches) is structurally impossible
    because each shadow_id is fresh per dispatch — never cached or
    deterministically derived from content.
    """
    content = b"identical content for all generations"
    ids = [
        generate(content, ContentType.DOCUMENT, relevance=0.5).shadow.shadow_id
        for _ in range(100)
    ]
    distinct = len(set(ids))
    assert distinct == 100, (
        f"AT-A2: shadow_ids must be unique per generation; got {distinct}/100"
    )
