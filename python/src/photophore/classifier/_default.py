"""default_tier() — the named function for classifier default per CLASS-06.

CLASS-06 mandates this be a NAMED FUNCTION, not a Tier.LOCAL literal at call sites.
A Hypothesis property test (test_classifier_default_property.py) asserts the invariant
over >=100 generated cases.
"""
from __future__ import annotations

from ..core import Tier


def default_tier() -> Tier:
    """Return the default tier for content with no explicit tag and no path-rule match.

    NEVER returns Tier.SHARED or Tier.PUBLIC. The privacy guarantee depends on this.
    Pitfall 2 (classifier default drift) — keep this function trivial; CI can be extended
    later to lint that no other code path returns Tier.LOCAL from a default-fallthrough.
    """
    return Tier.LOCAL
