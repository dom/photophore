"""Explicit-tag parser per CLASS-02. Tags @photophore:(local|shared|public).

SECURITY (AT-A3): the tag is parsed from content BYTES, which are untrusted.
Callers must never let a parsed tag RAISE the tier above the trusted base
assignment (path rule / classifier / default); it may only lower it. The
lower-only enforcement lives in classifier._engine.classify().
"""
from __future__ import annotations

import re

from ..core import Tier

# CLASS-02: case-insensitive, recognized anywhere in content text.
_EXPLICIT_TAG_RE = re.compile(r"@photophore:(local|shared|public)\b", re.IGNORECASE)

_TIER_BY_NAME: dict[str, Tier] = {
    "local": Tier.LOCAL,
    "shared": Tier.SHARED,
    "public": Tier.PUBLIC,
}


def parse_explicit_tag(content: bytes) -> Tier | None:
    """Return the explicit-tag Tier if found in `content`, else None.

    Pure function — no I/O. Decodes content as UTF-8 with errors='replace';
    invalid UTF-8 does not raise. Returns the FIRST match (per CLASS-02 — single tag wins).
    """
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return None
    match = _EXPLICIT_TAG_RE.search(text)
    if match is None:
        return None
    return _TIER_BY_NAME[match.group(1).lower()]
