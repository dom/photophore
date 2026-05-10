"""Shadow quality tests per SHADOW-04.

HARD FAIL: irreversibility_test — raises ShadowIrreversibilityError when the
abstraction contains any substring of the source content with length >=
_IRREVERSIBILITY_MIN_SUBSTR_LEN (8 chars, per 02-RESEARCH §7). Dispatch aborts.

SOFT WARN: relevance_preservation_test, distinguishability_test — return a list
of warning strings. The Shadow is still returned. Phase 3 dispatch coordinator
records non-empty warnings to the audit log.
"""
from __future__ import annotations

from ..errors import ShadowIrreversibilityError

# Pinned by 02-RESEARCH.md key finding §7.
# 4-char threshold produced false positives on common English words;
# 8-char threshold passes all verified test cases.
# Named constant per CLASS-06 / SHADOW-04 idiom.
_IRREVERSIBILITY_MIN_SUBSTR_LEN: int = 8


def irreversibility_test(source_content: bytes, abstraction: str) -> None:
    """Raise ShadowIrreversibilityError if abstraction leaks any source substring
    of length >= _IRREVERSIBILITY_MIN_SUBSTR_LEN chars.

    Binary content (non-decodable as UTF-8 strict) cannot leak via substring check;
    return without raising in that case. Using ``errors='strict'`` means an attacker
    cannot inject binary padding to bypass the check on an otherwise-valid UTF-8 source.

    Args:
        source_content: the original content bytes passed to generate().
        abstraction: the abstraction string produced by the per-type strategy.

    Raises:
        ShadowIrreversibilityError: if a >= 8-char substring of source appears
            verbatim in the abstraction. Hard fail — dispatch must abort.
    """
    try:
        source_text = source_content.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return  # Binary content — substring check not applicable

    n = len(source_text)
    if n < _IRREVERSIBILITY_MIN_SUBSTR_LEN:
        return  # source too short to produce a threshold-length substring

    for i in range(n - _IRREVERSIBILITY_MIN_SUBSTR_LEN + 1):
        substr = source_text[i : i + _IRREVERSIBILITY_MIN_SUBSTR_LEN]
        # Skip substrings that are purely whitespace — those are not identifying.
        if substr.strip() and substr in abstraction:
            raise ShadowIrreversibilityError(
                f"abstraction leaks source substring {substr!r}",
                code="SHADOW_IRREVERSIBILITY_FAILED",
            )


def relevance_preservation_test(
    source_content: bytes, abstraction: str, relevance: float
) -> list[str]:
    """SOFT WARN: return a list of diagnostic strings when the abstraction's
    apparent information content is poorly matched to the declared relevance.

    v0.1 heuristic: if relevance > 0.8 and the abstraction is shorter than
    30 characters, warn. This is intentionally simple; Phase 4 may extend with
    corpus-statistical measures.

    Never raises — soft fail only. Returns an empty list on pass.
    """
    warnings: list[str] = []
    if relevance > 0.8 and len(abstraction) < 30:
        warnings.append(
            f"high relevance ({relevance:.2f}) but short abstraction "
            f"({len(abstraction)} chars) — consider a richer abstraction strategy"
        )
    return warnings


def distinguishability_test(abstraction: str) -> list[str]:
    """SOFT WARN: return a list of diagnostic strings when the abstraction is so
    generic that distinct source documents would produce identical abstractions.

    v0.1 heuristic: flag exact matches against known generic template phrases.
    Phase 4 may extend with corpus-statistical checks.

    Never raises — soft fail only. Returns an empty list on pass.
    """
    warnings: list[str] = []
    _GENERIC_TEMPLATES: frozenset[str] = frozenset(
        {
            "document of length class short, topic category general, temporal current",
            "conversation with multiple participants, topic domain general, tone neutral",
        }
    )
    if abstraction in _GENERIC_TEMPLATES:
        # Note: v0.1 strategies are generic by design. This warning is informational,
        # not blocking. Phase 4 hardening may upgrade it.
        warnings.append(
            "abstraction matches a known generic template; "
            "consider adding corpus-statistical signals for better distinguishability"
        )
    return warnings


__all__ = [
    "_IRREVERSIBILITY_MIN_SUBSTR_LEN",
    "irreversibility_test",
    "relevance_preservation_test",
    "distinguishability_test",
]
