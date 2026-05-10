"""Shadow value types per SHADOW-02 + SHADOW-03.

ContentType: closed enum of 6 spec-mandated content-type categories.
Shadow: frozen dataclass — the tier-1 abstraction produced per dispatch.
ShadowResult: frozen dataclass wrapping Shadow + soft-warn diagnostic strings (OQ-3).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ContentType(Enum):
    """Six content-type categories from Photophore spec v0.3 §'Shadow Generation Quality'."""

    DOCUMENT = "document"
    CONVERSATION = "conversation"
    CREDENTIAL = "credential"
    FILE = "file"
    IDENTITY = "identity"
    CODE = "code"


@dataclass(frozen=True)
class Shadow:
    """Tier-1 shadow per SHADOW-02.

    Fields (exactly):
      shadow_id: UUIDv4 string (one per dispatch — NEVER cached)
      content_type: ContentType enum
      abstraction: per-type-strategy string (passes irreversibility_test)
      relevance: float 0.0..1.0
      tier: always 1 (tier-1 SHARED — validated at construction)
    """

    shadow_id: str
    content_type: ContentType
    abstraction: str
    relevance: float
    tier: int  # validated == 1 in __post_init__

    def __post_init__(self) -> None:
        if self.tier != 1:
            raise ValueError(
                f"Shadow.tier must be 1 (tier-1 SHARED), got {self.tier!r}"
            )
        if not (0.0 <= self.relevance <= 1.0):
            raise ValueError(
                f"Shadow.relevance must be in [0.0, 1.0], got {self.relevance!r}"
            )


@dataclass(frozen=True)
class ShadowResult:
    """generate() return value (OQ-3 resolution).

    Hard-fail (irreversibility): generate() raises ShadowIrreversibilityError;
    no ShadowResult is returned.

    Soft-fail (relevance / distinguishability): generate() returns ShadowResult
    with non-empty ``warnings``. Phase 3 dispatch coordinator records non-empty
    warnings to the audit log.
    """

    shadow: Shadow
    warnings: tuple[str, ...]


__all__ = ["ContentType", "Shadow", "ShadowResult"]
