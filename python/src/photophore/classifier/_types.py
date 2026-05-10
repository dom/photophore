"""Classifier output types. Frozen dataclasses + Reason enum."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from ..core import Tier


class Reason(Enum):
    """Source of a classification — the four spec-mandated reason categories (CLASS-05)."""

    EXPLICIT_TAG = "explicit_tag"
    PATH_RULE = "path_rule"  # full reason string built as f"path_rule:{pattern_or_label}"
    CLASSIFIER_RULE = "classifier"  # full reason string built as f"classifier:{rule_name}"
    CLASSIFIER_DEFAULT = "classifier:default"


@dataclass(frozen=True)
class Classification:
    """Output of `classify()`. Reason is the full string per CLASS-05.

    Reason format:
      "explicit_tag"
      "path_rule:<pattern_or_label>"
      "classifier:<rule_name>"  (e.g., "classifier:credential_pem")
      "classifier:default"
    """

    tier: Tier
    reason: str


@dataclass(frozen=True)
class PathRule:
    pattern: str
    tier: Tier
    reason: str  # freeform reason label per D-10


# W7: PathRules is a typing.Protocol — _rules.py provides the concrete implementation
# via _LoadedPathRules. Duck typing means no explicit inheritance is required, and no
# runtime_checkable is needed. This avoids the type: ignore[return-value] in load_rules().


class PathRules(Protocol):
    """Protocol for the loaded path-rules container produced by load_rules().
    Implementation lives in _rules.py as `_LoadedPathRules` (duck-typed).
    """

    rules: tuple[PathRule, ...]

    def match(self, path: str) -> PathRule | None:
        """First-match-wins per D-10. Returns None if no rule matches (only possible if catch-all
        was bypassed, which load_rules() prevents — defensive None handling is required).
        """
        ...
