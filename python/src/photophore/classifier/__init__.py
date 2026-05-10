"""Photophore classifier — content tier classification with strict priority order.

Priority: Explicit Tag (CLASS-02) > Path Rule (CLASS-03) > Rule-based Classifier (CLASS-04) > Default (CLASS-06).
"""
from __future__ import annotations

from ._default import default_tier
from ._tags import parse_explicit_tag
from ._types import Classification, PathRule, PathRules, Reason

# _engine.classify and _rules.load_rules are added by Tasks 2 + 3.

__all__ = [
    "default_tier",
    "parse_explicit_tag",
    "Classification",
    "PathRule",
    "PathRules",
    "Reason",
]
