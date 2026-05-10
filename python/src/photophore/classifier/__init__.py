"""Photophore classifier — content tier classification with strict priority order.

Priority: Explicit Tag (CLASS-02) > Path Rule (CLASS-03) > Rule-based Classifier (CLASS-04) > Default (CLASS-06).
"""
from __future__ import annotations

from ._default import default_tier
from ._engine import classify
from ._rules import load_rules
from ._tags import parse_explicit_tag
from ._types import Classification, PathRule, PathRules, Reason

__all__ = [
    "classify",
    "default_tier",
    "load_rules",
    "parse_explicit_tag",
    "Classification",
    "PathRule",
    "PathRules",
    "Reason",
]
