"""classify() — main classifier entry point with strict priority order per CLASS-01.

Priority:
  1. Explicit Tag (CLASS-02) — @photophore:(local|shared|public) parsed from content
  2. Path Rule (CLASS-03)    — first-match-wins from rules YAML; mandatory `**` catch-all
  3. Rule-based Classifier (CLASS-04) — credential/PII/file-extension patterns; local on match
  4. Default (CLASS-06)      — default_tier() returns local as the named-function default

The branch ORDER IS the priority. Do NOT refactor to a strategy/registry pattern.
The order is the spec contract — CLASS-01 names the three priorities by number.
"""
from __future__ import annotations

from ._default import default_tier
from ._patterns import classify_by_rules
from ._tags import parse_explicit_tag
from ._types import Classification, PathRules


def classify(
    content: bytes,
    path: str | None = None,
    rules: PathRules | None = None,
) -> Classification:
    """Classify a single ContentBlock per CLASS-01 priority order.

    Args:
        content: raw content bytes (caller decodes if needed for human display).
        path: optional source-path string for path-rule matching (Priority 2).
        rules: optional loaded path rules (Priority 2). If None, Priority 2 is skipped.

    Returns:
        Classification(tier, reason) where reason is one of:
          - "explicit_tag"
          - "path_rule:<reason_label>"
          - "classifier:<rule_name>"
          - "classifier:default"
    """
    # Priority 1: Explicit Tag (CLASS-02)
    explicit = parse_explicit_tag(content)
    if explicit is not None:
        return Classification(tier=explicit, reason="explicit_tag")

    # Priority 2: Path Rule (CLASS-03)
    if path is not None and rules is not None:
        rule = rules.match(path)
        if rule is not None:
            return Classification(tier=rule.tier, reason=f"path_rule:{rule.reason}")

    # Priority 3: Rule-based Classifier (CLASS-04)
    rule_name = classify_by_rules(content, path)
    if rule_name is not None:
        # CLASS-04: positive classifier match always assigns the default tier (local) — never public.
        return Classification(tier=default_tier(), reason=f"classifier:{rule_name}")

    # Priority 4 (default): default_tier() — CLASS-06 named function (returns local, never shared/public).
    return Classification(tier=default_tier(), reason="classifier:default")
