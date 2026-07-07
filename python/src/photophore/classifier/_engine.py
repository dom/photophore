"""classify(): main classifier entry point (CLASS-01 hardened, lower-only tags).

Base assignment (trusted signals, in order):
  1. Path Rule (CLASS-03): first-match-wins from rules YAML; mandatory `**` catch-all
  2. Rule-based Classifier (CLASS-04): credential/PII/file-extension patterns; local on match
  3. Default (CLASS-06): default_tier() returns local as the named-function default

Embedded tags (CLASS-02, HARDENED): ``@photophore:(local|shared|public)`` is
parsed from the content BYTES, which are untrusted (anything that can write
into a file, an email body, a downloaded document, a prompt injection, can
plant a tag). A tag may therefore only LOWER the tier below the base
assignment, never raise it. ``@photophore:public`` inside a ``~/Private/**``
secret stays local; ``@photophore:local`` inside shared-path content locks it
down. Fail closed.

(Pre-hardening behavior made the embedded tag Priority 1 over everything,
which let untrusted content self-promote to public. That is the AT-A3
classifier-evasion surface; do not restore it.)
"""
from __future__ import annotations

from ..core import Tier
from ._default import default_tier
from ._patterns import classify_by_rules
from ._tags import parse_explicit_tag
from ._types import Classification, PathRules

# Rank order for the lower-only tag rule. Tier declaration order IS the rank
# order (local < shared < public); rank 0 (local) is the most restrictive.
# Built from the enum, never from tier literals (CLASS-06 keeps hardcoded
# Tier members out of this module).
_TIER_RANK: dict[Tier, int] = {tier: rank for rank, tier in enumerate(Tier)}


def classify(
    content: bytes,
    path: str | None = None,
    rules: PathRules | None = None,
) -> Classification:
    """Classify a single ContentBlock; embedded tags can only lower the tier.

    Args:
        content: raw content bytes (caller decodes if needed for human display).
        path: optional source-path string for path-rule matching.
        rules: optional loaded path rules. If None, path-rule matching is skipped.

    Returns:
        Classification(tier, reason) where reason is one of:
          - "explicit_tag"            (tag LOWERED the tier, or confirmed it)
          - "path_rule:<reason_label>"
          - "classifier:<rule_name>"
          - "classifier:default"
    """
    # ---- Base assignment from TRUSTED signals ------------------------------
    base: Classification | None = None

    # Path Rule (CLASS-03): issuer-configured, first-match-wins.
    if path is not None and rules is not None:
        rule = rules.match(path)
        if rule is not None:
            base = Classification(tier=rule.tier, reason=f"path_rule:{rule.reason}")

    # Rule-based Classifier (CLASS-04): positive match always assigns the
    # default tier (local), never public.
    if base is None:
        rule_name = classify_by_rules(content, path)
        if rule_name is not None:
            base = Classification(tier=default_tier(), reason=f"classifier:{rule_name}")

    # Default (CLASS-06): default_tier() named function (local, never shared/public).
    if base is None:
        base = Classification(tier=default_tier(), reason="classifier:default")

    # ---- Embedded tag: LOWER-ONLY (fail closed) ----------------------------
    # Tags live in untrusted content bytes; they may restrict, never promote.
    explicit = parse_explicit_tag(content)
    if explicit is not None and _TIER_RANK[explicit] <= _TIER_RANK[base.tier]:
        return Classification(tier=explicit, reason="explicit_tag")
    return base
