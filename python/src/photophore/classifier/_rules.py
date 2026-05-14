"""Path-rules YAML loader with pathspec gitwildmatch matching.

D-08: load-per-invocation; loader-time refusal of missing `**` -> local catch-all.
D-09: default location is ~/.config/photophore/rules.yaml (XDG override). CLI flag --rules.
D-10: ordered list of {pattern, tier, reason}; first-match-wins.

CRITICAL: yaml.safe_load is mandatory (Pitfall 5 / PITFALLS.md security). yaml.load
without SafeLoader is RCE via YAML tags.

CRITICAL: pathspec>=1.1.1 with gitwildmatch semantics is required. fnmatch and
pathlib.PurePath.match both fail on `**/.env*` matching bare `.env`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pathspec
import pathspec.patterns
import yaml

from ..core import Tier
from ..errors import RulesConfigError
from ._types import PathRule, PathRules

_TIER_BY_NAME: dict[str, Tier] = {
    "local": Tier.LOCAL,
    "shared": Tier.SHARED,
    "public": Tier.PUBLIC,
}


@dataclass(frozen=True)
class _LoadedPathRules:
    """Concrete PathRules with pathspec-backed match implementation.

    Mirrors PathRules Protocol but with the pathspec instance bound and a working match().
    Duck-typed to PathRules Protocol — no explicit inheritance required (W7).
    """

    rules: tuple[PathRule, ...]
    spec_per_rule: tuple[pathspec.PathSpec[Any], ...]

    def match(self, path: str) -> PathRule | None:
        """First-match-wins per D-10. Walk rules in order; check each individual pathspec."""
        for rule, spec in zip(self.rules, self.spec_per_rule):
            if spec.match_file(path):
                return rule
        return None


def load_rules(path: Path | str) -> PathRules:
    """Load YAML rules config. Raises RulesConfigError on malformed or missing catch-all (D-08)."""
    p = Path(path)
    try:
        raw_text = p.read_text()
    except OSError as exc:
        raise RulesConfigError(
            f"failed to read rules file {p!s}: {exc}", code="RULES_CONFIG_INVALID"
        ) from exc
    try:
        raw: Any = yaml.safe_load(raw_text)  # NEVER yaml.load() — RCE via YAML tags (Pitfall 5)
    except yaml.YAMLError as exc:
        raise RulesConfigError(
            f"malformed YAML in rules file {p!s}: {exc}", code="RULES_CONFIG_INVALID"
        ) from exc
    if not isinstance(raw, dict) or "rules" not in raw or not isinstance(raw["rules"], list):
        raise RulesConfigError(
            f"rules file {p!s} missing top-level `rules:` list", code="RULES_CONFIG_INVALID"
        )
    rules_list: list[Any] = raw["rules"]
    if not rules_list:
        raise RulesConfigError(
            f"rules file {p!s} has empty `rules:` list", code="RULES_CONFIG_INVALID"
        )
    # D-08 / CLASS-03: mandatory `**` -> local catch-all as LAST rule.
    last = rules_list[-1]
    if not isinstance(last, dict) or last.get("pattern") != "**" or last.get("tier") != "local":
        raise RulesConfigError(
            f"rules file {p!s} missing mandatory '**' -> 'local' catch-all as last rule; "
            f"missing catch-all would allow unmatched content to escape classification (CLASS-03 / D-08)",
            code="RULES_CONFIG_INVALID",
        )
    # Build PathRule + per-rule pathspec for first-match-wins.
    rules: list[PathRule] = []
    specs: list[pathspec.PathSpec[Any]] = []
    for i, raw_rule in enumerate(rules_list):
        if not isinstance(raw_rule, dict):
            raise RulesConfigError(
                f"rule #{i} in {p!s} is not a mapping", code="RULES_CONFIG_INVALID"
            )
        pat: Any = raw_rule.get("pattern")
        tier_name: Any = raw_rule.get("tier")
        reason_label: Any = raw_rule.get("reason") or pat or f"rule_{i}"
        if not isinstance(pat, str) or not isinstance(tier_name, str):
            raise RulesConfigError(
                f"rule #{i} in {p!s} missing pattern or tier", code="RULES_CONFIG_INVALID"
            )
        if tier_name not in _TIER_BY_NAME:
            raise RulesConfigError(
                f"rule #{i} in {p!s} has invalid tier {tier_name!r}; expected one of "
                f"{sorted(_TIER_BY_NAME)}",
                code="RULES_CONFIG_INVALID",
            )
        rules.append(PathRule(pattern=pat, tier=_TIER_BY_NAME[tier_name], reason=str(reason_label)))
        # Use "gitignore" pattern type (gitwildmatch semantics; "gitwildmatch" name deprecated in pathspec>=1.0.0)
        specs.append(pathspec.PathSpec.from_lines("gitignore", [pat]))
    # W7: PathRules in _types.py is a typing.Protocol; _LoadedPathRules satisfies it via duck typing.
    # Return type is PathRules (Protocol); _LoadedPathRules concretely implements .match(). No type: ignore.
    return _LoadedPathRules(rules=tuple(rules), spec_per_rule=tuple(specs))
