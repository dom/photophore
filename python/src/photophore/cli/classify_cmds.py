"""`photophore classify` CLI subcommand. CLI-04: dry-run classification.

Reads `--rules <path>` if provided; otherwise resolves D-09 default location:
  $XDG_CONFIG_HOME/photophore/rules.yaml, falling back to ~/.config/photophore/rules.yaml.
Refuses to run if no rules file is present (per D-09 / CLASS-03).

Output:
  Single-file input + --json -> single JSON document  {path, tier, reason}
  Directory input + --json   -> JSON Lines (one per file)
  Default (no --json)        -> human-readable: f"{path}: ({tier}, {reason})"

Exit codes (D-14):
  0  success
  2  config error (rules file missing or malformed / RulesConfigError)
  4  classifier error (content unreadable or other failure)
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator

import click

from ..classifier import Classification, PathRules, classify, load_rules
from ..errors import RulesConfigError
from ._errors import ClassifierError, ConfigError
from ._format import emit_json_document, emit_json_lines


def _default_rules_path() -> Path:
    """Resolve the D-09 default rules location."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "photophore" / "rules.yaml"


def _resolve_rules(rules_arg: str | None) -> PathRules:
    """Load and validate the rules file. Raises ConfigError (exit 2) on failure."""
    if rules_arg is not None:
        path = Path(rules_arg)
    else:
        path = _default_rules_path()
        if not path.exists():
            raise ConfigError(
                f"no rules file present at {path!s}. Pass --rules <file> or create the default."
            )
    try:
        return load_rules(path)
    except RulesConfigError as exc:
        raise ConfigError(str(exc)) from exc


def _classify_single(path: Path, rules: PathRules) -> tuple[str, Classification]:
    """Classify a single file. Raises ClassifierError (exit 4) on read failure."""
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise ClassifierError(f"failed to read {path!s}: {exc}")
    return (str(path), classify(content, path=str(path), rules=rules))


def _walk_dir(
    path: Path, rules: PathRules
) -> Iterator[tuple[str, Classification]]:
    """Walk a directory recursively, classifying each file."""
    for child in sorted(path.rglob("*")):
        if child.is_file():
            yield _classify_single(child, rules)


@click.command("classify")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--rules", "rules_arg", default=None, help="Path to rules.yaml (overrides default).")
@click.pass_context
def classify_cmd(ctx: click.Context, path: Path, rules_arg: str | None) -> None:
    """Dry-run classify a path or content blob (CLI-04).

    Classifies the file or every file in a directory using the configured rules.

    With --json: single JSON document for a file; JSON Lines for a directory (D-12).
    Without --json: human-readable lines.
    """
    rules = _resolve_rules(rules_arg)
    output_json = ctx.obj.get("json", False) if ctx.obj else False

    if path.is_file():
        results = [_classify_single(path, rules)]
        if output_json:
            # Single file -> single JSON document (D-12)
            emit_json_document(
                {"path": results[0][0], "tier": results[0][1].tier.value, "reason": results[0][1].reason}
            )
        else:
            for p, c in results:
                click.echo(f"{p}: ({c.tier.value}, {c.reason})")
    elif path.is_dir():
        results_iter = _walk_dir(path, rules)
        if output_json:
            # Directory walk -> JSON Lines (D-12 streaming-friendly)
            emit_json_lines(
                {"path": p, "tier": c.tier.value, "reason": c.reason}
                for p, c in results_iter
            )
        else:
            for p, c in _walk_dir(path, rules):
                click.echo(f"{p}: ({c.tier.value}, {c.reason})")
    else:
        raise ClassifierError(f"unsupported path type: {path!s}")
