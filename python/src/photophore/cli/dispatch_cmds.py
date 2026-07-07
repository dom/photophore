"""`photophore dispatch` CLI subcommand (CLI-03, D-14 exit code 6).

Wires the 9-step async dispatch coordinator into a click subcommand:
  - --channel <id>: channel id to dispatch through
  - --task <path>: task envelope draft JSON file
  - --forge-url <url>: forge HTTP endpoint
  - --rules <path>: path rules for dispatch-time classification (optional;
    falls back to the D-09 default location when that file exists)

Exit code 6 family on DispatchError:
  - Human mode: single-line "error: dispatch failed (<SUBCODE>) at step <N>: <msg>."
  - --json mode: structured body { error, subcode, stage, message, retryable, ... }
Exit code 2 on a missing/malformed --rules file (ConfigError, fail closed).
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import click

from ..audit import open_audit_log
from ..channels import ChannelStore
from ..classifier import PathRules, load_rules
from ..dispatch import DispatchError, dispatch_async
from ..errors import RulesConfigError
from ._audit_decorator import audit_cli_invocation
from ._errors import ConfigError
from .classify_cmds import _default_rules_path

__all__ = ["dispatch_command"]


def _resolve_optional_rules(rules_arg: str | None) -> PathRules | None:
    """Resolve path rules for dispatch-time classification (LOW 9).

    Enforcement runs inside the dispatch coordinator, so classification (and
    the warnings it emits) is only authoritative when the coordinator sees
    the same path rules the classifier CLI uses.

    - ``--rules <path>``: must load; missing or malformed is a ConfigError
      (exit 2, fail closed).
    - No flag: the D-09 default location is loaded when the file exists
      (malformed default is also a ConfigError).
    - No flag and no default file: returns None; the classifier still
      fail-closes to local without path rules.
    """
    if rules_arg is not None:
        path = Path(rules_arg)
    else:
        path = _default_rules_path()
        if not path.exists():
            return None
    try:
        return load_rules(path)
    except RulesConfigError as exc:
        raise ConfigError(str(exc)) from exc


@click.command("dispatch")
@audit_cli_invocation("dispatch")
@click.option(
    "--channel", "channel_id", required=True,
    help="Channel id (UUIDv4) to dispatch through.",
)
@click.option(
    "--task", "task_path", required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to task envelope draft JSON.",
)
@click.option(
    "--forge-url", "forge_url", required=True,
    help="HTTP URL of the target forge.",
)
@click.option(
    "--rules", "rules_arg", default=None,
    help="Path to rules.yaml for dispatch-time classification "
         "(overrides the default location).",
)
@click.pass_context
def dispatch_command(
    ctx: click.Context, channel_id: str, task_path: Path, forge_url: str,
    rules_arg: str | None,
) -> None:
    """Dispatch a task envelope through the full 9-step privacy flow (CLI-03)."""
    output_json = bool(ctx.obj.get("json", False))
    audit_db = ctx.obj["audit_db"]
    channels_db = ctx.obj["channels_db"]
    rules = _resolve_optional_rules(rules_arg)
    draft: dict[str, Any] = json.loads(task_path.read_text())

    audit_log = open_audit_log(audit_db)
    channel_store = ChannelStore(channels_db, audit_log)

    # IdentityProvider + Verifier wiring — sovereign brine adapter from thermocline-py.
    from thermocline.identity import BrineProvider, Verifier
    provider = BrineProvider(keyring_service="thermocline.brine")
    verifier = Verifier()
    verifier.register(provider)

    try:
        outcome = asyncio.run(
            dispatch_async(
                channel_id=channel_id,
                task_draft=draft,
                audit_log=audit_log,
                channel_store=channel_store,
                identity_provider=provider,
                verifier=verifier,
                forge_url=forge_url,
                rules=rules,
            )
        )
    except DispatchError as exc:
        if output_json:
            body: dict[str, Any] = {
                "error": "DispatchError",
                "subcode": str(exc.subcode),
                "stage": exc.stage,
                "message": str(exc),
                "retryable": exc.retryable,
                "envelope_id": exc.envelope_id,
                "channel_id": exc.channel_id,
            }
            if exc.audit_entry_hash is not None:
                body["audit_entry_hash"] = exc.audit_entry_hash
            click.echo(json.dumps(body))
        else:
            audit_note = (
                f" audit entry: {exc.audit_entry_hash}."
                if exc.audit_entry_hash else ""
            )
            # CLI-07 / D-08: augment with (tier=X, reason=Y) when the
            # dispatch was blocked on a specific content block (classification
            # or policy failure). Optional fields default to None for
            # backward compatibility.
            tier_reason = ""
            if exc.blocked_tier is not None and exc.blocked_reason is not None:
                block_label = exc.blocked_block_path or "block"
                tier_reason = (
                    f" blocked block: {block_label} "
                    f"(tier={exc.blocked_tier}, reason={exc.blocked_reason})."
                )
            click.echo(
                f"error: dispatch failed ({exc.subcode}) at step {exc.stage}: "
                f"{exc}. retryable: {str(exc.retryable).lower()}."
                f"{tier_reason}{audit_note}"
            )
        sys.exit(6)

    if output_json:
        click.echo(json.dumps({
            "envelope_id": outcome.envelope_id,
            "receipt_signature_hash": outcome.receipt_signature_hash,
            "pre_audit_hash": outcome.pre_audit_hash,
            "post_audit_hash": outcome.post_audit_hash,
            "warnings": list(outcome.warnings),
        }, indent=2, sort_keys=True))
    else:
        click.echo(
            f"dispatch ok envelope_id={outcome.envelope_id} "
            f"receipt_sig={outcome.receipt_signature_hash}"
        )
