"""`photophore dispatch` CLI subcommand (CLI-03, CONTEXT D-03, D-14 exit code 6).

Wires the 9-step async dispatch coordinator into a click subcommand:
  - --channel <id>: channel id to dispatch through
  - --task <path>: task envelope draft JSON file
  - --forge-url <url>: forge HTTP endpoint

Exit code 6 family on DispatchError (per CONTEXT D-03):
  - Human mode: single-line "error: dispatch failed (<SUBCODE>) at step <N>: <msg>."
  - --json mode: structured body { error, subcode, stage, message, retryable, ... }
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import click

from ..audit import AuditLog
from ..channels import ChannelStore
from ..dispatch import DispatchError, dispatch_async

__all__ = ["dispatch_command"]


@click.command("dispatch")
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
@click.pass_context
def dispatch_command(
    ctx: click.Context, channel_id: str, task_path: Path, forge_url: str
) -> None:
    """Dispatch a task envelope through the full 9-step privacy flow (CLI-03)."""
    output_json = bool(ctx.obj.get("json", False))
    audit_db = ctx.obj["audit_db"]
    channels_db = ctx.obj["channels_db"]
    draft: dict[str, Any] = json.loads(task_path.read_text())

    audit_log = AuditLog(audit_db)
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
            click.echo(
                f"error: dispatch failed ({exc.subcode}) at step {exc.stage}: "
                f"{exc}. retryable: {str(exc.retryable).lower()}.{audit_note}"
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
