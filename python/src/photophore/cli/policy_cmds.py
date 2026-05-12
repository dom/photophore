"""`photophore policy` CLI subcommand group.

CLI-05: ``photophore policy preview`` — show the result_policy that would be
authored for a given channel + envelope draft WITHOUT dispatching.

POLICY-01: any result_policy field in the draft is IGNORED. The output shows
the channel-derived policy, not the draft's policy.
"""
from __future__ import annotations

import json
from pathlib import Path

import click

from ..audit import AuditLog
from ..channels import ChannelStore
from ..core import ChannelId
from ..policy import author
from ._audit_decorator import audit_cli_invocation
from ._errors import KeystoreError
from ._format import emit_json_document

__all__ = ["policy"]


@click.group("policy")
def policy() -> None:
    """Result policy authoring — preview the authored policy without dispatching."""


@policy.command("preview")
@audit_cli_invocation("policy.preview")
@click.option(
    "--channel",
    "channel_id",
    required=True,
    help="Channel id (UUIDv4) to author policy for.",
)
@click.option(
    "--task",
    "task_path",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to task envelope draft JSON.",
)
@click.pass_context
def preview(ctx: click.Context, channel_id: str, task_path: Path) -> None:
    """Show the result_policy that would be authored for a given channel + envelope draft.

    POLICY-01: any result_policy field in the draft is IGNORED. This command shows
    the channel-derived policy, not the draft's injected policy.

    Exits 5 (KeystoreError) if the channel is not found.
    Exits 0 on success.

    In --json mode, emits a single JSON document (D-12).
    In human mode, prints a multi-line readable summary.
    """
    audit_db = ctx.obj["audit_db"]
    channels_db = ctx.obj["channels_db"]
    audit_log = AuditLog(audit_db)
    store = ChannelStore(channels_db, audit_log)

    try:
        channel = store.show(ChannelId(channel_id))
    except Exception as exc:
        raise KeystoreError(
            f"channel {channel_id!r} not found: {exc}"
        ) from exc

    draft = json.loads(task_path.read_text())
    authored = author(channel, draft)
    has_injected_policy = draft.get("result_policy") is not None

    if ctx.obj.get("json"):
        emit_json_document(
            {
                "channel_id": channel.id,
                "channel_ceiling": channel.ceiling,
                "authored_policy": {
                    "persist_to_shared": authored.persist_to_shared,
                    "return_only": authored.return_only,
                    "strip_before_persist": authored.strip_before_persist,
                },
                "draft_policy_ignored": has_injected_policy,
            }
        )
    else:
        click.echo(f"channel:  {channel.id}")
        click.echo(f"ceiling:  {channel.ceiling}")
        click.echo("authored result_policy:")
        click.echo(f"  persist_to_shared:    {authored.persist_to_shared}")
        click.echo(f"  return_only:          {authored.return_only}")
        click.echo(f"  strip_before_persist: {authored.strip_before_persist}")
        if has_injected_policy:
            click.echo(
                "(NOTE: draft contained a result_policy field; it was IGNORED per POLICY-01.)"
            )
