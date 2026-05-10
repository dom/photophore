"""photophore channel subcommands: new | open | list | show | suspend | close | set-ceiling.

CLI-01: channel new|list|show|suspend|close|set-ceiling (plus open for CHAN-02 completeness).

D-12 output modes:
  - --json: single JSON document for all channel commands
  - default: human-readable

D-14 exit codes:
  - 0: success
  - 1: ChannelStateError (click default exit code for generic exceptions)
  - 5: keystore unavailable or channel not found (KeystoreError)

Local-node default: $PHOTOPHORE_LOCAL_NODE env var, fallback to socket.gethostname().
Creator-identity default: $USER env var, fallback to "unknown".
"""
from __future__ import annotations

import dataclasses
import os
import socket
from pathlib import Path
from typing import Any

import click

from ..audit._store import AuditLog
from ..channels._store import ChannelStore, _channel_to_dict
from ..channels._types import Channel
from ..core import ChannelId, ChannelState
from ..errors import ChannelStateError, KeystoreUnavailableError
from ._errors import KeystoreError as CliKeystoreError
from ._format import emit_human_channel, emit_json_document


def _get_local_node() -> str:
    return os.environ.get("PHOTOPHORE_LOCAL_NODE", socket.gethostname())


def _get_creator_identity() -> str:
    return os.environ.get("USER", "unknown")


def _channel_as_dict(ch: Channel) -> dict[str, Any]:
    d = _channel_to_dict(ch)
    d["state"] = ch.state.value
    return d


def _open_store(ctx: click.Context) -> tuple[AuditLog, ChannelStore]:
    """Open AuditLog + ChannelStore from ctx.obj, creating the data_dir if needed."""
    audit_db = ctx.obj["audit_db"]
    channels_db = ctx.obj["channels_db"]
    Path(audit_db).parent.mkdir(parents=True, exist_ok=True)
    try:
        log = AuditLog(audit_db)
        store = ChannelStore(channels_db, log)
    except KeystoreUnavailableError as exc:
        raise CliKeystoreError(str(exc)) from exc
    return log, store


@click.group("channel")
def channel() -> None:
    """Channel registry operations — create, inspect, and lifecycle management."""


@channel.command("new")
@click.option("--remote-node", required=True, help="Remote node identity.")
@click.option("--ceiling", default="tier-1",
              type=click.Choice(["tier-0", "tier-1", "tier-2"]),
              help="Trust ceiling (default: tier-1).")
@click.option("--key-scheme", default="brine",
              type=click.Choice(["brine", "pgp", "x509", "none"]),
              help="Key scheme for signing (default: brine).")
@click.option("--description", default="", help="Human-readable description.")
@click.pass_context
def new(
    ctx: click.Context,
    remote_node: str,
    ceiling: str,
    key_scheme: str,
    description: str,
) -> None:
    """Create a new channel (state=PROPOSED). (CLI-01)"""
    output_json = ctx.obj["json"]
    _, store = _open_store(ctx)
    try:
        ch = store.create(
            remote_node=remote_node,
            ceiling=ceiling,
            key_scheme=key_scheme,
            local_node=_get_local_node(),
            creator_identity=_get_creator_identity(),
            description=description,
        )
    except KeystoreUnavailableError as exc:
        raise CliKeystoreError(str(exc)) from exc
    if output_json:
        emit_json_document(_channel_as_dict(ch))
    else:
        click.echo(f"Created channel: {ch.id}")
        emit_human_channel(_channel_as_dict(ch))


@channel.command("list")
@click.pass_context
def list_channels(ctx: click.Context) -> None:
    """List all channels. (CLI-01 / CHAN-06)"""
    output_json = ctx.obj["json"]
    _, store = _open_store(ctx)
    try:
        channels = store.list_channels()
    except KeystoreUnavailableError as exc:
        raise CliKeystoreError(str(exc)) from exc
    if output_json:
        emit_json_document([_channel_as_dict(ch) for ch in channels])
    else:
        if not channels:
            click.echo("No channels registered.")
        for ch in channels:
            click.echo(f"  {ch.id} | {ch.remote_node} | {ch.state.value} | {ch.ceiling}")


@channel.command("show")
@click.argument("channel_id")
@click.pass_context
def show(ctx: click.Context, channel_id: str) -> None:
    """Show a single channel record. (CLI-01 / CHAN-06)"""
    output_json = ctx.obj["json"]
    _, store = _open_store(ctx)
    try:
        ch = store.show(ChannelId(channel_id))
    except KeystoreUnavailableError as exc:
        raise CliKeystoreError(str(exc)) from exc
    if output_json:
        emit_json_document(_channel_as_dict(ch))
    else:
        emit_human_channel(_channel_as_dict(ch))


@channel.command("open")
@click.argument("channel_id")
@click.pass_context
def open_(ctx: click.Context, channel_id: str) -> None:
    """Transition a channel from PROPOSED to OPEN. (CLI-01 / CHAN-02)"""
    output_json = ctx.obj["json"]
    _, store = _open_store(ctx)
    try:
        ch = store.transition_to(ChannelId(channel_id), ChannelState.OPEN)
    except ChannelStateError as exc:
        raise click.ClickException(str(exc)) from exc
    except KeystoreUnavailableError as exc:
        raise CliKeystoreError(str(exc)) from exc
    if output_json:
        emit_json_document(_channel_as_dict(ch))
    else:
        click.echo(f"Channel {channel_id} is now OPEN.")


@channel.command("suspend")
@click.argument("channel_id")
@click.pass_context
def suspend(ctx: click.Context, channel_id: str) -> None:
    """Suspend an OPEN channel. (CLI-01 / CHAN-02)"""
    output_json = ctx.obj["json"]
    _, store = _open_store(ctx)
    try:
        ch = store.transition_to(ChannelId(channel_id), ChannelState.SUSPENDED)
    except ChannelStateError as exc:
        raise click.ClickException(str(exc)) from exc
    except KeystoreUnavailableError as exc:
        raise CliKeystoreError(str(exc)) from exc
    if output_json:
        emit_json_document(_channel_as_dict(ch))
    else:
        click.echo(f"Channel {channel_id} is now SUSPENDED.")


@channel.command("close")
@click.argument("channel_id")
@click.pass_context
def close(ctx: click.Context, channel_id: str) -> None:
    """Permanently close a channel. (CLI-01 / CHAN-02)"""
    output_json = ctx.obj["json"]
    _, store = _open_store(ctx)
    try:
        ch = store.transition_to(ChannelId(channel_id), ChannelState.CLOSED)
    except ChannelStateError as exc:
        raise click.ClickException(str(exc)) from exc
    except KeystoreUnavailableError as exc:
        raise CliKeystoreError(str(exc)) from exc
    if output_json:
        emit_json_document(_channel_as_dict(ch))
    else:
        click.echo(f"Channel {channel_id} is now CLOSED.")


@channel.command("set-ceiling")
@click.argument("channel_id")
@click.argument("new_ceiling", type=click.Choice(["tier-0", "tier-1", "tier-2"]))
@click.pass_context
def set_ceiling(ctx: click.Context, channel_id: str, new_ceiling: str) -> None:
    """Change the trust ceiling of a channel (CHAN-03). (CLI-01)"""
    output_json = ctx.obj["json"]
    _, store = _open_store(ctx)
    try:
        ch = store.set_ceiling(ChannelId(channel_id), new_ceiling)
    except KeystoreUnavailableError as exc:
        raise CliKeystoreError(str(exc)) from exc
    if output_json:
        emit_json_document(_channel_as_dict(ch))
    else:
        click.echo(f"Channel {channel_id} ceiling is now {new_ceiling}.")
