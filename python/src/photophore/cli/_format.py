"""Output formatting helpers for the photophore CLI (D-12).

Three formatting modes:
- emit_json_document(obj): single JSON document (all non-audit-query commands)
- emit_json_lines(items): one JSON object per line (audit query + export, D-12 twist)
- emit_human_channel(channel_dict): multi-line human-readable for channel list/show
- emit_human_table(headers, rows): generic table for non-JSON output

D-12 summary:
  - audit query + audit export under --json: JSON Lines (one object per line)
  - all other commands under --json: single JSON document
  - default (no --json): human-readable
"""
from __future__ import annotations

import json
from typing import Any, Iterable

import click

__all__ = [
    "emit_json_document",
    "emit_json_lines",
    "emit_human_channel",
    "emit_human_audit_entry",
]


def emit_json_document(obj: Any) -> None:
    """Emit a single JSON document to stdout (all non-audit-query --json mode)."""
    click.echo(json.dumps(obj, indent=2, sort_keys=True))


def emit_json_lines(items: Iterable[Any]) -> None:
    """Emit one JSON object per line (audit query + export --json mode, D-12)."""
    for item in items:
        click.echo(json.dumps(item, sort_keys=True))


def emit_human_channel(ch: dict[str, Any]) -> None:
    """Emit a human-readable multi-line channel record."""
    click.echo(f"Channel:  {ch.get('id', '?')}")
    click.echo(f"  Remote: {ch.get('remote_node', '?')}")
    click.echo(f"  Local:  {ch.get('local_node', '?')}")
    click.echo(f"  State:  {ch.get('state', '?')}")
    click.echo(f"  Ceiling:{ch.get('ceiling', '?')}")
    click.echo(f"  Scheme: {ch.get('key_scheme', '?')}")
    if ch.get("description"):
        click.echo(f"  Desc:   {ch['description']}")


def emit_human_audit_entry(row: dict[str, Any]) -> None:
    """Emit a human-readable single audit entry line."""
    ts = str(row.get("timestamp", ""))[:23]  # trim to milliseconds
    eid = str(row.get("id", ""))[:8]
    eh = str(row.get("entry_hash", ""))[:8]
    et = str(row.get("event_type", ""))
    cid = str(row.get("channel_id") or "")[:8]
    click.echo(f"{ts} | {et:28s} | {cid:8s} | {eh:8s} | {eid}")


def emit_human_audit_header() -> None:
    """Emit the human-readable table header for audit query/export (B6 / D-12)."""
    click.echo(
        f"{'timestamp':23s} | {'event_type':28s} | {'channel':8s} | {'hash':8s} | {'id':8s}"
    )
    click.echo("-" * 90)
