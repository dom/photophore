"""photophore audit subcommands: query | export | verify (CLI-02, AUDIT-05, AUDIT-06).

D-12 output modes:
  - audit query --json: JSON Lines (one entry per line)
  - audit export --json: JSON Lines (one entry per line, includes algo_version)
  - audit export (no --json): human-readable table (B6 fix — export must work without --json)
  - audit verify --json: single JSON document {"valid": true|false, "head"|"broken_at": ...}
  - audit verify (no --json): human-readable one-liner

D-14 exit codes:
  - 0: success (chain valid, or empty result set)
  - 3: audit chain integrity failure (AuditIntegrityError)
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click

from ..audit._store import AuditLog
from ._audit_decorator import audit_cli_invocation
from ._errors import AuditIntegrityError, KeystoreError
from ._format import emit_human_audit_entry, emit_human_audit_header, emit_json_document, emit_json_lines


@click.group("audit")
def audit() -> None:
    """Audit log operations — query, export, and verify chain integrity."""


@audit.command("query")
@audit_cli_invocation("audit.query")
@click.option("--channel", "channel_id", default=None, help="Filter by channel ID.")
@click.option("--envelope", "envelope_id", default=None, help="Filter by envelope ID.")
@click.option("--since", default=None, help="Filter by timestamp >= (ISO 8601).")
@click.option("--until", default=None, help="Filter by timestamp <= (ISO 8601).")
@click.option("--event-type", "event_type", default=None, help="Filter by event type.")
@click.option("--shadow-id", "shadow_id", default=None, help="Filter by shadow_id in payload.")
@click.option("--tier", default=None, help="Filter by tier in payload.")
@click.pass_context
def query(
    ctx: click.Context,
    channel_id: str | None,
    envelope_id: str | None,
    since: str | None,
    until: str | None,
    event_type: str | None,
    shadow_id: str | None,
    tier: str | None,
) -> None:
    """Query the audit log with optional filters.

    With --json: emits JSON Lines (one object per line, D-12).
    Without --json: emits a human-readable table.
    """
    audit_db = ctx.obj["audit_db"]
    output_json = ctx.obj["json"]

    # Ensure the audit.db parent directory exists.
    Path(audit_db).parent.mkdir(parents=True, exist_ok=True)

    log = AuditLog(audit_db)
    filters: dict[str, Any] = {}
    if channel_id is not None:
        filters["channel_id"] = channel_id
    if envelope_id is not None:
        filters["envelope_id"] = envelope_id
    if since is not None:
        filters["since"] = since
    if until is not None:
        filters["until"] = until
    if event_type is not None:
        filters["event_type"] = event_type
    if shadow_id is not None:
        filters["shadow_id"] = shadow_id
    if tier is not None:
        filters["tier"] = tier

    rows = list(log._query_rows(**filters))

    if output_json:
        emit_json_lines(rows)
    else:
        if rows:
            emit_human_audit_header()
            for row in rows:
                emit_human_audit_entry(row)


@audit.command("export")
@audit_cli_invocation("audit.export")
@click.pass_context
def export(ctx: click.Context) -> None:
    """Export the full audit log.

    With --json: JSON Lines (one entry per line, includes algo_version, AUDIT-06).
    Without --json: human-readable table with header (B6 / D-12 default = human-readable).
    """
    audit_db = ctx.obj["audit_db"]
    output_json = ctx.obj["json"]

    Path(audit_db).parent.mkdir(parents=True, exist_ok=True)
    log = AuditLog(audit_db)

    rows = list(log.export())
    if output_json:
        emit_json_lines(rows)
    else:
        emit_human_audit_header()  # B6: must emit header (table separator with |) without --json
        for row in rows:
            emit_human_audit_entry(row)


@audit.command("verify")
@audit_cli_invocation("audit.verify")
@click.pass_context
def verify(ctx: click.Context) -> None:
    """Verify audit log chain integrity (AUDIT-08).

    With --json:
      - valid chain: {"valid": true, "head": "<hex>"}
      - broken chain: {"valid": false, "broken_at": "<entry-id>"}

    Without --json:
      - valid: "chain valid; head=<hex>"
      - broken: "chain BROKEN at <entry-id>"

    Exit code 0 on valid, 3 on broken (D-14 AuditIntegrityError).
    """
    audit_db = ctx.obj["audit_db"]
    output_json = ctx.obj["json"]

    Path(audit_db).parent.mkdir(parents=True, exist_ok=True)
    log = AuditLog(audit_db)
    ok, detail = log.verify_chain()

    if ok:
        head_hex = detail or ""
        if output_json:
            emit_json_document({"valid": True, "head": head_hex})
        else:
            click.echo(f"chain valid; head={head_hex}")
    else:
        # Emit diagnostic BEFORE raising (so CI pipeline sees both stdout and exit code).
        if output_json:
            emit_json_document({"valid": False, "broken_at": detail})
        else:
            click.echo(f"chain BROKEN at {detail}", err=False)
        raise AuditIntegrityError(
            f"audit chain integrity check failed; first broken entry: {detail}"
        )
