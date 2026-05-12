"""CLI-06 (D-07): helper for emitting cli.invoked audit entries.

Each photophore subcommand invocation produces exactly one ``cli.invoked``
audit entry recording the (subcommand, args, outcome, exit_code, ts) tuple.

Args sanitization (D-07):
    File-path args are recorded as ``blake3:<hex>`` of the file's CONTENT at
    invocation time. The hash provides correlation across audit entries
    (same envelope -> same chain) without retaining content.

    The hash family matches the audit chain (BLAKE3), so cross-audit
    correlation is consistent.

The audit-write itself is best-effort: failure to write an audit entry does
NOT change the subcommand's exit code. The user's command result is what
they see.
"""
from __future__ import annotations

from typing import Any

from ..core import AuditEventType
from ._store import AuditLog
from ._types import AuditEntry

__all__ = ["append_cli_invocation"]


def append_cli_invocation(
    audit_log: AuditLog,
    *,
    subcommand: str,
    args: dict[str, Any],
    outcome: str,
    exit_code: int,
    ts: str,
) -> AuditEntry:
    """Record a CLI subcommand invocation (CLI-06 / D-07).

    Args:
        audit_log: open AuditLog instance writing to the user's audit.db.
        subcommand: dotted subcommand name, e.g. ``"audit.query"`` or ``"dispatch"``.
        args: pre-sanitized dict of args; values that are file paths MUST be
            already replaced with ``"blake3:<hex>"`` by the caller (the
            ``_sanitize_args`` helper in cli/_audit_decorator.py).
        outcome: ``"success"`` (exit 0) or ``"failure"`` (any non-zero exit).
        exit_code: process exit code (0 on success, 1-N on various error
            classes per D-14 exit code policy).
        ts: ISO8601-UTC timestamp captured at subcommand entry (BEFORE the
            command body runs), so the audit trail reflects when the user
            invoked the command, not when the audit write happened.

    Returns:
        The committed AuditEntry.

    payload schema:
        {
          "subcommand": <str>,
          "args": <dict[str, str]>,
          "outcome": "success" | "failure",
          "exit_code": <int>,
        }
    """
    return audit_log.append(
        event_type=AuditEventType.CLI_INVOKED,
        channel_id=None,
        envelope_id=None,
        payload={
            "subcommand": subcommand,
            "args": args,
            "outcome": outcome,
            "exit_code": exit_code,
        },
        timestamp=ts,
    )
