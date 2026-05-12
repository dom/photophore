"""CLI-06 (D-07): @audit_cli_invocation decorator + _sanitize_args helper.

Wraps a click leaf command so each invocation produces exactly one
`cli.invoked` audit entry in the user's audit.db. Args containing file paths
are hashed (BLAKE3 — matches audit chain hash family) before being recorded.

Decorator order (Pitfall 6):
    @<group>.command("name")          # outermost — click command registration
    @audit_cli_invocation("group.name")  # our wrapper
    @click.option(...)                # any number of click options
    @click.pass_context               # innermost
    def name(ctx, ...) -> None:
        ...

The audit write is best-effort: failure to write does NOT change the
subcommand's exit code (D-07).
"""
from __future__ import annotations

import functools
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

import blake3
import click

from ..audit._cli_invocation import append_cli_invocation
from ..audit._store import AuditLog

__all__ = ["audit_cli_invocation", "_sanitize_args"]


def _utcnow_ms() -> str:
    """Current UTC time at millisecond precision as ISO-Z string."""
    return (
        datetime.now(tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _strict_after(prev_ts: str) -> str:
    """Return a ms-precision UTC ISO-Z string strictly greater than ``prev_ts``.

    Used to ensure the cli.invoked audit entry sorts AFTER any prior audit
    writes the wrapped subcommand made, even when those writes happen in the
    same millisecond. The audit-log's verify_chain walks in
    `ORDER BY timestamp ASC, id ASC`, so chain integrity requires
    monotonic-or-strictly-later timestamps.
    """
    now = _utcnow_ms()
    if prev_ts and now <= prev_ts:
        # Parse the prev timestamp and add 1 ms.
        prev = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
        bumped = prev + timedelta(milliseconds=1)
        return bumped.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return now


F = TypeVar("F", bound=Callable[..., Any])


# Args names whose VALUE is treated as a path to a file whose content must
# be hashed rather than recorded verbatim. Extend this list when adding new
# subcommands that take file-path arguments. The matching is on click's
# parameter name (after rewrites like ``--task -> task``).
_FILE_PATH_ARG_NAMES: frozenset[str] = frozenset({
    "task",
    "task_path",
    "rules",
    "rules_path",
    "policy",
    "policy_path",
    "envelope_path",
    "config",
    "config_path",
    "path",  # generic `classify <path>` argument
})


def _sanitize_args(params: dict[str, Any]) -> dict[str, Any]:
    """Sanitize click ctx.params for audit recording.

    Transformations:
    - File-path values: replaced with ``"blake3:<hex>"`` of file content
      (BLAKE3 32-byte hex). Missing files become ``"blake3:<missing>"``.
    - bytes values: replaced with ``"<bytes-omitted>"`` (never serialize raw
      bytes to JSON via the audit chain).
    - None / bool / int / float / str: passed through.
    - Other types: ``repr()`` stringified to keep the payload JSON-safe.

    Non-secret identifiers (channel_id, envelope_id, --json flag, etc.) pass
    through verbatim.
    """
    out: dict[str, Any] = {}
    for k, v in params.items():
        if v is None:
            out[k] = None
            continue
        if isinstance(v, bool):
            out[k] = v
            continue
        if isinstance(v, (int, float)):
            out[k] = v
            continue
        if isinstance(v, bytes):
            out[k] = "<bytes-omitted>"
            continue
        if isinstance(v, str) and k in _FILE_PATH_ARG_NAMES:
            try:
                content = Path(v).read_bytes()
                hex_digest = blake3.blake3(content).hexdigest()
                out[k] = f"blake3:{hex_digest}"
            except (OSError, IOError):
                out[k] = "blake3:<missing>"
            continue
        if isinstance(v, str):
            out[k] = v
            continue
        # Fallback: stringify anything else (avoid leaking arbitrary objects
        # into the audit payload).
        out[k] = repr(v)
    return out


def audit_cli_invocation(subcommand: str) -> Callable[[F], F]:
    """Decorator factory: wrap a click leaf command with cli.invoked audit emit.

    Args:
        subcommand: dotted subcommand name (e.g. ``"audit.query"``,
            ``"channel.new"``, ``"dispatch"``).

    Behavior:
        On invocation, captures the start timestamp. After the wrapped
        function returns (or raises), opens the user's audit.db (path from
        ``ctx.obj["audit_db"]``) and appends one ``cli.invoked`` entry with
        outcome="success" + exit_code=0 on clean return, or outcome="failure"
        + exit_code=<code> on SystemExit. Any other exception is re-raised
        AFTER the audit write attempt.

        The audit write itself is wrapped in a try/except; failure to write
        does NOT alter the user's exit code (D-07 best-effort guarantee).
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx = click.get_current_context()
            sanitized_args = _sanitize_args(dict(ctx.params))
            outcome = "success"
            exit_code = 0
            exc_to_reraise: BaseException | None = None
            try:
                result = func(*args, **kwargs)
            except SystemExit as exc:
                outcome = "failure"
                exit_code = int(exc.code) if isinstance(exc.code, int) else 1
                exc_to_reraise = exc
                result = None
            except BaseException as exc:  # pragma: no cover (re-raised below)
                outcome = "failure"
                exit_code = 1
                exc_to_reraise = exc
                result = None
            # Best-effort audit write. Failure here MUST NOT mask the user's
            # actual exit code or exception.
            #
            # Timestamp policy: capture ts AFTER the wrapped function returns
            # AND strictly greater than the most recent audit entry, so
            # cli.invoked sorts after any prior writes the subcommand made.
            # This preserves verify_chain ordering across same-millisecond
            # writes.
            audit_db_path = ctx.obj.get("audit_db") if ctx.obj else None
            if audit_db_path:
                try:
                    Path(audit_db_path).parent.mkdir(parents=True, exist_ok=True)
                    audit_log = AuditLog(audit_db_path)
                    # Fetch the most recent entry's timestamp, then build a
                    # strictly-later one.
                    rows = list(audit_log._query_rows())
                    prev_ts = str(rows[-1]["timestamp"]) if rows else ""
                    end_ts = _strict_after(prev_ts)
                    append_cli_invocation(
                        audit_log,
                        subcommand=subcommand,
                        args=sanitized_args,
                        outcome=outcome,
                        exit_code=exit_code,
                        ts=end_ts,
                    )
                except Exception:
                    # Audit-write failure is best-effort; do not mask the
                    # user's actual exit code (D-07).
                    pass
            if exc_to_reraise is not None:
                raise exc_to_reraise
            return result

        return wrapper  # type: ignore[return-value]
    return decorator
