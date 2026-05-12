"""Test CLI-06 / D-07: every photophore CLI subcommand emits one cli.invoked audit entry."""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from photophore.audit import AuditLog
from photophore.cli import photophore as photophore_cli


def _invoke(runner: CliRunner, data_dir: Path, *argv: str):
    return runner.invoke(
        photophore_cli,
        ["--data-dir", str(data_dir), *argv],
        catch_exceptions=False,
    )


def _cli_invoked_rows(data_dir: Path) -> list[dict]:
    """Return all cli.invoked audit entries from the user's audit.db."""
    log = AuditLog(data_dir / "audit.db")
    return [r for r in log._query_rows(event_type="cli.invoked")]


def test_audit_query_invocation_recorded(tmp_path):
    """`photophore audit query` produces one cli.invoked entry."""
    runner = CliRunner()
    result = _invoke(runner, tmp_path, "audit", "query")
    assert result.exit_code == 0, f"audit query failed: {result.output!r}"
    rows = _cli_invoked_rows(tmp_path)
    assert len(rows) == 1, f"expected 1 cli.invoked row; got {len(rows)}"
    payload = rows[0]["payload"]
    assert payload["subcommand"] == "audit.query"
    assert payload["outcome"] == "success"
    assert payload["exit_code"] == 0


def test_audit_export_invocation_recorded(tmp_path):
    """`photophore audit export` produces one cli.invoked entry."""
    runner = CliRunner()
    result = _invoke(runner, tmp_path, "audit", "export")
    assert result.exit_code == 0
    rows = _cli_invoked_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["payload"]["subcommand"] == "audit.export"


def test_audit_verify_invocation_recorded(tmp_path):
    """`photophore audit verify` produces one cli.invoked entry (empty chain = valid)."""
    runner = CliRunner()
    result = _invoke(runner, tmp_path, "audit", "verify")
    # Empty audit.db: chain is valid (head is empty string).
    assert result.exit_code == 0
    rows = _cli_invoked_rows(tmp_path)
    # The cli.invoked entry is itself the only entry, so there's 1 cli.invoked.
    assert len(rows) == 1
    assert rows[0]["payload"]["subcommand"] == "audit.verify"


def test_channel_list_invocation_recorded(tmp_path):
    """`photophore channel list` produces one cli.invoked entry."""
    runner = CliRunner()
    result = _invoke(runner, tmp_path, "channel", "list")
    assert result.exit_code == 0, f"channel list failed: {result.output!r}"
    rows = _cli_invoked_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["payload"]["subcommand"] == "channel.list"
