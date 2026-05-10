"""Test photophore channel CLI subcommands (CLI-01, CHAN-02, CHAN-03, CHAN-06, D-12).

Tests verify:
- channel new exits 0, returns JSON with id/remote_node/ceiling/state
- channel list --json returns JSON array
- channel show <id> --json returns single JSON object
- channel new -> suspend raises error (PROPOSED->SUSPENDED invalid)
- full lifecycle PROPOSED->OPEN->SUSPENDED->CLOSED all exit 0
- set-ceiling lower produces ceiling_lowered audit event (CHAN-03)
- set-ceiling raise produces ceiling_raised audit event (CHAN-03)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from photophore.cli import photophore
from photophore.core import AuditEventType


def _new_channel(runner: CliRunner, data_dir: str, remote: str = "bob",
                 ceiling: str = "tier-1") -> str:
    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", data_dir, "channel", "new",
         "--remote-node", remote, "--ceiling", ceiling, "--key-scheme", "brine"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, f"channel new failed: {result.output}"
    return str(json.loads(result.output)["id"])


def test_channel_new_exits_0_with_json(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """CLI-01: channel new --json exits 0 with id/remote_node/ceiling/state fields."""
    runner = CliRunner()
    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", str(tmp_path), "channel", "new",
         "--remote-node", "bob", "--ceiling", "tier-1", "--key-scheme", "brine"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    doc = json.loads(result.output)
    assert "id" in doc
    assert doc["remote_node"] == "bob"
    assert doc["ceiling"] == "tier-1"
    assert doc["state"] == "PROPOSED"


def test_channel_list_json_returns_array(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """CHAN-06: channel list --json returns a JSON array."""
    runner = CliRunner()
    data_dir = str(tmp_path)
    _new_channel(runner, data_dir)
    _new_channel(runner, data_dir, remote="carol")

    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", data_dir, "channel", "list"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    arr = json.loads(result.output)
    assert isinstance(arr, list)
    assert len(arr) == 2


def test_channel_show_json_returns_single_document(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """CHAN-06: channel show <id> --json returns a single JSON document."""
    runner = CliRunner()
    data_dir = str(tmp_path)
    ch_id = _new_channel(runner, data_dir)

    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", data_dir, "channel", "show", ch_id],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    doc = json.loads(result.output)
    assert doc["id"] == ch_id


def test_channel_suspend_from_proposed_fails(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """CHAN-02: PROPOSED->SUSPENDED is invalid; CLI exits non-zero with error message."""
    runner = CliRunner()
    data_dir = str(tmp_path)
    ch_id = _new_channel(runner, data_dir)

    result = runner.invoke(
        photophore,
        ["--data-dir", data_dir, "channel", "suspend", ch_id],
        catch_exceptions=True,
    )
    assert result.exit_code != 0
    # Error message must mention "invalid transition"
    assert "invalid transition" in result.output.lower() or \
           "invalid transition" in (result.exception and str(result.exception)).lower()


def test_channel_full_lifecycle(tmp_path: Path, in_memory_keyring: object) -> None:
    """CHAN-02: PROPOSED->OPEN->SUSPENDED->CLOSED all succeed with exit 0."""
    runner = CliRunner()
    data_dir = str(tmp_path)
    ch_id = _new_channel(runner, data_dir)

    for subcommand in ["open", "suspend", "close"]:
        result = runner.invoke(
            photophore,
            ["--data-dir", data_dir, "channel", subcommand, ch_id],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, f"{subcommand} failed: {result.output}"


def test_channel_set_ceiling_lower_produces_audit_event(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """CHAN-03: set-ceiling lower -> channel.ceiling_lowered audit event."""
    from photophore.audit import AuditLog
    runner = CliRunner()
    data_dir = str(tmp_path)
    ch_id = _new_channel(runner, data_dir, ceiling="tier-1")

    result = runner.invoke(
        photophore,
        ["--data-dir", data_dir, "channel", "set-ceiling", ch_id, "tier-0"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0

    # Verify audit event via AuditLog
    log = AuditLog(tmp_path / "audit.db")
    events = log.query(channel_id=ch_id, event_type=AuditEventType.CHANNEL_CEILING_LOWERED)
    assert len(events) == 1


def test_channel_set_ceiling_raise_produces_distinct_audit_event(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """CHAN-03: set-ceiling raise -> DISTINCT channel.ceiling_raised audit event."""
    from photophore.audit import AuditLog
    runner = CliRunner()
    data_dir = str(tmp_path)
    ch_id = _new_channel(runner, data_dir, ceiling="tier-0")

    result = runner.invoke(
        photophore,
        ["--data-dir", data_dir, "channel", "set-ceiling", ch_id, "tier-2"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0

    log = AuditLog(tmp_path / "audit.db")
    events = log.query(channel_id=ch_id, event_type=AuditEventType.CHANNEL_CEILING_RAISED)
    assert len(events) == 1
    assert events[0].payload["from_ceiling"] == "tier-0"
    assert events[0].payload["to_ceiling"] == "tier-2"
