"""Task 3 dispatch CLI tests (CLI-03, D-03, D-14 exit code 6).

Tests verify:
  - exit 0 on happy path; --json emits the spec-shape document
  - exit 6 on CHANNEL_RESOLVE_FAILED with the human-mode "error: dispatch failed
    (CHANNEL_RESOLVE_FAILED) at step 1: ..." prefix
  - exit 6 on RECEIPT_INVALID with JSON body shape per CONTEXT D-03
  - exit 6 on POLICY_VIOLATED with retryable=false
  - exit 6 on AUDIT_FAILED_PRE with retryable=true
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from photophore.audit import AuditLog
from photophore.channels import ChannelStore
from photophore.channels._store import _channel_to_dict, _upsert_channels_db_raw
from photophore.channels._keystore import _set_channel
from photophore.channels._index import add_to_index
from photophore.channels._types import Channel
from photophore.cli import photophore
from photophore.core import ChannelId, ChannelState
from photophore.dispatch import DispatchError, DispatchOutcome, DispatchSubcode


def _seed_channel(tmp_path: Path, channel_id: str, *,
                  key_scheme: str = "brine",
                  ceiling: str = "tier-2",
                  state: ChannelState = ChannelState.OPEN) -> tuple[str, str]:
    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    chan = Channel(
        id=ChannelId(channel_id),
        local_node="alice-node",
        remote_node="pi-forge",
        ceiling=ceiling,
        key_scheme=key_scheme,
        state=state,
        created_at="2026-05-11T00:00:00.000Z",
        creator_identity="test",
        description="",
        remote_pubkey_hex=None,
    )
    _set_channel(ChannelId(channel_id), _channel_to_dict(chan))
    add_to_index(ChannelId(channel_id))
    _upsert_channels_db_raw(store._conn, chan)  # type: ignore[attr-defined]
    return str(tmp_path / "audit.db"), str(tmp_path / "channels.db")


def _write_draft(tmp_path: Path, channel_id: str = "chan-1",
                 envelope_id: str = "env-1") -> Path:
    draft: dict[str, Any] = {
        "thermocline": "0.3.1",
        "type": "task",
        "envelope_id": envelope_id,
        "issued_at": "2026-05-11T00:00:00Z",
        "issuer": "alice-node",
        "recipient": "pi-forge",
        "channel_id": channel_id,
        "key_scheme": "brine",
        "task": {"type": "data.compute", "instruction": "noop"},
        "context": [],
        "output_contract": {"format": "text/plain"},
        "dispatch_signature": {"key_scheme": "brine"},
    }
    p = tmp_path / "draft.json"
    p.write_text(json.dumps(draft))
    return p


def _ok_outcome() -> DispatchOutcome:
    return DispatchOutcome(
        envelope_id="env-1",
        receipt_signature_hash="ab" * 32,
        pre_audit_hash="cd" * 16,
        post_audit_hash="ef" * 16,
        warnings=(),
        result_body={"outputs": {"answer": "ok"}},
    )


def test_dispatch_success_human(tmp_path: Path, in_memory_keyring: object) -> None:
    _seed_channel(tmp_path, "chan-1")
    draft = _write_draft(tmp_path)
    runner = CliRunner()
    with patch("photophore.cli.dispatch_cmds.asyncio.run",
               return_value=_ok_outcome()):
        result = runner.invoke(
            photophore,
            ["--data-dir", str(tmp_path),
             "dispatch",
             "--channel", "chan-1",
             "--task", str(draft),
             "--forge-url", "http://localhost:5000/task"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0, f"output={result.output!r}"
    assert "dispatch ok" in result.output
    assert "envelope_id=env-1" in result.output
    assert "receipt_sig=" in result.output


def test_dispatch_success_json(tmp_path: Path, in_memory_keyring: object) -> None:
    _seed_channel(tmp_path, "chan-1")
    draft = _write_draft(tmp_path)
    runner = CliRunner()
    with patch("photophore.cli.dispatch_cmds.asyncio.run",
               return_value=_ok_outcome()):
        result = runner.invoke(
            photophore,
            ["--json", "--data-dir", str(tmp_path),
             "dispatch",
             "--channel", "chan-1",
             "--task", str(draft),
             "--forge-url", "http://localhost:5000/task"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0, f"output={result.output!r}"
    doc = json.loads(result.output)
    assert doc["envelope_id"] == "env-1"
    assert doc["receipt_signature_hash"]
    assert doc["pre_audit_hash"]
    assert doc["post_audit_hash"]


def test_dispatch_channel_resolve_failed_exits_6(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """Unknown channel → exit 6, human "error: dispatch failed (CHANNEL_RESOLVE_FAILED) at step 1"."""
    # No channel seeded; the coordinator will hit the channel-not-found path.
    draft = _write_draft(tmp_path, channel_id="no-such")
    runner = CliRunner()
    err = DispatchError(
        "no such channel",
        subcode=DispatchSubcode.CHANNEL_RESOLVE_FAILED, stage=1,
        channel_id="no-such",
    )
    with patch("photophore.cli.dispatch_cmds.asyncio.run", side_effect=err):
        result = runner.invoke(
            photophore,
            ["--data-dir", str(tmp_path),
             "dispatch",
             "--channel", "no-such",
             "--task", str(draft),
             "--forge-url", "http://localhost:5000/task"],
            catch_exceptions=False,
        )
    assert result.exit_code == 6, f"output={result.output!r}"
    assert "error: dispatch failed (CHANNEL_RESOLVE_FAILED)" in result.output
    assert "step 1" in result.output


def test_dispatch_receipt_invalid_exits_6_json(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """Forged-receipt path → exit 6 with the CONTEXT D-03 JSON body shape."""
    _seed_channel(tmp_path, "chan-1")
    draft = _write_draft(tmp_path)
    runner = CliRunner()
    err = DispatchError(
        "sig verify failed",
        subcode=DispatchSubcode.RECEIPT_INVALID, stage=8,
        envelope_id="env-1", channel_id="chan-1",
        audit_entry_hash="ab" * 16,
    )
    with patch("photophore.cli.dispatch_cmds.asyncio.run", side_effect=err):
        result = runner.invoke(
            photophore,
            ["--json", "--data-dir", str(tmp_path),
             "dispatch",
             "--channel", "chan-1",
             "--task", str(draft),
             "--forge-url", "http://localhost:5000/task"],
            catch_exceptions=False,
        )
    assert result.exit_code == 6, f"output={result.output!r}"
    body = json.loads(result.output)
    assert body["error"] == "DispatchError"
    assert body["subcode"] == "RECEIPT_INVALID"
    assert body["stage"] == 8
    assert body["retryable"] is False
    assert body["audit_entry_hash"] == "ab" * 16


def test_dispatch_policy_violated_exits_6(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    _seed_channel(tmp_path, "chan-1")
    draft = _write_draft(tmp_path)
    runner = CliRunner()
    err = DispatchError(
        "policy violation",
        subcode=DispatchSubcode.POLICY_VIOLATED, stage=8,
        envelope_id="env-1", channel_id="chan-1",
    )
    with patch("photophore.cli.dispatch_cmds.asyncio.run", side_effect=err):
        result = runner.invoke(
            photophore,
            ["--data-dir", str(tmp_path),
             "dispatch",
             "--channel", "chan-1",
             "--task", str(draft),
             "--forge-url", "http://localhost:5000/task"],
            catch_exceptions=False,
        )
    assert result.exit_code == 6
    assert "POLICY_VIOLATED" in result.output
    assert "retryable: false" in result.output


def test_dispatch_audit_failed_pre_retryable_true(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    _seed_channel(tmp_path, "chan-1")
    draft = _write_draft(tmp_path)
    runner = CliRunner()
    err = DispatchError(
        "audit poisoned",
        subcode=DispatchSubcode.AUDIT_FAILED_PRE, stage=5,
        envelope_id="env-1", channel_id="chan-1",
    )
    with patch("photophore.cli.dispatch_cmds.asyncio.run", side_effect=err):
        result = runner.invoke(
            photophore,
            ["--json", "--data-dir", str(tmp_path),
             "dispatch",
             "--channel", "chan-1",
             "--task", str(draft),
             "--forge-url", "http://localhost:5000/task"],
            catch_exceptions=False,
        )
    assert result.exit_code == 6
    body = json.loads(result.output)
    assert body["subcode"] == "AUDIT_FAILED_PRE"
    assert body["retryable"] is True


def test_dispatch_help_lists_options(tmp_path: Path) -> None:
    """`photophore dispatch --help` exits 0 and mentions --channel, --task, --forge-url."""
    runner = CliRunner()
    result = runner.invoke(photophore, ["dispatch", "--help"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "--channel" in result.output
    assert "--task" in result.output
    assert "--forge-url" in result.output
