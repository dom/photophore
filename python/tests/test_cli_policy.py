"""Tests for ``photophore policy preview`` CLI subcommand (CLI-05).

Uses CliRunner to exercise the full CLI surface including POLICY-01 visibility.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from photophore.cli import photophore

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    return tmp_path


def _create_channel(runner: CliRunner, data_dir: Path, ceiling: str = "tier-1") -> str:
    """Create a channel via CLI and return its channel_id."""
    result = runner.invoke(
        photophore,
        [
            "--json",
            "--data-dir",
            str(data_dir),
            "channel",
            "new",
            "--remote-node",
            "bob",
            "--ceiling",
            ceiling,
            "--key-scheme",
            "none",
        ],
    )
    assert result.exit_code == 0, (
        f"channel new failed (exit {result.exit_code}): {result.output}"
    )
    data = json.loads(result.output)
    return str(data["id"])


class TestPolicyPreviewHumanMode:
    def test_preview_tier1_human(
        self, runner: CliRunner, data_dir: Path
    ) -> None:
        """Human mode: shows authored policy fields."""
        channel_id = _create_channel(runner, data_dir, "tier-1")
        result = runner.invoke(
            photophore,
            [
                "--data-dir",
                str(data_dir),
                "policy",
                "preview",
                "--channel",
                channel_id,
                "--task",
                str(_FIXTURES / "task-draft.json"),
            ],
        )
        assert result.exit_code == 0, f"preview failed: {result.output}"
        assert "shadow_refs" in result.output

    def test_preview_shows_note_on_injected_policy(
        self, runner: CliRunner, data_dir: Path
    ) -> None:
        """Human mode: shows POLICY-01 note when draft has injected result_policy."""
        channel_id = _create_channel(runner, data_dir, "tier-2")
        result = runner.invoke(
            photophore,
            [
                "--data-dir",
                str(data_dir),
                "policy",
                "preview",
                "--channel",
                channel_id,
                "--task",
                str(_FIXTURES / "task-draft-with-injected-policy.json"),
            ],
        )
        assert result.exit_code == 0, f"preview failed: {result.output}"
        assert "IGNORED" in result.output or "POLICY-01" in result.output


class TestPolicyPreviewJsonMode:
    def test_preview_tier1_json(
        self, runner: CliRunner, data_dir: Path
    ) -> None:
        """JSON mode: emits single JSON document with ResultPolicy fields."""
        channel_id = _create_channel(runner, data_dir, "tier-1")
        result = runner.invoke(
            photophore,
            [
                "--json",
                "--data-dir",
                str(data_dir),
                "policy",
                "preview",
                "--channel",
                channel_id,
                "--task",
                str(_FIXTURES / "task-draft.json"),
            ],
        )
        assert result.exit_code == 0, f"preview failed: {result.output}"
        data = json.loads(result.output)
        assert "authored_policy" in data
        assert "persist_to_shared" in data["authored_policy"]
        assert "return_only" in data["authored_policy"]
        assert "strip_before_persist" in data["authored_policy"]
        assert "shadow_refs" in data["authored_policy"]["return_only"]

    def test_preview_tier0_json(
        self, runner: CliRunner, data_dir: Path
    ) -> None:
        """Tier-0 channel: strip_before_persist must contain '*'."""
        channel_id = _create_channel(runner, data_dir, "tier-0")
        result = runner.invoke(
            photophore,
            [
                "--json",
                "--data-dir",
                str(data_dir),
                "policy",
                "preview",
                "--channel",
                channel_id,
                "--task",
                str(_FIXTURES / "task-draft.json"),
            ],
        )
        assert result.exit_code == 0, f"preview failed: {result.output}"
        data = json.loads(result.output)
        assert "*" in data["authored_policy"]["strip_before_persist"]

    def test_preview_tier2_json(
        self, runner: CliRunner, data_dir: Path
    ) -> None:
        """Tier-2 channel (Plan 03-03): permissive template — empty
        persist_to_shared/return_only/strip_before_persist."""
        channel_id = _create_channel(runner, data_dir, "tier-2")
        result = runner.invoke(
            photophore,
            [
                "--json",
                "--data-dir",
                str(data_dir),
                "policy",
                "preview",
                "--channel",
                channel_id,
                "--task",
                str(_FIXTURES / "task-draft.json"),
            ],
        )
        assert result.exit_code == 0, f"preview failed: {result.output}"
        data = json.loads(result.output)
        assert data["authored_policy"]["persist_to_shared"] == []
        assert data["authored_policy"]["return_only"] == []
        assert data["authored_policy"]["strip_before_persist"] == []

    def test_preview_injected_policy_ignored_visible_in_json(
        self, runner: CliRunner, data_dir: Path
    ) -> None:
        """POLICY-01: draft_policy_ignored=True in JSON output when draft has result_policy."""
        channel_id = _create_channel(runner, data_dir, "tier-2")
        result = runner.invoke(
            photophore,
            [
                "--json",
                "--data-dir",
                str(data_dir),
                "policy",
                "preview",
                "--channel",
                channel_id,
                "--task",
                str(_FIXTURES / "task-draft-with-injected-policy.json"),
            ],
        )
        assert result.exit_code == 0, f"preview failed: {result.output}"
        data = json.loads(result.output)
        assert data.get("draft_policy_ignored") is True
        # Authored policy differs from the injected one (POLICY-01)
        assert data["authored_policy"]["persist_to_shared"] != ["EVERYTHING"]

    def test_preview_includes_channel_id_and_ceiling(
        self, runner: CliRunner, data_dir: Path
    ) -> None:
        """JSON output includes channel_id and channel_ceiling."""
        channel_id = _create_channel(runner, data_dir, "tier-1")
        result = runner.invoke(
            photophore,
            [
                "--json",
                "--data-dir",
                str(data_dir),
                "policy",
                "preview",
                "--channel",
                channel_id,
                "--task",
                str(_FIXTURES / "task-draft.json"),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["channel_id"] == channel_id
        assert data["channel_ceiling"] == "tier-1"


class TestPolicyPreviewErrorCases:
    def test_unknown_channel_exits_5(
        self, runner: CliRunner, data_dir: Path
    ) -> None:
        """Unknown channel_id exits with code 5 (KeystoreError)."""
        result = runner.invoke(
            photophore,
            [
                "--data-dir",
                str(data_dir),
                "policy",
                "preview",
                "--channel",
                "00000000-0000-4000-8000-999999999999",
                "--task",
                str(_FIXTURES / "task-draft.json"),
            ],
        )
        assert result.exit_code == 5, f"Expected exit 5, got {result.exit_code}: {result.output}"

    def test_missing_task_file_exits_nonzero(
        self, runner: CliRunner, data_dir: Path
    ) -> None:
        """Non-existent task file causes click to exit with a non-zero code."""
        channel_id = _create_channel(runner, data_dir, "tier-1")
        result = runner.invoke(
            photophore,
            [
                "--data-dir",
                str(data_dir),
                "policy",
                "preview",
                "--channel",
                channel_id,
                "--task",
                "/nonexistent/path/to/draft.json",
            ],
        )
        assert result.exit_code != 0


class TestPolicyPreviewHelp:
    def test_help_exits_0(self, runner: CliRunner) -> None:
        result = runner.invoke(photophore, ["policy", "preview", "--help"])
        assert result.exit_code == 0
        assert "preview" in result.output.lower() or "policy" in result.output.lower()
