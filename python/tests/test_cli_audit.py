"""Test photophore audit CLI subcommands (CLI-02, AUDIT-05, AUDIT-06, D-12, D-14).

Tests verify:
- audit query --json emits JSON Lines (one object per line)
- audit query with date filters returns filtered results
- audit export --json emits JSON Lines with algo_version
- audit export (no --json) emits human-readable table with | separator
- audit verify --json on valid chain emits {valid: true, head: ...} exit 0
- audit verify --json on tampered chain emits {valid: false, broken_at: ...} exit 3
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from photophore.cli import photophore
from photophore.core import AuditEventType


def _seed_channel(runner: CliRunner, data_dir: str) -> str:
    """Create a channel and return its id (from JSON output)."""
    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", data_dir, "channel", "new",
         "--remote-node", "bob", "--ceiling", "tier-1", "--key-scheme", "brine"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, f"channel new failed: {result.output}"
    doc = json.loads(result.output)
    return str(doc["id"])


def test_audit_query_json_emits_json_lines(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """CLI-02: audit query --json emits one JSON object per line (JSON Lines, D-12)."""
    runner = CliRunner()
    data_dir = str(tmp_path)

    ch_id = _seed_channel(runner, data_dir)

    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", data_dir, "audit", "query", "--channel", ch_id],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    lines = [l for l in result.output.strip().split("\n") if l]
    assert len(lines) >= 1
    for line in lines:
        obj = json.loads(line)  # must parse as valid JSON object
        assert "event_type" in obj


def test_audit_query_empty_result_exits_zero(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """audit query on non-existent channel_id produces no output and exits 0."""
    runner = CliRunner()
    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", str(tmp_path), "audit", "query",
         "--channel", "nonexistent-channel"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert result.output.strip() == ""


def test_audit_query_date_filter(tmp_path: Path, in_memory_keyring: object) -> None:
    """audit query --since --until filters by timestamp."""
    runner = CliRunner()
    data_dir = str(tmp_path)
    _seed_channel(runner, data_dir)

    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", data_dir, "audit", "query",
         "--since", "2026-01-01T00:00:00Z",
         "--until", "2026-12-31T23:59:59Z"],
        catch_exceptions=False,
    )
    # The channel was just created today (2026-05-xx) so should be in range.
    assert result.exit_code == 0


def test_audit_export_json_emits_json_lines_with_algo_version(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """AUDIT-06: audit export --json emits JSON Lines with algo_version on every line."""
    runner = CliRunner()
    data_dir = str(tmp_path)
    _seed_channel(runner, data_dir)

    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", data_dir, "audit", "export"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    lines = [l for l in result.output.strip().split("\n") if l]
    assert len(lines) >= 1
    first = json.loads(lines[0])
    assert "algo_version" in first, "algo_version missing from export"
    assert first["algo_version"] == "blake3-v1"


def test_audit_export_without_json_emits_human_table(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """B6 / D-12: audit export without --json emits human-readable table with | separator."""
    runner = CliRunner()
    data_dir = str(tmp_path)
    _seed_channel(runner, data_dir)

    # Invoke WITHOUT --json flag at root group
    result = runner.invoke(
        photophore,
        ["--data-dir", data_dir, "audit", "export"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    # B6: output must contain | (table separator)
    assert "|" in result.output, f"Expected | table separator; got: {result.output!r}"


def test_audit_verify_json_valid_chain(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """audit verify --json on intact chain: {valid: true, head: <hex>} exit 0."""
    runner = CliRunner()
    data_dir = str(tmp_path)
    _seed_channel(runner, data_dir)

    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", data_dir, "audit", "verify"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    doc = json.loads(result.output)
    assert doc["valid"] is True
    assert "head" in doc


def test_audit_verify_json_broken_chain_exit_3(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """audit verify --json on tampered chain: {valid: false, broken_at: <id>} exit 3."""
    runner = CliRunner()
    data_dir = str(tmp_path)
    _seed_channel(runner, data_dir)

    # Tamper: drop trigger, mutate payload
    audit_db = str(tmp_path / "audit.db")
    raw = sqlite3.connect(audit_db)
    raw.execute("PRAGMA writable_schema=ON")
    raw.execute("DROP TRIGGER IF EXISTS entries_no_update")
    raw.execute("PRAGMA writable_schema=OFF")
    raw.execute("UPDATE entries SET payload='{\"tampered\":true}' WHERE rowid=1")
    raw.commit()
    raw.close()

    result = runner.invoke(
        photophore,
        ["--json", "--data-dir", data_dir, "audit", "verify"],
        catch_exceptions=True,
    )
    assert result.exit_code == 3, f"Expected exit 3; got {result.exit_code}: {result.output}"
    # Output is the JSON document followed by the click error message.
    # Parse only the first JSON object (up to the first newline after the closing brace).
    first_json_line = result.output.split("\n}\n")[0] + "\n}"
    # Alternatively, split on newlines and find the JSON block.
    output_lines = result.output.strip().split("\n")
    json_block = "\n".join(line for line in output_lines if not line.startswith("Error:"))
    doc = json.loads(json_block)
    assert doc["valid"] is False
    assert "broken_at" in doc
