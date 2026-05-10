"""Tests for `photophore classify` CLI subcommand (Task 4, CLI-04)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from photophore.cli import photophore

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def rules_valid() -> Path:
    return FIXTURES / "rules-valid.yaml"


@pytest.fixture()
def rules_no_catchall() -> Path:
    return FIXTURES / "rules-no-catchall.yaml"


@pytest.fixture()
def rules_malformed() -> Path:
    return FIXTURES / "rules-malformed.yaml"


@pytest.fixture()
def tmp_file(tmp_path: Path) -> Path:
    """A simple text file with no special content."""
    f = tmp_path / "notes.txt"
    f.write_text("hello world\n")
    return f


@pytest.fixture()
def tmp_env_file(tmp_path: Path) -> Path:
    """A .env file with sensitive content."""
    f = tmp_path / ".env"
    f.write_text("DATABASE_URL=postgres://user:pass@host\n")
    return f


@pytest.fixture()
def tmp_dir(tmp_path: Path, rules_valid: Path) -> Path:
    """A directory with multiple files for directory walk testing."""
    d = tmp_path / "myproject"
    d.mkdir()
    (d / "notes.txt").write_text("hello world")
    (d / ".env").write_text("SECRET=supersecretvalue")
    docs = d / "docs"
    docs.mkdir()
    (docs / "guide.md").write_text("# Guide")
    return d


# ---------------------------------------------------------------------------
# Single file: human-readable output


def test_classify_single_file_human(runner: CliRunner, tmp_file: Path, rules_valid: Path) -> None:
    """classify <file> --rules <valid> emits human-readable (tier, reason) line, exits 0."""
    result = runner.invoke(photophore, ["classify", str(tmp_file), "--rules", str(rules_valid)])
    assert result.exit_code == 0, f"Unexpected exit: {result.output!r}"
    assert "(local," in result.output or ", classifier:default)" in result.output


# ---------------------------------------------------------------------------
# Single file: --json output (single JSON document, D-12)


def test_classify_single_file_json(runner: CliRunner, tmp_file: Path, rules_valid: Path) -> None:
    """classify <file> --rules <valid> --json emits single JSON document, exits 0."""
    result = runner.invoke(photophore, ["--json", "classify", str(tmp_file), "--rules", str(rules_valid)])
    assert result.exit_code == 0, f"Unexpected exit: {result.output!r}"
    doc = json.loads(result.output.strip())
    assert "path" in doc
    assert "tier" in doc
    assert "reason" in doc


def test_classify_single_file_json_tier_local(runner: CliRunner, tmp_file: Path, rules_valid: Path) -> None:
    """Untagged harmless file classifies as local."""
    result = runner.invoke(photophore, ["--json", "classify", str(tmp_file), "--rules", str(rules_valid)])
    assert result.exit_code == 0
    doc = json.loads(result.output.strip())
    assert doc["tier"] == "local"


# ---------------------------------------------------------------------------
# Single file: explicit-tag wins over path rule (AT-A3 via CLI)


def test_classify_explicit_tag_wins_via_cli(runner: CliRunner, tmp_path: Path, rules_valid: Path) -> None:
    """@photophore:public in .env file -> tier=public, reason=explicit_tag (CLASS-01 priority via CLI)."""
    env_file = tmp_path / ".env"
    env_file.write_text("DATABASE_URL=postgres://x:y@h @photophore:public")
    result = runner.invoke(photophore, ["--json", "classify", str(env_file), "--rules", str(rules_valid)])
    assert result.exit_code == 0
    doc = json.loads(result.output.strip())
    assert doc["tier"] == "public"
    assert doc["reason"] == "explicit_tag"


def test_classify_env_file_without_tag(runner: CliRunner, tmp_env_file: Path, rules_valid: Path) -> None:
    """Without explicit tag, .env file -> local via path rule."""
    result = runner.invoke(photophore, ["--json", "classify", str(tmp_env_file), "--rules", str(rules_valid)])
    assert result.exit_code == 0
    doc = json.loads(result.output.strip())
    assert doc["tier"] == "local"
    assert doc["reason"].startswith("path_rule:")


# ---------------------------------------------------------------------------
# Directory walk: --json emits JSON Lines (one per file)


def test_classify_directory_json_lines(runner: CliRunner, tmp_dir: Path, rules_valid: Path) -> None:
    """classify <dir> --rules <valid> --json emits one JSON object PER LINE (D-12)."""
    result = runner.invoke(photophore, ["--json", "classify", str(tmp_dir), "--rules", str(rules_valid)])
    assert result.exit_code == 0, f"Unexpected exit: {result.output!r}"
    lines = [line for line in result.output.strip().splitlines() if line.strip()]
    assert len(lines) >= 1
    for line in lines:
        doc = json.loads(line)  # each line must be valid JSON
        assert "path" in doc
        assert "tier" in doc
        assert "reason" in doc


# ---------------------------------------------------------------------------
# Exit code 2: config errors (D-14)


def test_classify_no_rules_no_default_exits_2(runner: CliRunner, tmp_file: Path, tmp_path: Path) -> None:
    """Without --rules and no ~/.config/photophore/rules.yaml, exits with code 2."""
    # Override XDG_CONFIG_HOME to an empty dir so default doesn't exist
    env = {"XDG_CONFIG_HOME": str(tmp_path)}
    result = runner.invoke(
        photophore,
        ["classify", str(tmp_file)],
        env=env,
        catch_exceptions=False,
    )
    assert result.exit_code == 2, f"Expected exit 2; got {result.exit_code}: {result.output!r}"


def test_classify_rules_no_catchall_exits_2(runner: CliRunner, tmp_file: Path, rules_no_catchall: Path) -> None:
    """--rules <no-catchall-file> raises RulesConfigError surfaced as exit code 2."""
    result = runner.invoke(photophore, ["classify", str(tmp_file), "--rules", str(rules_no_catchall)])
    assert result.exit_code == 2, f"Expected exit 2; got {result.exit_code}: {result.output!r}"


def test_classify_rules_malformed_exits_2(runner: CliRunner, tmp_file: Path, rules_malformed: Path) -> None:
    """--rules <malformed-file> raises RulesConfigError surfaced as exit code 2."""
    result = runner.invoke(photophore, ["classify", str(tmp_file), "--rules", str(rules_malformed)])
    assert result.exit_code == 2, f"Expected exit 2; got {result.exit_code}: {result.output!r}"


# ---------------------------------------------------------------------------
# Binary content: graceful handling (invalid UTF-8 does NOT exit 4 — classifier handles it)


def test_classify_binary_content_graceful(runner: CliRunner, tmp_path: Path, rules_valid: Path) -> None:
    """A binary file with invalid UTF-8 does NOT exit 4; classifier falls through gracefully."""
    binary_file = tmp_path / "binary.bin"
    binary_file.write_bytes(bytes(range(256)))  # all byte values including invalid UTF-8
    result = runner.invoke(photophore, ["--json", "classify", str(binary_file), "--rules", str(rules_valid)])
    assert result.exit_code == 0, f"Unexpected exit: {result.output!r}"
    doc = json.loads(result.output.strip())
    assert doc["tier"] == "local"


# ---------------------------------------------------------------------------
# Reason format: CLASS-05 compliance


def test_classify_reason_format_default(runner: CliRunner, tmp_file: Path, rules_valid: Path) -> None:
    """Reason follows CLASS-05 format: classifier:default for unmatched harmless content."""
    result = runner.invoke(photophore, ["--json", "classify", str(tmp_file), "--rules", str(rules_valid)])
    assert result.exit_code == 0
    doc = json.loads(result.output.strip())
    # The catch-all rule matches, so reason is path_rule:default
    # OR if no rule matches content, it's classifier:default
    assert doc["reason"].startswith("path_rule:") or doc["reason"].startswith("classifier:")


# ---------------------------------------------------------------------------
# photophore classify --help


def test_classify_help(runner: CliRunner) -> None:
    """photophore classify --help exits 0 and includes classify in help text."""
    result = runner.invoke(photophore, ["classify", "--help"])
    assert result.exit_code == 0
    assert "classify" in result.output.lower() or "dry-run" in result.output.lower()
