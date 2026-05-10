"""Tests for path-rules YAML loader and rule-based classifier patterns (Task 2)."""
from __future__ import annotations

from pathlib import Path

import pytest

from photophore.classifier._patterns import classify_by_rules
from photophore.classifier._rules import load_rules
from photophore.core import Tier
from photophore.errors import RulesConfigError

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ---------------------------------------------------------------------------
# Helper fixtures


@pytest.fixture()
def valid_rules_path() -> Path:
    return FIXTURES / "rules-valid.yaml"


@pytest.fixture()
def no_catchall_rules_path() -> Path:
    return FIXTURES / "rules-no-catchall.yaml"


@pytest.fixture()
def malformed_rules_path() -> Path:
    return FIXTURES / "rules-malformed.yaml"


# ---------------------------------------------------------------------------
# load_rules — happy path


def test_load_rules_returns_path_rules(valid_rules_path: Path) -> None:
    rules = load_rules(valid_rules_path)
    # Has a .rules attribute that is a tuple of PathRule
    assert isinstance(rules.rules, tuple)
    assert len(rules.rules) > 0


def test_load_rules_env_match(valid_rules_path: Path) -> None:
    rules = load_rules(valid_rules_path)
    match = rules.match("/x/.env")
    assert match is not None
    assert match.tier is Tier.LOCAL
    assert match.reason == "env-credentials"


def test_load_rules_env_star_match(valid_rules_path: Path) -> None:
    """**/.env* should match .env.local and similar."""
    rules = load_rules(valid_rules_path)
    match = rules.match("/x/.env.local")
    assert match is not None
    assert match.tier is Tier.LOCAL
    assert match.reason == "env-credentials"


def test_load_rules_catchall_match(valid_rules_path: Path) -> None:
    """Unmatched paths fall through to the catch-all rule."""
    rules = load_rules(valid_rules_path)
    match = rules.match("/x/notes.md")
    assert match is not None
    assert match.tier is Tier.LOCAL
    assert match.reason == "default"


def test_load_rules_pem_match(valid_rules_path: Path) -> None:
    rules = load_rules(valid_rules_path)
    match = rules.match("/x/server.pem")
    assert match is not None
    assert match.tier is Tier.LOCAL
    assert match.reason == "keys"


def test_load_rules_shared_docs_match(valid_rules_path: Path) -> None:
    rules = load_rules(valid_rules_path)
    match = rules.match("docs/api/reference.md")
    assert match is not None
    assert match.tier is Tier.SHARED
    assert match.reason == "shared-docs"


def test_load_rules_first_match_wins(valid_rules_path: Path) -> None:
    """A path matching an earlier rule should NOT fall through to catch-all."""
    rules = load_rules(valid_rules_path)
    # docs/*.md matches shared-docs (rule 3), not the ** catch-all (rule 4)
    match = rules.match("docs/guide.md")
    assert match is not None
    assert match.tier is Tier.SHARED  # shared-docs wins, not catch-all (local)


def test_load_rules_reason_in_path_rule_format(valid_rules_path: Path) -> None:
    """Rules with reason field surface the reason label (per CLASS-05 path_rule:<reason>)."""
    rules = load_rules(valid_rules_path)
    match = rules.match("/x/.env")
    assert match is not None
    # The caller formats the full reason as f"path_rule:{rule.reason}"
    # Here we just check the rule.reason is the label from YAML
    assert match.reason == "env-credentials"


# ---------------------------------------------------------------------------
# load_rules — pathspec **/.env* bare .env match verification
# (This is the key finding from 02-RESEARCH.md — fnmatch fails, pathspec passes)


def test_pathspec_matches_bare_dotenv(valid_rules_path: Path) -> None:
    """CRITICAL: pathspec gitwildmatch `**/.env*` must match bare `.env` filename.

    This is the failure case from 02-RESEARCH.md key finding #2:
    fnmatch and pathlib.PurePath.match both fail on this. pathspec>=1.1.1 passes.
    """
    rules = load_rules(valid_rules_path)
    # Test bare .env with various path shapes
    assert rules.match(".env") is not None
    match = rules.match(".env")
    assert match is not None
    assert match.reason == "env-credentials"


# ---------------------------------------------------------------------------
# load_rules — error cases


def test_load_rules_no_catchall_raises_at_load_time(no_catchall_rules_path: Path) -> None:
    """Missing `**` -> local catch-all MUST raise RulesConfigError AT LOAD TIME (CLASS-03 / D-08)."""
    with pytest.raises(RulesConfigError) as exc_info:
        load_rules(no_catchall_rules_path)
    msg = str(exc_info.value).lower()
    assert "missing" in msg or "catch-all" in msg or "mandatory" in msg, (
        f"Error message doesn't mention missing catch-all: {exc_info.value}"
    )


def test_load_rules_no_catchall_error_code(no_catchall_rules_path: Path) -> None:
    with pytest.raises(RulesConfigError) as exc_info:
        load_rules(no_catchall_rules_path)
    assert exc_info.value.code == "RULES_CONFIG_INVALID"


def test_load_rules_malformed_yaml_raises(malformed_rules_path: Path) -> None:
    """Malformed YAML structure raises RulesConfigError (or subclass) with diagnostic."""
    with pytest.raises(RulesConfigError):
        load_rules(malformed_rules_path)


def test_load_rules_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent.yaml"
    with pytest.raises(RulesConfigError):
        load_rules(missing)


def test_load_rules_uses_safe_load_not_load() -> None:
    """Verify yaml.safe_load is used (yaml.load without SafeLoader is RCE — Pitfall 5)."""
    import ast

    src = Path(__file__).resolve().parent.parent / "src" / "photophore" / "classifier" / "_rules.py"
    source_text = src.read_text()
    assert "yaml.safe_load" in source_text, "_rules.py must use yaml.safe_load"
    # Must NOT contain yaml.load( (without safe_load on same line)
    lines_with_yaml_load = [
        line
        for line in source_text.splitlines()
        if "yaml.load(" in line and "yaml.safe_load" not in line
    ]
    assert not lines_with_yaml_load, f"Found yaml.load() without safe_load: {lines_with_yaml_load}"


# ---------------------------------------------------------------------------
# classify_by_rules tests


def test_classify_by_rules_pem_header() -> None:
    content = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN...\n-----END PRIVATE KEY-----"
    assert classify_by_rules(content, "/x/key.txt") == "credential_pem"


def test_classify_by_rules_aws_key() -> None:
    assert classify_by_rules(b"AKIAIOSFODNN7EXAMPLE", None) == "credential_aws_key"


def test_classify_by_rules_env_assignment() -> None:
    assert classify_by_rules(b"DATABASE_URL=postgres://user:pass@host", None) == "credential_env_assignment"


def test_classify_by_rules_ssn() -> None:
    assert classify_by_rules(b"my SSN is 123-45-6789", None) == "pii_ssn"


def test_classify_by_rules_email() -> None:
    assert classify_by_rules(b"contact alice@example.com please", None) == "pii_email"


def test_classify_by_rules_no_match() -> None:
    assert classify_by_rules(b"hello world\n", "/x/notes.txt") is None


def test_classify_by_rules_pem_extension() -> None:
    """File extension .pem triggers credential_file_extension (cheapest check first)."""
    assert classify_by_rules(b"normal content", "/x/key.pem") == "credential_file_extension"


def test_classify_by_rules_env_file_extension() -> None:
    """Bare .env file triggers credential_file_extension."""
    assert classify_by_rules(b"DB_PASS=secret", "/x/.env") == "credential_file_extension"


def test_classify_by_rules_never_promotes_to_public() -> None:
    """classify_by_rules NEVER returns anything that would cause Tier.PUBLIC from inference.

    This function returns a rule_name string or None — the caller applies LOCAL on positive match.
    CLASS-04: false positives (private → PUBLIC) are NEVER acceptable.
    """
    # Test a variety of inputs — none should return "promote_to_public" or similar
    test_cases = [
        (b"AKIAIOSFODNN7EXAMPLE", None),
        (b"-----BEGIN PRIVATE KEY-----\nMIIE...", None),
        (b"123-45-6789", None),
        (b"alice@example.com", None),
        (b"DATABASE_URL=postgres://user:pass@host", None),
    ]
    for content, path in test_cases:
        result = classify_by_rules(content, path)
        if result is not None:
            assert "public" not in result.lower(), (
                f"classify_by_rules returned a rule that mentions 'public': {result!r}"
            )


def test_classify_by_rules_jwt() -> None:
    jwt = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert classify_by_rules(jwt, None) == "credential_jwt"


def test_classify_by_rules_sk_token() -> None:
    assert classify_by_rules(b"sk-abcdefghijklmnopqrstuvwxyz12345", None) == "credential_sk_token"
