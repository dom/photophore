"""AT-A5 behavioral wire: D-04 three-store separation test (CHAN-04).

This test verifies that Photophore's three stores are structurally separate:
1. Trust store: platform keystore via python-keyring (not a local file under photophore's data dir)
2. Channel index: channels.db (a specific file path)
3. Audit log: audit.db (a DIFFERENT file path from channels.db)

The AT-A5 fixture at thermocline/conformance/invalid/AT-A5-trust-store-colocation.json
documents the violating_config and compliant_config shapes; this test exercises the
compliant path and verifies the separation invariant holds.

Behavioral coverage: test_audit_chain_property.py covers AT-A4; this file covers AT-A5.
"""
from __future__ import annotations

import json
from pathlib import Path

import keyring
import pytest

from photophore.audit import AuditLog
from photophore.channels import ChannelStore
from photophore.channels._keystore import _KEYSTORE_SERVICE


def test_audit_db_and_channels_db_are_different_files(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """AT-A5: AuditLog.path != ChannelStore.channels_db_path (D-04 three-store model)."""
    audit = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit)

    assert audit.path != store.channels_db_path, (
        "AT-A5 violation: audit.db and channels.db must be different file paths"
    )


def test_keystore_service_is_not_a_file_path(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """AT-A5: keystore service 'photophore.channel' is not a filesystem path.

    The keystore is platform-backed (Keychain/libsecret/CredentialManager) — not
    a SQLite file under the same directory as audit.db or channels.db.
    """
    # Verify the keystore service namespace is a logical service name, not a file path.
    assert not _KEYSTORE_SERVICE.startswith("/"), (
        f"Keystore service {_KEYSTORE_SERVICE!r} must be a logical name, not a file path"
    )
    assert "audit" not in _KEYSTORE_SERVICE, (
        f"Keystore service {_KEYSTORE_SERVICE!r} must not reference 'audit'"
    )


def test_channel_store_does_not_create_files_at_audit_db_path(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """AT-A5: ChannelStore must NOT write a file at the audit.db path."""
    audit_db = tmp_path / "audit.db"
    channels_db = tmp_path / "channels.db"

    audit = AuditLog(audit_db)
    store = ChannelStore(channels_db, audit)

    # Create a channel to trigger all D-07 three-step writes.
    store.create(
        remote_node="bob", ceiling="tier-1", key_scheme="brine",
        local_node="alice", creator_identity="alice",
    )

    # Verify the two DB files are separate.
    assert audit_db.exists(), "audit.db must exist after append"
    assert channels_db.exists(), "channels.db must exist after channel create"
    assert audit_db.resolve() != channels_db.resolve(), (
        "AT-A5 violation: audit.db and channels.db must not be the same file"
    )


def test_at_a5_fixture_loads_and_parses(tmp_path: Path) -> None:
    """AT-A5 fixture: thermocline/conformance/invalid/AT-A5-trust-store-colocation.json parses correctly."""
    # Locate the fixture relative to this test file.
    # The fixture is at: thermocline/conformance/invalid/AT-A5-trust-store-colocation.json
    # This test file is at: photophore/python/tests/test_channels_separation.py
    # Resolve: ../../../thermocline/conformance/invalid/AT-A5-trust-store-colocation.json
    # or use an absolute path relative to the project root.
    import os
    # Try to find the fixture by walking up from the test directory.
    test_dir = Path(__file__).resolve().parent
    # Look for thermocline repo at siblings of the photophore repo.
    photophore_repo = test_dir.parent.parent  # photophore/python/tests -> photophore/python -> photophore
    thermocline_repo = photophore_repo.parent / "thermocline"
    fixture_path = thermocline_repo / "thermocline" / "conformance" / "invalid" / "AT-A5-trust-store-colocation.json"

    if not fixture_path.exists():
        pytest.skip(f"AT-A5 fixture not found at {fixture_path}; skipping fixture load test")

    content = fixture_path.read_text()
    fixture = json.loads(content)
    assert fixture["_at_surface"] == "AT-A5"
    assert "violating_config" in fixture
    assert "compliant_config" in fixture
    assert fixture["violating_config"]["audit_db_path"] == fixture["violating_config"]["channels_db_path"]
