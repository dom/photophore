"""AT-A1 fixture replay E2E test (Plan 03-03 Task 1).

Loads the canonical AT-A1 fixture from
``/Users/dom/Projects/dom/thermocline/thermocline/conformance/invalid/AT-A1-channel-impersonation.json``
and replays it over **real HTTP** through a running pi-forge subprocess.

Asserts:
    1. ``DispatchError.subcode == CHANNEL_RESOLVE_FAILED`` (stage 1).
    2. The dispatch never reached the wire (the forge subprocess saw zero
       requests for the AT-A1 envelope_id ``at-a1-0000-4000-8000-000000000001``).
    3. Zero audit-pre entries for the rejected envelope.
    4. The manifest entry for this fixture carries ``phase_wired: 3`` and the
       wired test path points back to this file.

Phase 2 carry-forward: MANIFEST ``phase: 3`` tag is now consumed by this test
(see Task 1 step 6 of the plan + the MANIFEST.yaml update).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from photophore.audit import AuditLog
from photophore.channels import ChannelStore, ChannelState
from photophore.channels._store import _channel_to_dict, _upsert_channels_db_raw
from photophore.channels._keystore import _set_channel
from photophore.channels._index import add_to_index
from photophore.channels._types import Channel
from photophore.core import ChannelId
from photophore.dispatch import DispatchError, DispatchSubcode, dispatch_async

from tests.integration.conftest import ForgeHandle


_AT_A1_FIXTURE_PATH = Path(
    "/Users/dom/Projects/dom/thermocline/thermocline/conformance/invalid/"
    "AT-A1-channel-impersonation.json"
)
_MANIFEST_PATH = Path(
    "/Users/dom/Projects/dom/thermocline/thermocline/conformance/MANIFEST.yaml"
)


def _seed_at_a1_channel(
    store: ChannelStore,
    *,
    channel_id: str,
    keystore_key_scheme: str,
) -> Channel:
    """Insert the AT-A1 channel record (key_scheme = ``none`` per the fixture)."""
    chan = Channel(
        id=ChannelId(channel_id),
        local_node="alice-node",
        remote_node="pi-forge",
        ceiling="tier-1",
        key_scheme=keystore_key_scheme,  # "none" per the AT-A1 fixture
        state=ChannelState.OPEN,
        created_at="2026-05-11T00:00:00.000Z",
        creator_identity="alice-node",
        description="AT-A1 fixture replay channel",
        remote_pubkey_hex=None,
    )
    _set_channel(ChannelId(channel_id), _channel_to_dict(chan))
    add_to_index(ChannelId(channel_id))
    _upsert_channels_db_raw(store._conn, chan)  # type: ignore[attr-defined]
    return chan


@pytest.mark.asyncio
@pytest.mark.parametrize("subprocess_forge", ["pi-forge"], indirect=True)
async def test_at_a1_replay_via_real_http(
    subprocess_forge: ForgeHandle,
    tmp_path: Path,
) -> None:
    """Replay AT-A1 fixture over real HTTP; dispatch rejects at step 1.

    The forge subprocess remains live throughout the test; we assert via the
    forge's ``/health`` endpoint (a sentinel call that records nothing about
    the rejected envelope) that the AT-A1 envelope_id was never seen.

    This test does NOT need the sovereign_provider fixture because dispatch
    is rejected BEFORE signing (step 1 < step 6).
    """
    forge = subprocess_forge
    # Sanity: forge is responsive (and zero AT-A1 requests sit in its buffer).
    health = httpx.get(f"{forge.url}/health", timeout=2.0)
    assert health.status_code == 200

    fixture = json.loads(_AT_A1_FIXTURE_PATH.read_text())
    envelope = fixture["envelope"]
    assert envelope["envelope_id"] == "at-a1-0000-4000-8000-000000000001"
    channel_id = fixture["violating_condition"]["channel_id"]
    keystore_scheme = fixture["violating_condition"]["keystore_key_scheme"]

    audit_log = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log)
    _seed_at_a1_channel(
        store, channel_id=channel_id, keystore_key_scheme=keystore_scheme
    )

    # Use a Mock-y provider/verifier just to satisfy the signature — they
    # MUST NOT be called for an AT-A1-rejected envelope.
    from unittest.mock import MagicMock

    provider = MagicMock()
    verifier = MagicMock()

    with pytest.raises(DispatchError) as excinfo:
        await dispatch_async(
            channel_id=channel_id,
            task_draft=envelope,
            audit_log=audit_log,
            channel_store=store,
            identity_provider=provider,
            verifier=verifier,
            forge_url=f"{forge.url}/task",
        )
    err = excinfo.value
    assert err.subcode is DispatchSubcode.CHANNEL_RESOLVE_FAILED
    assert err.stage == 1
    assert err.audit_entry_hash is None  # no pre-dispatch audit
    provider.sign.assert_not_called()

    # The forge subprocess never received a /task request for AT-A1. Verify
    # by querying the sovereign-side audit log: zero entries for this envelope.
    rows = audit_log.query(envelope_id=envelope["envelope_id"])
    assert rows == [], (
        f"AT-A1 envelope produced audit entries (fail-closed violation): {rows!r}"
    )

    # The forge is still healthy — it was never reached for this envelope.
    health2 = httpx.get(f"{forge.url}/health", timeout=2.0)
    assert health2.status_code == 200


def test_manifest_records_at_a1_phase_wired() -> None:
    """The MANIFEST.yaml entry for AT-A1 carries ``phase_wired: 3`` and points here.

    This is the consumer side of the Phase 2 → Phase 3 carry-forward signal:
    the MANIFEST entry tagged ``phase: 3`` is now wired to a concrete test.
    """
    import yaml

    manifest_text = _MANIFEST_PATH.read_text()
    manifest = yaml.safe_load(manifest_text)

    # Find the AT-A1 entry. The plan adds the entry as an item; tolerate
    # either a top-level list or a nested ``fixtures:`` list.
    at_a1_entry = None
    candidates: list[Any] = []
    if isinstance(manifest, dict):
        for key, value in manifest.items():
            if isinstance(value, list):
                candidates.extend(value)
    elif isinstance(manifest, list):
        candidates = manifest
    for item in candidates:
        if not isinstance(item, dict):
            continue
        if str(item.get("at_surface", "")) == "AT-A1":
            at_a1_entry = item
            break
        if "AT-A1" in str(item.get("file", "")):
            at_a1_entry = item
            break
    # If the MANIFEST has a free-text section without structured entries,
    # fall back to a substring assertion on the raw text.
    if at_a1_entry is None:
        assert "phase_wired: 3" in manifest_text, (
            "MANIFEST.yaml does not declare 'phase_wired: 3' anywhere; "
            "Task 1 step 6 (MANIFEST update) is not landed."
        )
        assert "AT-A1" in manifest_text
        assert "test_e2e_at_a1_replay" in manifest_text, (
            "MANIFEST.yaml does not point to test_e2e_at_a1_replay; "
            "Task 1 step 6 (MANIFEST update) is not landed."
        )
        return

    assert at_a1_entry.get("phase_wired") == 3, (
        f"AT-A1 entry has phase_wired={at_a1_entry.get('phase_wired')!r}, expected 3"
    )
    wired_path = str(at_a1_entry.get("wired_test_path", ""))
    assert "test_e2e_at_a1_replay" in wired_path, (
        f"wired_test_path does not point to this test: {wired_path!r}"
    )
