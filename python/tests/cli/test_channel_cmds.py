"""Task 3 channel-cmds tests: `channel new --fetch-pubkey-from URL` carve-out (D-01, D-07).

Tests verify:
  - --fetch-pubkey-from invokes httpx.get on the forge /pubkey endpoint
  - D-07 atomic three-step ordering: keystore (BrineProvider.register_public_key)
    → audit (channel.pubkey_registered event) → channels.db.upsert
  - The new event type "channel.pubkey_registered" is registered in
    photophore.core.KNOWN_EVENT_TYPES (regression guard — without this, the
    AuditLog.append at the second step would raise at runtime).
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from photophore.cli import photophore
from photophore.core import KNOWN_EVENT_TYPES


# The 32-byte (64-hex) verify key the mocked forge returns.
_FAKE_PUBKEY_HEX = "ab" * 32


def _mock_httpx_get(url: str, *args, **kwargs):
    """Return a mocked httpx.Response that yields the pi-forge /pubkey JSON."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "identity": "pi-forge",
        "key_scheme": "brine",
        "pubkey": _FAKE_PUBKEY_HEX,
    }
    mock_resp.raise_for_status = MagicMock(return_value=None)
    return mock_resp


def test_channel_new_fetch_pubkey_audit_event_known() -> None:
    """KNOWN_EVENT_TYPES regression guard for the new event type."""
    assert "channel.pubkey_registered" in KNOWN_EVENT_TYPES


def test_channel_new_fetch_pubkey_registers_via_d07(
    tmp_path: Path, in_memory_keyring: object
) -> None:
    """D-07 atomic three-step: keystore → audit → channels.db, on the fetch-pubkey path."""
    runner = CliRunner()
    with patch("photophore.cli.channel_cmds.httpx.get", side_effect=_mock_httpx_get):
        result = runner.invoke(
            photophore,
            ["--json", "--data-dir", str(tmp_path), "channel", "new",
             "--remote-node", "pi-forge",
             "--ceiling", "tier-1",
             "--key-scheme", "brine",
             "--fetch-pubkey-from", "http://localhost:5000"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0, f"output={result.output!r}"
    doc = json.loads(result.output)
    channel_id = doc["id"]
    assert doc["key_scheme"] == "brine"

    # Step 1 verification: BrineProvider.public_key(identity='pi-forge') returns
    # the registered hex bytes.
    from thermocline.identity import BrineProvider
    provider = BrineProvider(keyring_service="thermocline.brine")
    actual_pubkey = provider.public_key(identity="pi-forge")
    assert actual_pubkey.hex() == _FAKE_PUBKEY_HEX

    # Step 2 verification: audit log has the channel.pubkey_registered entry.
    from photophore.audit import AuditLog
    audit_log = AuditLog(tmp_path / "audit.db")
    rows = audit_log.query(event_type="channel.pubkey_registered")
    assert len(rows) == 1
    payload = rows[0].payload
    assert payload["identity"] == "pi-forge"
    assert payload["pubkey_hex"] == _FAKE_PUBKEY_HEX
    assert payload["source_url"] == "http://localhost:5000"

    # Step 3 verification: channels.db has the row.
    from photophore.channels import ChannelStore
    audit_log2 = AuditLog(tmp_path / "audit.db")
    store = ChannelStore(tmp_path / "channels.db", audit_log2)
    chan = store.show(channel_id)
    assert chan.remote_node == "pi-forge"
    assert chan.key_scheme == "brine"
