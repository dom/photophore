"""Forged-receipt E2E test — DISP-03 hard-fail gate (Plan 03-03 Task 2).

Closes Phase 3 SC2 first half. A small inline Flask forge (spawned in its own
process via multiprocessing) returns a structurally valid task_result envelope
with ``receipt_signature.sig = "00" * 64`` — known-invalid for any real key.
Dispatch must raise ``DispatchError.RECEIPT_INVALID`` (stage 8) and the audit
log must contain exactly 1 entry (the pre-dispatch one) — no audit-post
referencing the forged receipt.

Test 4 additionally queries the audit log for ANY entry whose payload contains
the forged sig hex; expects zero matches (DISP-03 strict — no record references
the forged receipt anywhere).
"""
from __future__ import annotations

import asyncio
import json
import multiprocessing
import socket
import time
import uuid
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


_FORGED_SIG_HEX = "00" * 64  # known-invalid for any real ed25519 key
_FORGED_RESPONDER = "forged-forge"


def _forged_forge_app(port: int) -> None:
    """Tiny in-process forge that returns a forged receipt sig.

    Runs in a child multiprocessing.Process. Returns 200 + a structurally
    valid task_result envelope (so transport/JSON layer is happy) but the
    receipt_signature.sig is "00" * 64 — known-invalid for any real key.
    """
    # Stub socket.getfqdn — werkzeug's HTTPServer.server_bind calls it on
    # the bound host and reverse-DNS of 127.0.0.1 hangs ~35s on macOS arm64
    # GH runners. server_name isn't used by this fake forge.
    import socket as _socket
    _socket.getfqdn = lambda name="": name or "localhost"
    from flask import Flask, jsonify, request  # local import — child process

    app = Flask(__name__)

    @app.post("/task")
    def fake_task() -> Any:
        body = request.get_json(force=True)
        envelope_id = body.get("envelope_id")
        timestamp = "2026-05-11T00:00:00Z"
        result_id = "forged-result-0001"
        return jsonify(
            {
                "thermocline": "0.3.1",
                "type": "task_result",
                "envelope_id": envelope_id,
                "result_id": result_id,
                "completed_at": timestamp,
                "responder": _FORGED_RESPONDER,
                "outputs": {"pi": "3.14"},
                "provenance": {
                    "shadows_received": [],
                    "tiers_present": [2],
                    "local_tiers_present": False,
                },
                "receipt_signature": {
                    "key_scheme": "brine",
                    "node_id": _FORGED_RESPONDER,
                    "envelope_id": envelope_id,
                    "result_id": result_id,
                    "timestamp": timestamp,
                    "sig": _FORGED_SIG_HEX,
                },
            }
        ), 200

    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return int(s.getsockname()[1])


def _seed_channel(
    store: ChannelStore,
    *,
    channel_id: str,
    key_scheme: str = "brine",
    ceiling: str = "tier-2",
    remote_node: str = "forged-forge",
    local_node: str = "alice-node",
) -> Channel:
    chan = Channel(
        id=ChannelId(channel_id),
        local_node=local_node,
        remote_node=remote_node,
        ceiling=ceiling,
        key_scheme=key_scheme,
        state=ChannelState.OPEN,
        created_at="2026-05-11T00:00:00.000Z",
        creator_identity=local_node,
        description="forged-forge test channel",
        remote_pubkey_hex=None,
    )
    _set_channel(ChannelId(channel_id), _channel_to_dict(chan))
    add_to_index(ChannelId(channel_id))
    _upsert_channels_db_raw(store._conn, chan)  # type: ignore[attr-defined]
    return chan


@pytest.mark.asyncio
async def test_forged_receipt_rejected_no_audit_post(
    sovereign_provider: tuple[Any, Any, str, bytes],
    tmp_path: Path,
) -> None:
    """Forge returns sig="00"*64; dispatch raises RECEIPT_INVALID; no audit-post.

    DISP-03 conformance test (Phase 3 SC2 first half).
    """
    provider, verifier, sov_identity, sov_pubkey = sovereign_provider
    # The verifier must know about the forged-forge identity so the verify
    # path actually reaches the sig-check (vs. blowing up on IDENTITY_NOT_FOUND).
    # Register a dummy pubkey — verification will still fail because the
    # forged sig won't match this key either.
    import nacl.signing

    dummy_sk = nacl.signing.SigningKey.generate()
    dummy_pubkey = bytes(dummy_sk.verify_key)
    provider.register_public_key(identity=_FORGED_RESPONDER, verify_key=dummy_pubkey)

    port = _free_port()
    proc = multiprocessing.Process(
        target=_forged_forge_app, args=(port,), daemon=True
    )
    proc.start()
    try:
        # Wait for forge readiness (any HTTP response is fine). 60s budget
        # accommodates cold macOS arm64 GH-runner starts; locally <1s.
        url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 60.0
        ready = False
        while time.monotonic() < deadline:
            if not proc.is_alive():
                raise RuntimeError("forged-forge subprocess died during startup")
            try:
                resp = httpx.post(url + "/task", json={"envelope_id": "probe"}, timeout=0.5)
                if resp.status_code in (200, 400, 415):
                    ready = True
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
        assert ready, "forged-forge did not become ready in 60s"

        # Build sovereign-side state.
        audit_log = AuditLog(tmp_path / "audit.db")
        store = ChannelStore(tmp_path / "channels.db", audit_log)
        channel_id = f"chan-forged-{uuid.uuid4().hex[:6]}"
        _seed_channel(
            store,
            channel_id=channel_id,
            remote_node=_FORGED_RESPONDER,
            local_node=sov_identity,
        )

        envelope_id = f"env-forged-{uuid.uuid4().hex[:6]}"
        draft = {
            "thermocline": "0.3.1",
            "type": "task",
            "envelope_id": envelope_id,
            "issued_at": "2026-05-11T00:00:00Z",
            "issuer": sov_identity,
            "recipient": _FORGED_RESPONDER,
            "channel_id": channel_id,
            "task": {
                "type": "data.compute",
                "instruction": "noop",
                "parameters": {"digits": 1},
            },
            "context": [],
            "output_contract": {"format": "text/plain"},
            "dispatch_signature": {
                "key_scheme": "brine",
                "signer_identity": sov_identity,
            },
        }

        with pytest.raises(DispatchError) as excinfo:
            await dispatch_async(
                channel_id=channel_id,
                task_draft=draft,
                audit_log=audit_log,
                channel_store=store,
                identity_provider=provider,
                verifier=verifier,
                forge_url=f"{url}/task",
            )
        err = excinfo.value
        assert err.subcode is DispatchSubcode.RECEIPT_INVALID, (
            f"expected RECEIPT_INVALID, got {err.subcode}"
        )
        assert err.stage == 8
        assert err.audit_entry_hash is not None  # pre-dispatch landed; post did NOT.

        # SC2: exactly 1 audit entry (the pre-dispatch one). No audit-post.
        rows = audit_log.query(envelope_id=envelope_id)
        assert len(rows) == 1, (
            f"expected exactly 1 audit entry (pre-dispatch only), got {len(rows)}: "
            f"{[r.event_type for r in rows]!r}"
        )
        assert rows[0].event_type == "dispatch.pre"

        # Test 4 (DISP-03 strict): no audit-log entry references the forged sig.
        all_rows = audit_log.query()
        for row in all_rows:
            payload_str = json.dumps(row.payload)
            assert _FORGED_SIG_HEX not in payload_str, (
                f"audit entry {row.entry_hash!r} contains the forged sig: {row.payload!r}"
            )
    finally:
        proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)
