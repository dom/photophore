"""Poisoned-audit-DB E2E test — DISP-02 abort gate.

The sovereign-side audit log is constructed with a path that cannot be
written (a directory). The first ``audit.append`` call at step 5 raises;
dispatch must abort with ``DispatchError.AUDIT_FAILED_PRE`` (stage 5,
retryable=True). A live subprocess forge with a
``multiprocessing.Value("i", 0)`` shared counter proves the forge NEVER
received a request — the abort gate fires BEFORE signing/transport.

This is a DISP-02 abort-gate test that requires a real wire;
``httpx.MockTransport`` is NOT permitted.
"""
from __future__ import annotations

import asyncio
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


def _counter_forge_app(port: int, counter: Any) -> None:
    """Tiny forge that increments a shared counter on EVERY request received.

    Returns a benign 200 — the test asserts counter.value==0, so the forge
    should NEVER be hit. If somehow dispatch reached transport, the test will
    detect it via the counter (not via a downstream error).
    """
    # Stub socket.getfqdn — werkzeug's HTTPServer.server_bind calls it on
    # the bound host and reverse-DNS of 127.0.0.1 hangs ~35s on macOS arm64
    # GH runners. server_name isn't used by this fake forge.
    import socket as _socket
    _socket.getfqdn = lambda name="": name or "localhost"
    from flask import Flask, jsonify, request  # local import — child process

    app = Flask(__name__)

    @app.before_request
    def _bump() -> None:
        with counter.get_lock():
            counter.value += 1

    @app.post("/task")
    def task() -> Any:
        return jsonify({"thermocline": "0.3.1", "type": "task_result"}), 200

    @app.get("/health")
    def health() -> Any:
        return jsonify({"status": "ok"}), 200

    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return int(s.getsockname()[1])


def _seed_channel(
    store: ChannelStore,
    *,
    channel_id: str,
    local_node: str = "alice-node",
) -> Channel:
    chan = Channel(
        id=ChannelId(channel_id),
        local_node=local_node,
        remote_node="counter-forge",
        ceiling="tier-2",
        key_scheme="brine",
        state=ChannelState.OPEN,
        created_at="2026-05-11T00:00:00.000Z",
        creator_identity=local_node,
        description="poisoned-audit test channel",
        remote_pubkey_hex=None,
    )
    _set_channel(ChannelId(channel_id), _channel_to_dict(chan))
    add_to_index(ChannelId(channel_id))
    _upsert_channels_db_raw(store._conn, chan)  # type: ignore[attr-defined]
    return chan


class _PoisonedAuditLog:
    """Audit log stand-in whose every ``append`` call raises.

    The real ``AuditLog`` would refuse to open if its db path is a directory;
    the failure happens at construction time, not at append time. To prove
    DISP-02 (abort BEFORE signing/transport when the audit-pre WRITE fails),
    we need an audit log that opens successfully but raises on ``append``.
    This stand-in mirrors the ``AuditLog`` query/append surface the dispatch
    coordinator consumes.
    """

    def __init__(self, real_log: AuditLog) -> None:
        self._real = real_log
        self._append_calls = 0

    @property
    def path(self) -> Path:
        return self._real.path

    def append(self, **kwargs: Any) -> Any:
        self._append_calls += 1
        raise OSError(
            "poisoned audit log — append intentionally fails (DISP-02 abort gate test)"
        )

    def query(self, **filters: Any) -> list:
        return self._real.query(**filters)

    def verify_chain(self) -> None:
        return self._real.verify_chain()


@pytest.mark.asyncio
async def test_poisoned_audit_aborts_before_sign(
    sovereign_provider: tuple[Any, Any, str, bytes],
    tmp_path: Path,
) -> None:
    """Audit-pre write fails → dispatch raises AUDIT_FAILED_PRE; forge never hit.

    DISP-02 conformance. The forge subprocess
    runs and is reachable, but the dispatch must abort at step 5 before
    transport (step 7) executes.
    """
    provider, verifier, sov_identity, sov_pubkey = sovereign_provider

    port = _free_port()
    # multiprocessing.Value("i", 0) is a shared int (ctypes c_int) with a
    # lock; readable across the test + forge processes.
    counter = multiprocessing.Value("i", 0)
    proc = multiprocessing.Process(
        target=_counter_forge_app, args=(port, counter), daemon=True
    )
    proc.start()
    try:
        url = f"http://127.0.0.1:{port}"
        # 60s budget accommodates cold macOS arm64 GH-runner starts.
        deadline = time.monotonic() + 60.0
        ready = False
        while time.monotonic() < deadline:
            if not proc.is_alive():
                raise RuntimeError("counter-forge subprocess died during startup")
            try:
                resp = httpx.get(url + "/health", timeout=0.5)
                if resp.status_code == 200:
                    ready = True
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
        assert ready, "counter-forge did not become ready in 60s"
        # Health probe inc'd counter once — reset so the test's assertion is
        # crisp ("forge was never hit").
        with counter.get_lock():
            counter.value = 0

        # Build sovereign-side state.
        real_audit = AuditLog(tmp_path / "audit.db")
        poisoned = _PoisonedAuditLog(real_audit)
        store = ChannelStore(tmp_path / "channels.db", real_audit)
        channel_id = f"chan-poisoned-{uuid.uuid4().hex[:6]}"
        _seed_channel(store, channel_id=channel_id, local_node=sov_identity)

        envelope_id = f"env-poisoned-{uuid.uuid4().hex[:6]}"
        draft = {
            "thermocline": "0.3.1",
            "type": "task",
            "envelope_id": envelope_id,
            "issued_at": "2026-05-11T00:00:00Z",
            "issuer": sov_identity,
            "recipient": "counter-forge",
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
                audit_log=poisoned,  # type: ignore[arg-type]
                channel_store=store,
                identity_provider=provider,
                verifier=verifier,
                forge_url=f"{url}/task",
            )
        err = excinfo.value
        assert err.subcode is DispatchSubcode.AUDIT_FAILED_PRE
        assert err.stage == 5
        assert err.retryable is True, (
            "DISP-02: AUDIT_FAILED_PRE is retryable (the failure is on the "
            "sovereign side; nothing crossed the wire)"
        )
        # SC2 second half: forge was NEVER hit — the abort gate fired before
        # transport could execute.
        assert counter.value == 0, (
            f"forge was hit despite audit-pre failure (counter={counter.value})"
        )
        # The sovereign-side audit log (the real one) has zero entries —
        # the poisoned wrapper never let any append succeed.
        rows = real_audit.query(envelope_id=envelope_id)
        assert rows == []
    finally:
        proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)
