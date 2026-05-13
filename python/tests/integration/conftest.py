"""Integration test fixtures: subprocess_forge per CONTEXT D-04.

Spawns a real forge subprocess on an ephemeral port with an isolated keystore
namespace, polls ``GET /pubkey`` for readiness, yields ``(url, pubkey_hex, role)``
to the test, then SIGTERMs the process and deletes the ephemeral keystore entry.

Tests parametrize the fixture indirectly:

    @pytest.mark.parametrize("subprocess_forge", ["pi-forge"], indirect=True)
    def test_x(subprocess_forge):
        url, pubkey_hex, role = subprocess_forge
        ...

This file also exposes the ``sovereign_provider`` fixture: a real
``BrineProvider`` bound to an ephemeral ``thermocline.brine.test-<uuid>``
namespace with a fresh ``alice-node`` keypair, plus paired teardown.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Generator, Literal, Tuple

import httpx
import keyring
import pytest

from thermocline.identity import BrineProvider, Verifier


_SUITE_ROOT = Path(
    os.environ.get(
        "THERMOCLINE_SUITE_ROOT",
        str(Path.home() / "Projects" / "dom"),
    )
)
_SEAMOUNT_ROOT = _SUITE_ROOT / "seamount"
_FORGE_PATHS: dict[str, dict[str, str]] = {
    "pi-forge": {
        "dir": str(_SEAMOUNT_ROOT / "pi-forge"),
        "module": "pi_forge",
        "ready_marker": "PIFORGE_READY port=",
        "namespace_prefix": "seamount.piforge",
        "identity": "pi-forge",
        "env_prefix": "PIFORGE",
    },
    "describe-forge": {
        "dir": str(_SEAMOUNT_ROOT / "describe-forge"),
        "module": "describe_forge",
        "ready_marker": "DESCRIBEFORGE_READY port=",
        "namespace_prefix": "seamount.describeforge",
        "identity": "describe-forge",
        "env_prefix": "DESCRIBEFORGE",
    },
}


def _free_port() -> int:
    """Pick an ephemeral free port. Race-tolerant for sequential test runs."""
    with socket.socket() as s:
        s.bind(("", 0))
        return int(s.getsockname()[1])


class ForgeHandle:
    """Handle yielded by ``subprocess_forge`` carrying the fields a test needs.

    Attributes
    ----------
    url
        Base HTTP URL (e.g. ``http://127.0.0.1:5117``); append ``/task`` etc.
    pubkey_hex
        Forge's ed25519 public key in hex (from ``GET /pubkey``).
    role
        ``"pi-forge"`` or ``"describe-forge"``.
    namespace
        Ephemeral keyring service namespace (``seamount.<role>.test-<uuid>``).
        Tests need this to cross-register the sovereign's pubkey on the
        forge side (so the forge can verify dispatch signatures).
    identity
        The forge's keystore identity string (``pi-forge`` / ``describe-forge``).
    """

    __slots__ = ("url", "pubkey_hex", "role", "namespace", "identity")

    def __init__(
        self,
        *,
        url: str,
        pubkey_hex: str,
        role: str,
        namespace: str,
        identity: str,
    ) -> None:
        self.url = url
        self.pubkey_hex = pubkey_hex
        self.role = role
        self.namespace = namespace
        self.identity = identity

    def __iter__(self):  # type: ignore[no-untyped-def]
        # Backwards-compatible 3-tuple unpacking for tests that use the
        # old (url, pubkey, role) shape.
        return iter((self.url, self.pubkey_hex, self.role))


@pytest.fixture
def subprocess_forge(request: pytest.FixtureRequest) -> Generator[
    ForgeHandle, None, None
]:
    """Spawn a real forge subprocess; yield a :class:`ForgeHandle`.

    The fixture is indirect-parametrized via ``@pytest.mark.parametrize(
    "subprocess_forge", ["pi-forge"|"describe-forge"], indirect=True)``.

    Steps (CONTEXT D-04, 03-RESEARCH Pattern 7):
        1. Allocate ephemeral port.
        2. Allocate ephemeral keystore namespace ``seamount.<role>.test-<uuid>``.
        3. ``<role> init --keyring-service <ns>`` to generate the forge keypair.
        4. ``<role> serve --keyring-service <ns> --port <p>`` to spawn HTTP server.
        5. Poll ``GET /pubkey`` for readiness (12s budget).
        6. Yield :class:`ForgeHandle` to the test.
        7. SIGTERM + keystore cleanup on teardown.
    """
    role = request.param
    assert role in _FORGE_PATHS, f"unknown role {role!r}"
    meta = _FORGE_PATHS[role]
    test_ns = f"{meta['namespace_prefix']}.test-{uuid.uuid4().hex[:8]}"
    port = _free_port()
    forge_dir = Path(meta["dir"])
    # Prefer a per-forge .venv python (local dev convention from Plan 03-02);
    # fall back to the current interpreter (CI environments install the forge
    # into the runner's site-packages and have no per-forge venv).
    venv_python = forge_dir / ".venv" / "bin" / "python3"
    if not venv_python.exists():
        venv_python = forge_dir / ".venv" / "bin" / "python"
    if not venv_python.exists():
        venv_python = Path(sys.executable)
    env = {**os.environ}
    # Force the forge subprocess to use the ephemeral namespace + identity.
    env[f"{meta['env_prefix']}_KEYRING_SERVICE"] = test_ns
    env[f"{meta['env_prefix']}_IDENTITY"] = meta["identity"]
    # Crucial for the receipt-signing path: the forge signs with
    # signer_identity=responder=FORGE_NODE_ID. To make the receipt sig
    # verifiable end-to-end against the forge's keypair, FORGE_NODE_ID
    # must equal the keystore identity. (Default FORGE_NODE_ID is
    # ``pi-forge-local`` which would not match the ``pi-forge`` keypair.)
    env["FORGE_NODE_ID"] = meta["identity"]
    env["FORGE_PORT"] = str(port)

    # Step 1: init keypair under the ephemeral namespace.
    init_result = subprocess.run(
        [
            str(venv_python),
            "-m",
            meta["module"],
            "init",
            "--keyring-service",
            test_ns,
            "--identity",
            meta["identity"],
        ],
        cwd=str(forge_dir),
        env=env,
        check=False,
        timeout=20,
        capture_output=True,
        text=True,
    )
    if init_result.returncode != 0:
        raise RuntimeError(
            f"{role} init failed (rc={init_result.returncode}):\n"
            f"stdout: {init_result.stdout}\n"
            f"stderr: {init_result.stderr}"
        )

    # Step 2: spawn the server. We pipe stdout/stderr so test diagnostics
    # can inspect them on failure.
    proc = subprocess.Popen(
        [
            str(venv_python),
            "-m",
            meta["module"],
            "serve",
            "--keyring-service",
            test_ns,
            "--port",
            str(port),
        ],
        cwd=str(forge_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    url = f"http://127.0.0.1:{port}"
    # Step 3: poll /pubkey for readiness.
    deadline = time.monotonic() + 12.0
    pubkey_hex: str | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, _ = proc.communicate()
            # Best-effort keystore cleanup before raising.
            try:
                keyring.delete_password(test_ns, meta["identity"])
            except Exception:  # noqa: BLE001
                pass
            raise RuntimeError(
                f"{role} died during startup; rc={proc.returncode}; output:\n{out}"
            )
        try:
            resp = httpx.get(f"{url}/pubkey", timeout=1.0)
            if resp.status_code == 200:
                pubkey_hex = resp.json()["pubkey"]
                break
        except Exception:  # noqa: BLE001 — connection refused during startup is normal
            time.sleep(0.1)
    if pubkey_hex is None:
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            out = "<process killed>"
        try:
            keyring.delete_password(test_ns, meta["identity"])
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError(
            f"{role} did not become ready within 12s on port {port}\n"
            f"output: {out}"
        )
    try:
        # Expose the test namespace via request.node.user_properties so
        # tests can introspect it (used by test_subprocess_forge_teardown_*
        # to verify cleanup).
        request.node.user_properties.append(("forge_namespace", test_ns))
        yield ForgeHandle(
            url=url,
            pubkey_hex=pubkey_hex,
            role=role,
            namespace=test_ns,
            identity=meta["identity"],
        )
    finally:
        # Teardown: SIGTERM, wait, KILL if necessary.
        proc.terminate()
        try:
            outs, _ = proc.communicate(timeout=5)
            if os.environ.get("PHOTOPHORE_INTEGRATION_DEBUG"):
                # Dump forge output on debug for diagnostics.
                print(f"\n--- {role} subprocess output ---\n{outs}\n--- end ---")
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        # Delete forge keypair from the ephemeral namespace.
        try:
            keyring.delete_password(test_ns, meta["identity"])
        except Exception:  # noqa: BLE001
            pass
        # Also delete any registered public-key entries that the sovereign
        # may have written under this namespace. ``register_public_key``
        # writes under the prefix ``pubkey:<identity>``; we use the same
        # private import.
        try:
            from thermocline.identity import _PUBKEY_PREFIX

            # Best-effort delete for the common case (the test registered
            # alice-node's pubkey under the forge namespace).
            keyring.delete_password(test_ns, f"{_PUBKEY_PREFIX}alice-node")
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture
def sovereign_provider() -> Generator[
    Tuple[BrineProvider, Verifier, str, bytes], None, None
]:
    """Set up a sovereign-side BrineProvider + Verifier with a fresh ``alice-node`` keypair.

    Yields ``(provider, verifier, identity, pubkey_bytes)``. Uses an ephemeral
    ``thermocline.brine.sovereign-test-<uuid>`` keystore namespace.

    Teardown deletes the seed and any registered public keys this test wrote.
    """
    sov_ns = f"thermocline.brine.sovereign-test-{uuid.uuid4().hex[:8]}"
    identity = "alice-node"
    provider = BrineProvider(keyring_service=sov_ns)
    provider.generate(identity=identity)
    pubkey_bytes = provider.public_key(identity=identity)
    verifier = Verifier()
    verifier.register(provider)
    try:
        yield (provider, verifier, identity, pubkey_bytes)
    finally:
        try:
            keyring.delete_password(sov_ns, identity)
        except Exception:  # noqa: BLE001
            pass
        # Delete any registered foreign pubkeys (the test may have called
        # provider.register_public_key for the forge identity).
        try:
            from thermocline.identity import _PUBKEY_PREFIX

            for forge_identity in ("pi-forge", "describe-forge"):
                try:
                    keyring.delete_password(sov_ns, f"{_PUBKEY_PREFIX}{forge_identity}")
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture(scope="session", autouse=True)
def _orphan_keystore_sweep() -> Generator[None, None, None]:
    """Session-scoped sweep: best-effort cleanup of orphaned test namespaces from SIGKILL'd prior runs.

    The platform ``keyring`` library has no list API (Phase 2 LEARNINGS), so we
    cannot enumerate. This fixture exists as a documentation placeholder; the
    real cleanup happens in per-test finalizers above.
    """
    yield
    # No-op: see docstring.


@pytest.fixture(autouse=True)
def _force_real_keyring_backend() -> Generator[None, None, None]:
    """Force the integration test process to use the real platform keyring.

    The photophore tests/conftest.py registers
    ``tests.conftest._InMemoryKeyringBackend`` as a KeyringBackend subclass
    with ``priority = 100`` — pytest discovery picks it up as the highest
    priority backend, so ``keyring.get_keyring()`` returns it in any test
    process that imports tests.conftest. That backend stores its state in
    a per-process dict — when an integration test cross-registers a pubkey
    here, the forge SUBPROCESS (running with real macOS Keychain) cannot
    read it, breaking the E2E flow with a spurious SIGNATURE_INVALID.

    This autouse fixture forces ``keyring.set_keyring`` to the real platform
    backend (macOS Keychain / libsecret / Credential Manager) for the
    duration of each integration test, and restores whatever was in place
    before. macOS Keychain is then shared with the forge subprocess.
    """
    import keyring
    import keyring.backends.macOS  # noqa: F401 — ensure backend module loaded
    from keyring.backends import macOS as _macos_module  # noqa: PLC0415

    previous = keyring.get_keyring()
    real_backend = _macos_module.Keyring()
    keyring.set_keyring(real_backend)
    try:
        yield
    finally:
        keyring.set_keyring(previous)


# --- helpers re-exported for tests -----------------------------------------


def cross_register_keys(
    *,
    sovereign_provider: BrineProvider,
    sovereign_pubkey: bytes,
    sovereign_identity: str,
    forge_namespace: str,
    forge_identity: str,
    forge_pubkey_hex: str,
) -> None:
    """Cross-register pubkeys: sovereign learns forge pubkey, forge learns sovereign pubkey.

    Both directions are needed for the E2E round trip:
        - Forge verifies the inbound dispatch_signature (signed by sovereign).
        - Sovereign verifies the inbound receipt_signature (signed by forge).
    """
    # Sovereign-side: register the forge's pubkey under the forge's identity.
    sovereign_provider.register_public_key(
        identity=forge_identity, verify_key=bytes.fromhex(forge_pubkey_hex)
    )
    # Forge-side: register the sovereign's pubkey under the sovereign's identity,
    # in the forge's keyring namespace. The forge subprocess will read from this
    # namespace when it verifies the dispatch_signature.
    forge_side_provider = BrineProvider(keyring_service=forge_namespace)
    forge_side_provider.register_public_key(
        identity=sovereign_identity, verify_key=sovereign_pubkey
    )
    # Defensive sanity probe: read the pubkey back and confirm it's there.
    # Surfaces the in-memory-vs-real-keyring trap (see
    # _force_real_keyring_backend autouse fixture) on stderr when active.
    import os
    if os.environ.get("PHOTOPHORE_INTEGRATION_DEBUG"):
        from thermocline.identity import _PUBKEY_PREFIX
        stored = keyring.get_password(
            forge_namespace, _PUBKEY_PREFIX + sovereign_identity
        )
        backend = keyring.get_keyring()
        print(
            f"DEBUG cross-register: forge_namespace={forge_namespace!r}, "
            f"sovereign_identity={sovereign_identity!r}, "
            f"stored={stored[:16] if stored else None!r} "
            f"backend={type(backend).__module__}.{type(backend).__name__}"
        )
