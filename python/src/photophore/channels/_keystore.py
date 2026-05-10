"""Keystore operations for channel records (CHAN-04, D-04, D-06).

Uses python-keyring 25.x as the trust store backing (platform Keychain on macOS,
libsecret on Linux, Credential Manager on Windows).

Keystore namespace (D-06):
- service: "photophore.channel"
- username: channel_id (UUIDv4) for per-channel records
- username: "_index" for the sentinel (see _index.py)

BL-03 isinstance probe pattern from Phase 1 (thermocline.identity):
    isinstance(backend, (fail.Keyring, null.Keyring)) → unavailable
DO NOT use substring match on class name (both are named 'Keyring').
"""
from __future__ import annotations

import json

import keyring
from keyring.backends import fail as _fail_backend
from keyring.backends import null as _null_backend

from ..errors import KeystoreUnavailableError

__all__ = [
    "_KEYSTORE_SERVICE",
    "_probe_keystore",
    "_get_channel",
    "_set_channel",
    "_delete_channel",
]

_KEYSTORE_SERVICE: str = "photophore.channel"


def _probe_keystore() -> None:
    """Verify keystore availability at startup (Phase 1 BL-03 pattern).

    Raises KeystoreUnavailableError if:
    - keyring.get_keyring() raises
    - the backend is keyring.backends.fail.Keyring (CI/headless failure mode)
    - the backend is keyring.backends.null.Keyring (null/stub mode)

    DO NOT use isinstance on class name strings — both fail.Keyring and null.Keyring
    are named 'Keyring'; the isinstance check is the correct approach (Phase 1 BL-03).
    """
    try:
        backend = keyring.get_keyring()
    except Exception as exc:
        raise KeystoreUnavailableError(
            f"keyring unavailable: {exc}",
            code="KEYSTORE_UNAVAILABLE",
        ) from exc
    if isinstance(backend, (_fail_backend.Keyring, _null_backend.Keyring)):
        raise KeystoreUnavailableError(
            f"refusing to start: keystore backend is "
            f"{type(backend).__module__}.{type(backend).__qualname__!r} "
            f"(not a real secure store)",
            code="KEYSTORE_UNAVAILABLE",
        )


def _get_channel(channel_id: str) -> dict[str, object] | None:
    """Retrieve a channel record from the keystore. Returns None if not found."""
    raw = keyring.get_password(_KEYSTORE_SERVICE, channel_id)
    if raw is None:
        return None
    return dict(json.loads(raw))


def _set_channel(channel_id: str, record: dict[str, object]) -> None:
    """Store a channel record in the keystore (overwrites if exists)."""
    keyring.set_password(_KEYSTORE_SERVICE, channel_id, json.dumps(record))


def _delete_channel(channel_id: str) -> None:
    """Remove a channel record from the keystore."""
    try:
        keyring.delete_password(_KEYSTORE_SERVICE, channel_id)
    except keyring.errors.PasswordDeleteError:
        pass  # already deleted; idempotent
