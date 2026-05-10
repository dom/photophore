"""Test keystore probe and channel record operations (CHAN-04, D-06, BL-03).

Tests verify:
- _probe_keystore() raises KeystoreUnavailableError for fail/null backends (BL-03)
- _get_channel/_set_channel/_delete_channel round-trip correctly
- _get_index/_set_index/_add_to_index/_remove_from_index sentinel ops
"""
from __future__ import annotations

import json

import keyring
import pytest
from keyring.backends import fail as _fail_backend
from keyring.backends import null as _null_backend

from photophore.channels._keystore import (
    _KEYSTORE_SERVICE,
    _probe_keystore,
    _get_channel,
    _set_channel,
    _delete_channel,
)
from photophore.channels._index import (
    _INDEX_SENTINEL_KEY,
    get_index,
    set_index,
    add_to_index,
    remove_from_index,
)
from photophore.errors import KeystoreUnavailableError


def test_probe_keystore_raises_for_fail_backend() -> None:
    """BL-03: isinstance probe against fail.Keyring (not substring match)."""
    previous = keyring.get_keyring()
    keyring.set_keyring(_fail_backend.Keyring())
    try:
        with pytest.raises(KeystoreUnavailableError):
            _probe_keystore()
    finally:
        keyring.set_keyring(previous)


def test_probe_keystore_raises_for_null_backend() -> None:
    """BL-03: isinstance probe against null.Keyring."""
    previous = keyring.get_keyring()
    keyring.set_keyring(_null_backend.Keyring())
    try:
        with pytest.raises(KeystoreUnavailableError):
            _probe_keystore()
    finally:
        keyring.set_keyring(previous)


def test_probe_keystore_passes_for_real_backend(in_memory_keyring: object) -> None:
    """BL-03: real backend (not fail/null) passes the probe."""
    _probe_keystore()  # must not raise with in_memory_keyring installed


def test_set_get_channel_round_trip(in_memory_keyring: object) -> None:
    """_set_channel then _get_channel returns the same dict."""
    record = {"id": "ch-1", "remote_node": "bob", "ceiling": "tier-1"}
    _set_channel("ch-1", record)
    result = _get_channel("ch-1")
    assert result == record


def test_get_channel_returns_none_when_missing(in_memory_keyring: object) -> None:
    """_get_channel returns None for a channel_id not in the keystore."""
    result = _get_channel("nonexistent-channel-id")
    assert result is None


def test_delete_channel_removes_entry(in_memory_keyring: object) -> None:
    """_delete_channel removes the keystore entry; _get_channel returns None."""
    record = {"id": "ch-del", "state": "OPEN"}
    _set_channel("ch-del", record)
    _delete_channel("ch-del")
    assert _get_channel("ch-del") is None


def test_delete_channel_is_idempotent(in_memory_keyring: object) -> None:
    """_delete_channel on a non-existent key does not raise."""
    _delete_channel("ch-never-existed")  # must not raise


def test_get_index_on_empty_keystore_returns_empty_list(in_memory_keyring: object) -> None:
    """get_index() on an empty keystore returns []."""
    result = get_index()
    assert result == []


def test_add_to_index_appends(in_memory_keyring: object) -> None:
    """add_to_index() appends a channel_id to the sentinel list."""
    add_to_index("ch-1")
    add_to_index("ch-2")
    ids = get_index()
    assert "ch-1" in ids
    assert "ch-2" in ids


def test_add_to_index_is_idempotent(in_memory_keyring: object) -> None:
    """add_to_index() does not duplicate an existing channel_id."""
    add_to_index("ch-1")
    add_to_index("ch-1")  # second call must not duplicate
    ids = get_index()
    assert ids.count("ch-1") == 1


def test_remove_from_index_removes(in_memory_keyring: object) -> None:
    """remove_from_index() removes a channel_id from the sentinel."""
    add_to_index("ch-1")
    add_to_index("ch-2")
    remove_from_index("ch-1")
    ids = get_index()
    assert "ch-1" not in ids
    assert "ch-2" in ids


def test_remove_from_index_is_idempotent(in_memory_keyring: object) -> None:
    """remove_from_index() on a non-existent id does not raise."""
    remove_from_index("ch-never-existed")  # must not raise
