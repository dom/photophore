"""Shared pytest fixtures for the photophore test suite.

Provides:
- ``in_memory_keyring``: installs a real in-memory KeyringBackend for one test
  (replicates the brine_in_memory_keyring pattern from thermocline/python/tests/conftest.py,
  using a real KeyringBackend subclass so the isinstance probe passes)
- ``audit_log``: AuditLog backed by a tmp_path file
- ``channel_store``: ChannelStore with in-memory keyring + tmp_path DBs
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import keyring
import pytest
from keyring.backend import KeyringBackend

from photophore.audit import AuditLog


class _InMemoryKeyringBackend(KeyringBackend):
    """Real KeyringBackend subclass backed by a per-instance dict.

    Class name is deliberately NOT 'Keyring' so it is unambiguously distinct
    from keyring.backends.fail.Keyring and keyring.backends.null.Keyring
    (both of which the keystore isinstance probe rejects). This is the same pattern
    used by thermocline/python/tests/conftest.py::brine_in_memory_keyring.
    """

    priority: float = 100  # type: ignore[assignment]

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        self._store.pop((service, username), None)


@pytest.fixture
def in_memory_keyring() -> Iterator[_InMemoryKeyringBackend]:
    """Install a real in-memory KeyringBackend for the duration of one test.

    Yields the backend so tests can introspect _store directly.
    Restores the previous backend on teardown.
    """
    previous = keyring.get_keyring()
    backend = _InMemoryKeyringBackend()
    keyring.set_keyring(backend)
    try:
        yield backend
    finally:
        keyring.set_keyring(previous)


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    """Fresh AuditLog backed by a temp-path audit.db."""
    return AuditLog(tmp_path / "audit.db")


@pytest.fixture
def channel_store(
    tmp_path: Path,
    audit_log: AuditLog,
    in_memory_keyring: _InMemoryKeyringBackend,
) -> "ChannelStore":
    """ChannelStore with in-memory keyring and separate tmp_path DBs.

    Lazily imports ChannelStore so this fixture is available after Task 2.
    """
    from photophore.channels import ChannelStore  # noqa: PLC0415 (local import intentional)
    return ChannelStore(tmp_path / "channels.db", audit_log)
