"""Dispatch test fixtures."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import keyring
import pytest
from keyring.backend import KeyringBackend

from photophore.audit import AuditLog


class _InMemoryKeyringBackend(KeyringBackend):
    """Real KeyringBackend subclass backed by a per-instance dict (isinstance probe-safe)."""

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
    """Install a real in-memory KeyringBackend for the duration of one test."""
    previous = keyring.get_keyring()
    backend = _InMemoryKeyringBackend()
    keyring.set_keyring(backend)
    try:
        yield backend
    finally:
        keyring.set_keyring(previous)


@pytest.fixture
def tmp_audit_log(tmp_path: Path) -> Iterator[AuditLog]:
    """Fresh AuditLog backed by a per-test SQLite file."""
    yield AuditLog(tmp_path / "audit.db")
