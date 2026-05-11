"""Dispatch test fixtures."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from photophore.audit import AuditLog


@pytest.fixture
def tmp_audit_log(tmp_path: Path) -> Iterator[AuditLog]:
    """Fresh AuditLog backed by a per-test SQLite file."""
    yield AuditLog(tmp_path / "audit.db")
