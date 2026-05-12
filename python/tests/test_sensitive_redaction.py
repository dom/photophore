"""Test the Sensitive[T] runtime guard + repr-redaction contract (CONF-06 / D-09).

Two facets covered:

1. AuditLog.append rejects payloads containing Sensitive[T] values with
   AuditWriteError code=AUDIT_SENSITIVE_LEAK.
2. ContentBlock.__repr__ / model_dump on populated Sensitive content does not
   leak the underlying bytes.
"""
from __future__ import annotations

import pytest

from thermocline import ContentBlock, Sensitive
from photophore.audit import AuditLog
from photophore.core import AuditEventType
from photophore.errors import AuditWriteError


def test_audit_log_rejects_sensitive_top_level(tmp_path):
    """append(payload={'leak': Sensitive(b'...')}) raises AUDIT_SENSITIVE_LEAK."""
    log = AuditLog(tmp_path / "audit.db")
    with pytest.raises(AuditWriteError) as exc_info:
        log.append(
            event_type=AuditEventType.CHANNEL_CREATED,
            channel_id="ch-test",
            payload={"leak": Sensitive(b"private-bytes")},
        )
    assert exc_info.value.code == "AUDIT_SENSITIVE_LEAK"


def test_audit_log_rejects_sensitive_nested_dict(tmp_path):
    """Nested Sensitive inside dict-of-dict is also caught."""
    log = AuditLog(tmp_path / "audit.db")
    with pytest.raises(AuditWriteError) as exc_info:
        log.append(
            event_type=AuditEventType.CHANNEL_CREATED,
            channel_id="ch-test",
            payload={"outer": {"inner": Sensitive(b"deep-bytes")}},
        )
    assert exc_info.value.code == "AUDIT_SENSITIVE_LEAK"


def test_audit_log_rejects_sensitive_in_list(tmp_path):
    """Sensitive in a list is also caught."""
    log = AuditLog(tmp_path / "audit.db")
    with pytest.raises(AuditWriteError) as exc_info:
        log.append(
            event_type=AuditEventType.CHANNEL_CREATED,
            channel_id="ch-test",
            payload={"items": [Sensitive(b"list-bytes"), {"ok": "string"}]},
        )
    assert exc_info.value.code == "AUDIT_SENSITIVE_LEAK"


def test_audit_log_accepts_non_sensitive_payload(tmp_path):
    """Clean payloads with only primitives pass the guard."""
    log = AuditLog(tmp_path / "audit.db")
    entry = log.append(
        event_type=AuditEventType.CHANNEL_CREATED,
        channel_id="ch-test",
        payload={"channel_id": "ch-test", "ceiling": "tier-1"},
    )
    assert entry.entry_hash is not None


def test_content_block_sensitive_field_repr_redaction():
    """A populated ContentBlock with Sensitive[bytes] content does not leak via repr()."""
    block = ContentBlock(tier=2, role="task_background", content=Sensitive(b"super-secret-bytes"))
    r = repr(block)
    assert b"super-secret-bytes" not in r.encode(), (
        f"Sensitive bytes leaked into ContentBlock repr: {r!r}"
    )
    # The Sensitive wrapper's repr is "<Sensitive: bytes>".
    assert "Sensitive" in r
