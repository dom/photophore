"""Test SensitiveFilter — drops Sensitive[T] values from log records (CONF-06 / D-09)."""
from __future__ import annotations

import logging

import pytest

from thermocline.sensitive import Sensitive
from photophore.logging import SensitiveFilter, configure_logging


def test_sensitive_filter_drops_sensitive_extra(caplog):
    """logger.info(msg, extra={'envelope': Sensitive(b'...')}) -> bytes not in output."""
    configure_logging()
    logger = logging.getLogger("photophore.test")
    logger.addFilter(SensitiveFilter())
    with caplog.at_level(logging.INFO, logger="photophore.test"):
        logger.info("dispatch event", extra={"envelope": Sensitive(b"private-bytes-secret")})

    # The literal bytes MUST NOT appear anywhere in the captured log output.
    all_messages = " ".join(rec.getMessage() for rec in caplog.records)
    all_dicts = " ".join(repr(rec.__dict__) for rec in caplog.records)
    assert b"private-bytes-secret" not in all_messages.encode()
    assert b"private-bytes-secret" not in all_dicts.encode()

    # The record's `envelope` field should be redacted (no Sensitive instance left).
    for rec in caplog.records:
        if hasattr(rec, "envelope"):
            assert not isinstance(rec.envelope, Sensitive), (
                "SensitiveFilter must replace Sensitive instances with a redaction marker"
            )


def test_sensitive_filter_passes_non_sensitive_values(caplog):
    """Non-Sensitive values flow through normally."""
    logger = logging.getLogger("photophore.test_passthrough")
    logger.addFilter(SensitiveFilter())
    with caplog.at_level(logging.INFO, logger="photophore.test_passthrough"):
        logger.info("normal event", extra={"channel_id": "ch-123", "count": 5})

    found_record = next(r for r in caplog.records if "channel_id" in r.__dict__)
    assert found_record.channel_id == "ch-123"
    assert found_record.count == 5
