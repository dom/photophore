"""SensitiveFilter — privacy-aware logging filter (CONF-06 / D-09).

Drops any log record field whose value is a ``thermocline.Sensitive[T]``
wrapper. Used together with:

  - the ``print(`` AST lint (forbids print in library code)
  - the audit-payload runtime guard (``_assert_no_sensitive`` in
    photophore.audit._store)

These three controls form the CONF-06 defense-in-depth: prints are forbidden
by AST scan; audit payloads are checked at write time; logging records are
filtered as the last line of defense.

Public API:
    SensitiveFilter   — logging.Filter subclass; install on any logger.
    configure_logging — convenience: set up a root handler with the filter.

Usage:
    import logging
    from photophore.logging import configure_logging
    configure_logging()   # at app startup
    log = logging.getLogger("photophore.dispatch")
    log.info("dispatching", extra={"envelope_id": envelope_id})
    # If a Sensitive[T] value were ever passed via `extra=`, it would be
    # redacted to the literal string ``<REDACTED:Sensitive>``.
"""
from __future__ import annotations

import logging
from typing import Any

__all__ = ["SensitiveFilter", "configure_logging"]


# Heuristic key names that often carry privacy-sensitive content. The filter
# uses these as a defense-in-depth signal, but the PRIMARY mechanism is
# isinstance(value, Sensitive). String-name heuristics are intentionally
# conservative — only definitively-sensitive names are listed.
SENSITIVE_KEY_PATTERNS: frozenset[str] = frozenset({
    "key_material",
    "private_key",
    "secret",
    "password",
    "credential",
})


_REDACTED_MARKER = "<REDACTED:Sensitive>"


def _redact_record_field(value: Any) -> Any:
    """Return _REDACTED_MARKER if value is Sensitive[T]; otherwise return value as-is.

    The Sensitive import is lazy so this module can load without
    thermocline-py present (defensive — thermocline IS a hard dependency,
    but the filter should never break logging if there's an import issue).
    """
    try:
        from thermocline.sensitive import Sensitive
    except ImportError:
        return value
    if isinstance(value, Sensitive):
        return _REDACTED_MARKER
    return value


class SensitiveFilter(logging.Filter):
    """Walk record.__dict__ + record.args; replace any Sensitive[T] value with a redaction marker.

    Returns True (don't drop the record) but mutates the record in place.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Walk record.__dict__ for any Sensitive[T] values added via
        # `logger.info(msg, extra={...})`.
        for k, v in list(record.__dict__.items()):
            new_v = _redact_record_field(v)
            if new_v is not v:
                setattr(record, k, new_v)
            elif k in SENSITIVE_KEY_PATTERNS and not isinstance(v, str) or (
                k in SENSITIVE_KEY_PATTERNS and v != _REDACTED_MARKER
            ):
                # Conservative defense-in-depth: redact known-sensitive
                # key names even if the value is not Sensitive[T] wrapped.
                setattr(record, k, _REDACTED_MARKER)
        # record.args may be a dict or a tuple; check both shapes.
        if isinstance(record.args, dict):
            new_args = {k: _redact_record_field(v) for k, v in record.args.items()}
            record.args = new_args
        elif isinstance(record.args, tuple):
            redacted = tuple(_redact_record_field(v) for v in record.args)
            if redacted != record.args:
                record.args = redacted
        return True


def configure_logging(level: int = logging.INFO) -> None:
    """Install a stderr handler with SensitiveFilter on the photophore logger.

    Safe to call multiple times — adds the filter only once per handler.
    """
    logger = logging.getLogger("photophore")
    logger.setLevel(level)
    # Add a single stderr handler with the filter if not already attached.
    for h in logger.handlers:
        for f in h.filters:
            if isinstance(f, SensitiveFilter):
                return  # already configured
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(SensitiveFilter())
    logger.addHandler(handler)
