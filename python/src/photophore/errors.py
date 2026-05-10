"""Typed exception hierarchy for the photophore package.

All exceptions carry a ``code`` string for structured error handling and
machine-readable CLI output (D-14 exit codes).

Exit-code mapping (D-14):
  0  success
  1  generic (ChannelStateError — click default)
  2  config  (ConfigError)
  3  audit chain integrity (AuditChainBrokenError → AuditIntegrityError in CLI)
  4  classifier (ClassifierError — Plan 02-02)
  5  keystore (KeystoreError, UnauditedChannelError)
"""
from __future__ import annotations

from thermocline import KeystoreUnavailableError  # re-export from Phase 1

__all__ = [
    "PhotophoreError",
    "AuditWriteError",
    "AuditChainBrokenError",
    "UnsupportedChainAlgoError",
    "ChannelStateError",
    "UnauditedChannelError",
    "KeystoreUnavailableError",
]


class PhotophoreError(Exception):
    """Base exception for all photophore errors."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class AuditWriteError(PhotophoreError):
    """Raised when the audit log rejects a write.

    Wraps ``sqlite3.IntegrityError`` from append-only triggers (AUDIT-01) and
    any other write failure (unknown event_type, schema mismatch).
    """

    def __init__(self, message: str, *, code: str = "AUDIT_WRITE_FAILED") -> None:
        super().__init__(message, code=code)


class AuditChainBrokenError(PhotophoreError):
    """Raised when verify_chain() or query() detects a chain integrity failure (AUDIT-08).

    This is a privacy-critical incident — surfaces as exit code 3 in the CLI.
    """

    def __init__(self, message: str, *, code: str = "AUDIT_CHAIN_BROKEN") -> None:
        super().__init__(message, code=code)


class UnsupportedChainAlgoError(PhotophoreError):
    """Raised when an entry's algo_version is not in _HASH_ALGO_REGISTRY (AUDIT-02)."""

    def __init__(self, message: str, *, code: str = "UNSUPPORTED_CHAIN_ALGO") -> None:
        super().__init__(message, code=code)


class ChannelStateError(PhotophoreError):
    """Raised by Channel.transition_to() for invalid state transitions (CHAN-02)."""

    def __init__(self, message: str, *, code: str = "CHANNEL_STATE_INVALID") -> None:
        super().__init__(message, code=code)


class UnauditedChannelError(PhotophoreError):
    """Raised by bootstrap() when a channel_id exists in the keystore _index but
    has no corresponding ``channel.created`` audit entry (D-05 halt).

    The node refuses to operate until manual reconciliation.
    """

    def __init__(self, message: str, *, code: str = "UNAUDITED_CHANNEL") -> None:
        super().__init__(message, code=code)
