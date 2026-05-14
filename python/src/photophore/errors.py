"""Typed exception hierarchy for the photophore package.

All exceptions carry a ``code`` string for structured error handling and
machine-readable CLI output (D-14 exit codes).

Exit-code mapping (D-14):
  0  success
  1  generic (ChannelStateError — click default)
  2  config  (ConfigError)
  3  audit chain integrity (AuditChainBrokenError → AuditIntegrityError in CLI)
  4  classifier (ClassifierError)
  5  keystore (KeystoreError, UnauditedChannelError)
"""
from __future__ import annotations

from thermocline import KeystoreUnavailableError  # re-exported from thermocline

__all__ = [
    "PhotophoreError",
    "AuditWriteError",
    "AuditChainBrokenError",
    "UnsupportedChainAlgoError",
    "ChannelStateError",
    "UnauditedChannelError",
    "KeystoreUnavailableError",
    "RulesConfigError",
    "ClassifierError",
    "ShadowIrreversibilityError",
    "PolicyError",
    "DispatchError",
    "DispatchSubcode",
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


class RulesConfigError(PhotophoreError):
    """Raised when path-rules YAML is malformed OR missing the mandatory `**` -> local catch-all (D-08, CLASS-03)."""

    def __init__(self, message: str, *, code: str = "RULES_CONFIG_INVALID") -> None:
        super().__init__(message, code=code)


class ClassifierError(PhotophoreError):
    """Raised when content cannot be decoded or classification otherwise fails."""

    def __init__(self, message: str, *, code: str = "CLASSIFIER_ERROR") -> None:
        super().__init__(message, code=code)


class ShadowIrreversibilityError(PhotophoreError):
    """Hard fail when shadow abstraction leaks source content substrings (SHADOW-04).

    Raised by ``irreversibility_test()`` when the abstraction string contains any
    substring of the source content that is >= ``_IRREVERSIBILITY_MIN_SUBSTR_LEN``
    characters long (8 chars per shadow-quality research finding). Dispatch MUST abort.
    """

    def __init__(self, message: str, *, code: str = "SHADOW_IRREVERSIBILITY_FAILED") -> None:
        super().__init__(message, code=code)


class PolicyError(PhotophoreError):
    """Base class for result-policy authoring failures (POLICY-01..03)."""

    def __init__(self, message: str, *, code: str = "POLICY_ERROR") -> None:
        super().__init__(message, code=code)


# Late re-exports — DispatchError + DispatchSubcode live in photophore.dispatch._errors
# but are surfaced here so callers can do `from photophore.errors import DispatchError`.
#
# Lazy via module-level __getattr__ (PEP 562) so that importing photophore.errors at
# package-init time does NOT eagerly load photophore.dispatch (which imports audit,
# channels, etc. — and audit imports back into photophore.errors → circular).
def __getattr__(name: str):  # noqa: ANN202
    if name in ("DispatchError", "DispatchSubcode"):
        from .dispatch._errors import DispatchError, DispatchSubcode
        return {"DispatchError": DispatchError, "DispatchSubcode": DispatchSubcode}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
