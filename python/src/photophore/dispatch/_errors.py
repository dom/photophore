"""DispatchError + DispatchSubcode (D-03; exit code 6 family).

There are 12 distinct DispatchSubcode members. Stage 7 (transport) splits
into TRANSPORT_TIMEOUT and TRANSPORT_REFUSED — two subcodes, not one.
"""
from __future__ import annotations

from enum import StrEnum

from ..errors import PhotophoreError


class DispatchSubcode(StrEnum):
    CHANNEL_RESOLVE_FAILED = "CHANNEL_RESOLVE_FAILED"
    CLASSIFICATION_FAILED = "CLASSIFICATION_FAILED"
    SHADOW_GENERATION_FAILED = "SHADOW_GENERATION_FAILED"
    POLICY_AUTHORING_FAILED = "POLICY_AUTHORING_FAILED"
    AUDIT_FAILED_PRE = "AUDIT_FAILED_PRE"
    SIGNING_FAILED = "SIGNING_FAILED"
    TRANSPORT_TIMEOUT = "TRANSPORT_TIMEOUT"
    TRANSPORT_REFUSED = "TRANSPORT_REFUSED"
    RECEIPT_MALFORMED = "RECEIPT_MALFORMED"
    RECEIPT_INVALID = "RECEIPT_INVALID"
    POLICY_VIOLATED = "POLICY_VIOLATED"
    AUDIT_FAILED_POST = "AUDIT_FAILED_POST"


_RETRYABLE: frozenset[DispatchSubcode] = frozenset({
    DispatchSubcode.AUDIT_FAILED_PRE,
    DispatchSubcode.SIGNING_FAILED,
    DispatchSubcode.TRANSPORT_TIMEOUT,
    DispatchSubcode.TRANSPORT_REFUSED,
    DispatchSubcode.AUDIT_FAILED_POST,
})


class DispatchError(PhotophoreError):
    """Raised by photophore.dispatch.dispatch_async on any 9-step failure (D-03).

    CLI-07 (D-08) augmentation: when a classification or policy failure
    causes the dispatch to block on a specific content block, the coordinator
    MAY set ``blocked_block_path``, ``blocked_tier``, and ``blocked_reason``.
    The CLI surfaces these as ``(tier=X, reason=Y)`` suffixes on the
    human-readable error message so users can diagnose blocks without diving
    into the audit log.

    These fields are optional and default to None for backward compatibility
    with call sites that do not populate them.
    """

    def __init__(
        self,
        message: str,
        *,
        subcode: DispatchSubcode,
        stage: int,
        envelope_id: str | None = None,
        channel_id: str | None = None,
        audit_entry_hash: str | None = None,
        # CLI-07 / D-08 — diagnostic fields for classification/policy blocks
        blocked_block_path: str | None = None,
        blocked_tier: str | None = None,
        blocked_reason: str | None = None,
    ) -> None:
        super().__init__(message, code=str(subcode))
        self.subcode = subcode
        self.stage = stage
        self.retryable = subcode in _RETRYABLE
        self.envelope_id = envelope_id
        self.channel_id = channel_id
        self.audit_entry_hash = audit_entry_hash
        # CLI-07 (D-08)
        self.blocked_block_path = blocked_block_path
        self.blocked_tier = blocked_tier
        self.blocked_reason = blocked_reason


__all__ = ["DispatchError", "DispatchSubcode"]
