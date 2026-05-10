"""AnchorTarget Protocol and NullAnchor no-op default (AUDIT-07).

v0.1 ships only the Protocol + NullAnchor default. Ring 3 (blockchain)
anchor implementations arrive in v0.4 (RING3-01).

The Protocol is runtime_checkable so callers can use isinstance(obj, AnchorTarget)
to probe for anchor capability without importing concrete classes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ._types import AuditEntry

__all__ = [
    "AnchorReceipt",
    "AnchorTarget",
    "NullAnchor",
]


@dataclass(frozen=True)
class AnchorReceipt:
    """Confirmation that an audit entry was posted to a backing anchor store.

    v0.1 ships only the type definition; NullAnchor.anchor() always returns None.
    The first real anchor (Arweave Ring 3) will return a non-None AnchorReceipt.
    """

    target: str    # e.g. "arweave:tx/<txid>" or "noop://"
    timestamp: str  # ISO 8601 UTC


@runtime_checkable
class AnchorTarget(Protocol):
    """Ring 3 (blockchain/decentralized) anchor target.

    Implementations post each audit entry to a permanent append store and return
    an AnchorReceipt identifying the posting. Return None for no-op behavior.
    """

    def anchor(self, entry: AuditEntry) -> AnchorReceipt | None:
        """Post the audit entry to the anchor backing store.

        Returns None on no-op (e.g., NullAnchor) or an AnchorReceipt on success.
        Must not raise on no-op — raising is reserved for real transport failures.
        """
        ...  # Protocol stub


class NullAnchor:
    """No-op default anchor target (AUDIT-07 smoke test target).

    AuditLog uses NullAnchor when no anchor is supplied. The smoke test
    verifies that passing NullAnchor() to AuditLog(anchor=...) and appending
    an entry succeeds without raising.
    """

    def anchor(self, entry: AuditEntry) -> AnchorReceipt | None:
        """No-op — returns None unconditionally."""
        return None
