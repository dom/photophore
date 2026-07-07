"""AnchorTarget Protocol and NullAnchor no-op default (AUDIT-07).

v0.1 ships only the Protocol + NullAnchor default. Ring 3 (blockchain)
anchor implementations arrive in v0.4 (RING3-01).

The Protocol is runtime_checkable so callers can use isinstance(obj, AnchorTarget)
to probe for anchor capability without importing concrete classes.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ._types import AuditEntry

__all__ = [
    "AnchorReceipt",
    "AnchorTarget",
    "NullAnchor",
    "HeadAnchor",
    "KeystoreHeadAnchor",
    "keystore_available",
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


# ---------------------------------------------------------------------------
# Head anchor: out-of-band {head hash, entry count} record for tail-truncation
# detection. Ring "1.5": stronger than the bare Ring-1 chain, weaker than a
# Ring-2/Ring-3 external copy.


@runtime_checkable
class HeadAnchor(Protocol):
    """Out-of-band store for the chain head hash + entry count.

    The hash chain alone cannot detect TAIL truncation: deleting the newest
    N entries leaves a prefix that is still a valid chain. A HeadAnchor
    persists the expected head outside audit.db (e.g. the platform keystore,
    which the trust store already relies on per CHAN-04/D-04);
    :meth:`AuditLog.verify_chain` compares the walked head + count against it.

    CONSISTENCY RULE: every writer to a given audit.db must share the same
    head-anchor policy. A writer that appends without updating the anchor
    makes the anchor stale, and verify_chain will (correctly, fail closed)
    report a mismatch.

    Ring-1 residual (documented): an attacker who can modify BOTH audit.db
    and the anchor's backing store (platform keystore compromise), or who
    strikes a log with no anchor record at all, can truncate the tail
    undetected. Ring 2 (shared ledger) and Ring 3 (blockchain anchoring)
    close that gap in later milestones.
    """

    def get(self) -> tuple[str, int] | None:
        """Return (head_hash, entry_count) or None when no record exists."""
        ...  # Protocol stub

    def set(self, head_hash: str, count: int) -> None:
        """Persist the new head hash + entry count (called on every append)."""
        ...  # Protocol stub


_HEAD_ANCHOR_SERVICE = "photophore.audit"


class KeystoreHeadAnchor:
    """HeadAnchor backed by the platform keystore (python-keyring).

    The record lives under service ``photophore.audit`` with a username
    derived from the resolved audit.db path (one record per log file), value
    ``{"head_hash": ..., "count": ...}`` as JSON. Storing it in the keystore
    puts it on the same trust footing as the channel trust store (CHAN-04):
    tampering with the anchor requires a platform-keystore compromise, not
    just filesystem access to audit.db.
    """

    def __init__(self, db_path: Path | str) -> None:
        import blake3

        resolved = str(Path(db_path).resolve())
        self._username = (
            "head:" + blake3.blake3(resolved.encode("utf-8")).hexdigest()[:32]
        )

    def get(self) -> tuple[str, int] | None:
        import json

        import keyring

        raw = keyring.get_password(_HEAD_ANCHOR_SERVICE, self._username)
        if raw is None:
            return None
        record = json.loads(raw)
        return str(record["head_hash"]), int(record["count"])

    def set(self, head_hash: str, count: int) -> None:
        import json

        import keyring

        keyring.set_password(
            _HEAD_ANCHOR_SERVICE,
            self._username,
            json.dumps({"head_hash": head_hash, "count": count}),
        )


def keystore_available() -> bool:
    """True when a real keystore backend is present (not fail/null).

    Used by the CLI factory to decide whether a :class:`KeystoreHeadAnchor`
    can be attached. Mirrors the isinstance-probe pattern from
    photophore.channels._keystore without importing across module boundaries
    (audit and channels only share photophore.core).
    """
    import keyring
    from keyring.backends import fail as _fail_backend
    from keyring.backends import null as _null_backend

    try:
        backend = keyring.get_keyring()
    except Exception:  # noqa: BLE001 — any probe failure means "not available"
        return False
    return not isinstance(backend, (_fail_backend.Keyring, _null_backend.Keyring))
