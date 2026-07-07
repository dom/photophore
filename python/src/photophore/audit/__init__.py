"""photophore.audit — append-only, cryptographically chained audit log.

Public API:
    from photophore.audit import (
        AuditLog, AuditEntry, asdict, from_dict,
        AnchorTarget, NullAnchor, AnchorReceipt,
        HeadAnchor, KeystoreHeadAnchor, keystore_available, open_audit_log,
        AuditWriteError, AuditChainBrokenError, UnsupportedChainAlgoError,
    )

Internal _* modules are NOT part of the public API. Import only from here.
"""
from __future__ import annotations

from pathlib import Path

from ..errors import AuditChainBrokenError, AuditWriteError, UnsupportedChainAlgoError
from ._anchor import (
    AnchorReceipt,
    AnchorTarget,
    HeadAnchor,
    KeystoreHeadAnchor,
    NullAnchor,
    keystore_available,
)
from ._cli_invocation import append_cli_invocation
from ._store import AuditLog
from ._types import AuditEntry, asdict, from_dict

__all__ = [
    "AuditLog",
    "AuditEntry",
    "asdict",
    "from_dict",
    "AnchorTarget",
    "NullAnchor",
    "AnchorReceipt",
    "HeadAnchor",
    "KeystoreHeadAnchor",
    "keystore_available",
    "open_audit_log",
    "append_cli_invocation",
    "AuditWriteError",
    "AuditChainBrokenError",
    "UnsupportedChainAlgoError",
]


def open_audit_log(path: Path | str) -> AuditLog:
    """Canonical factory for CLI / coordinator audit-log access.

    Attaches a :class:`KeystoreHeadAnchor` when a real keystore backend is
    available, so every append updates the out-of-band head record and
    ``verify_chain`` detects tail truncation. Falls back to a bare (Ring-1
    chain only) AuditLog on keystore-less hosts; that residual is documented
    on :class:`HeadAnchor`.

    CONSISTENCY: all writers to one audit.db must share the anchor policy.
    Use this factory (not the raw constructor) everywhere a real photophore
    deployment appends or verifies.
    """
    p = Path(path)
    if keystore_available():
        return AuditLog(p, head_anchor=KeystoreHeadAnchor(p))
    return AuditLog(p)
