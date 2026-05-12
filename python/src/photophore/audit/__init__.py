"""photophore.audit — append-only, cryptographically chained audit log.

Public API for Plan 02-01 (and downstream 02-02, 02-03, Phase 3):
    from photophore.audit import (
        AuditLog, AuditEntry, asdict, from_dict,
        AnchorTarget, NullAnchor, AnchorReceipt,
        AuditWriteError, AuditChainBrokenError, UnsupportedChainAlgoError,
    )

Internal _* modules are NOT part of the public API. Import only from here.
"""
from __future__ import annotations

from ._anchor import AnchorReceipt, AnchorTarget, NullAnchor
from ._cli_invocation import append_cli_invocation
from ._store import AuditLog
from ._types import AuditEntry, asdict, from_dict
from ..errors import AuditChainBrokenError, AuditWriteError, UnsupportedChainAlgoError

__all__ = [
    "AuditLog",
    "AuditEntry",
    "asdict",
    "from_dict",
    "AnchorTarget",
    "NullAnchor",
    "AnchorReceipt",
    "append_cli_invocation",
    "AuditWriteError",
    "AuditChainBrokenError",
    "UnsupportedChainAlgoError",
]
