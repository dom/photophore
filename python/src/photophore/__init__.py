"""photophore — Photophore privacy policy engine.

Public top-level API (Plan 02-01 surface):
    from photophore import audit, channels, core, errors
    from photophore.audit import AuditLog, AuditEntry, AnchorTarget, NullAnchor
    from photophore.channels import Channel, ChannelStore, ChannelState
    from photophore.version import __version__

Plan 02-02 will add photophore.classifier.
Plan 02-03 will add photophore.shadow and photophore.policy.
Phase 3 will add photophore.dispatch (the only async surface).
"""
from __future__ import annotations

from . import audit, core, errors
from .version import __version__

__all__ = [
    "audit",
    "core",
    "errors",
    "__version__",
]
