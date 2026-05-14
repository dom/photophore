"""photophore — Photophore privacy policy engine.

Public top-level API:
    from photophore import audit, channels, core, errors
    from photophore.audit import AuditLog, AuditEntry, AnchorTarget, NullAnchor
    from photophore.channels import Channel, ChannelStore, ChannelState, bootstrap
    from photophore.version import __version__

Additional surfaces: photophore.classifier, photophore.shadow,
photophore.policy, and photophore.dispatch (the only async surface in the
suite).
"""
from __future__ import annotations

from . import audit, channels, core, errors
from .version import __version__

__all__ = [
    "audit",
    "channels",
    "core",
    "errors",
    "__version__",
]
