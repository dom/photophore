"""photophore.channels — channel registry backed by the platform keystore.

Public API for Plan 02-01 (and downstream 02-02, 02-03, Phase 3):
    from photophore.channels import (
        Channel, ChannelStore, ChannelState,
        ChannelStateError, UnauditedChannelError,
        bootstrap,
    )

D-04: Three-store model (keystore + channels.db + audit.db — NEVER co-located).
D-05: bootstrap() walks the _index sentinel, halts on unaudited channels.
D-07: D-07 three-step write ordering enforced by ChannelStore.create/transition_to/set_ceiling.
"""
from __future__ import annotations

from ._bootstrap import bootstrap
from ._store import ChannelStore
from ._types import Channel
from ..core import ChannelState
from ..errors import ChannelStateError, UnauditedChannelError

__all__ = [
    "Channel",
    "ChannelStore",
    "ChannelState",
    "ChannelStateError",
    "UnauditedChannelError",
    "bootstrap",
]
