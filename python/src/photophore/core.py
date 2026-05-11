"""Shared types used across photophore.{audit, channels, classifier, shadow, policy, cli}.

OQ-5 resolved: flat module (not a package) to avoid circular imports.
All shared enums, NewTypes, and constants live here. No module under
photophore.{audit, channels, classifier, shadow, policy} imports from each
other — they all import from photophore.core.
"""
from __future__ import annotations

from enum import Enum
from typing import NewType

# ---------------------------------------------------------------------------
# Privacy tier — the fundamental classification axis (CLASS-01..06).

class Tier(Enum):
    """Content privacy tier. Defaults to LOCAL; transmission is the exception."""
    LOCAL = "local"
    SHARED = "shared"
    PUBLIC = "public"


# ---------------------------------------------------------------------------
# ID NewTypes — opaque strings with no runtime overhead.
# Provides type discipline across module boundaries without boxing.

ChannelId = NewType("ChannelId", str)
AuditEntryId = NewType("AuditEntryId", str)
ShadowId = NewType("ShadowId", str)


# ---------------------------------------------------------------------------
# Channel state machine (CHAN-02).

class ChannelState(Enum):
    """Channel lifecycle states. CLOSED is terminal; IDs are never reused."""
    PROPOSED = "PROPOSED"
    OPEN = "OPEN"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"


# ---------------------------------------------------------------------------
# Audit event-type vocabulary.
# String constants for cross-module consistency; the KNOWN_EVENT_TYPES frozenset
# lets _store.py validate incoming event_type arguments at the API boundary.

class AuditEventType:
    """String constants for every audit event type shipped in Phase 2.

    Channel lifecycle (Plan 02-01):
    - CHANNEL_CREATED: new channel registered
    - CHANNEL_OPENED: PROPOSED -> OPEN transition
    - CHANNEL_SUSPENDED: OPEN -> SUSPENDED transition
    - CHANNEL_CLOSED: any -> CLOSED (terminal)
    - CHANNEL_CEILING_LOWERED: ceiling reduced (CHAN-03)
    - CHANNEL_CEILING_RAISED: ceiling raised — DISTINCT event per CHAN-03

    Dispatch lifecycle (Phase 3 scope):
    - DISPATCH_PRE: before dispatch; AUDIT-04 payload
    - DISPATCH_RECEIPT: after receipt verification
    - DISPATCH_FAILED: dispatch aborted

    CLI invocations (Phase 4 wires every CLI subcommand to emit one):
    - CLI_INVOKED: records which subcommand ran (CLI-06 scope, Phase 4)
    """

    # Channel lifecycle
    CHANNEL_CREATED: str = "channel.created"
    CHANNEL_OPENED: str = "channel.opened"
    CHANNEL_SUSPENDED: str = "channel.suspended"
    CHANNEL_CLOSED: str = "channel.closed"
    CHANNEL_CEILING_LOWERED: str = "channel.ceiling_lowered"
    CHANNEL_CEILING_RAISED: str = "channel.ceiling_raised"

    # Channel lifecycle additions for Phase 3 D-01 fetched-pubkey TOFU registration.
    # Logged by `photophore channel new --fetch-pubkey-from URL` between the keystore
    # write and the channels.db upsert (D-07 atomic three-step).
    CHANNEL_PUBKEY_REGISTERED: str = "channel.pubkey_registered"

    # Dispatch lifecycle (Phase 3)
    DISPATCH_PRE: str = "dispatch.pre"
    DISPATCH_RECEIPT: str = "dispatch.receipt"
    DISPATCH_FAILED: str = "dispatch.failed"

    # CLI invocations (Phase 4)
    CLI_INVOKED: str = "cli.invoked"


# All known event types — used by AuditLog.append() for defensive validation.
KNOWN_EVENT_TYPES: frozenset[str] = frozenset({
    AuditEventType.CHANNEL_CREATED,
    AuditEventType.CHANNEL_OPENED,
    AuditEventType.CHANNEL_SUSPENDED,
    AuditEventType.CHANNEL_CLOSED,
    AuditEventType.CHANNEL_CEILING_LOWERED,
    AuditEventType.CHANNEL_CEILING_RAISED,
    AuditEventType.CHANNEL_PUBKEY_REGISTERED,
    AuditEventType.DISPATCH_PRE,
    AuditEventType.DISPATCH_RECEIPT,
    AuditEventType.DISPATCH_FAILED,
    AuditEventType.CLI_INVOKED,
})
