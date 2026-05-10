"""Channel record types and state machine (CHAN-01, CHAN-02).

The Channel dataclass is the authoritative record shape — stored as canonical-JSON
in the keystore (trust store, per D-04) and projected to channels.db (the index).
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from ..core import ChannelId, ChannelState
from ..errors import ChannelStateError

__all__ = ["Channel", "ChannelStateError"]

# CHAN-02: valid state transitions.
# PROPOSED can transition to OPEN (normal) or CLOSED (cancelled before opening).
# OPEN can go to SUSPENDED (pause) or CLOSED (terminate).
# SUSPENDED can go back to OPEN (resume) or CLOSED (terminate).
# CLOSED is terminal — no transitions out.
_VALID_TRANSITIONS: dict[ChannelState, frozenset[ChannelState]] = {
    ChannelState.PROPOSED: frozenset({ChannelState.OPEN, ChannelState.CLOSED}),
    ChannelState.OPEN: frozenset({ChannelState.SUSPENDED, ChannelState.CLOSED}),
    ChannelState.SUSPENDED: frozenset({ChannelState.OPEN, ChannelState.CLOSED}),
    ChannelState.CLOSED: frozenset(),  # terminal
}


@dataclass(frozen=True)
class Channel:
    """Immutable channel record.

    Fields:
    - id: UUIDv4 string (CHAN-01). IDs are never reused (CHAN-02).
    - local_node: sovereign node identity string
    - remote_node: the peer node identity string (CHAN-01)
    - ceiling: "tier-0" | "tier-1" | "tier-2" (trust ceiling per CHAN-01/CHAN-03)
    - key_scheme: "brine" | "pgp" | "x509" | "none"
    - state: current lifecycle state (CHAN-02)
    - created_at: ISO 8601 UTC with "Z" suffix
    - creator_identity: identity of the human/process that created the channel
    - description: optional human-readable description
    - remote_pubkey_hex: public key of the remote node (safe to store — Pitfall 9/4 notes)
    """

    id: ChannelId
    local_node: str
    remote_node: str
    ceiling: str  # "tier-0" | "tier-1" | "tier-2"
    key_scheme: str  # "brine" | "pgp" | "x509" | "none"
    state: ChannelState
    created_at: str  # ISO 8601 UTC "Z" suffix
    creator_identity: str
    description: str = ""
    remote_pubkey_hex: str | None = None  # public key — safe to store

    def transition_to(self, new_state: ChannelState) -> "Channel":
        """Return a new Channel with the updated state, or raise ChannelStateError.

        CHAN-02: validates the transition against _VALID_TRANSITIONS. CLOSED is terminal.
        """
        allowed = _VALID_TRANSITIONS[self.state]
        if new_state not in allowed:
            raise ChannelStateError(
                f"invalid transition {self.state.value!r} -> {new_state.value!r}; "
                f"allowed from {self.state.value!r}: "
                f"{sorted(s.value for s in allowed)}",
                code="CHANNEL_STATE_INVALID",
            )
        return replace(self, state=new_state)
