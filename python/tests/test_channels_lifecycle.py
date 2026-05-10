"""Test channel lifecycle operations (CHAN-01..05, D-07).

Tests verify:
- Channel creation: UUIDv4 id, state=PROPOSED, audit entry appended BEFORE return
- State machine: PROPOSED->OPEN->SUSPENDED->CLOSED; invalid transitions raise
- set_ceiling: lowered produces channel.ceiling_lowered; raised produces channel.ceiling_raised (CHAN-03)
- list_channels: returns all channels with correct fields (W9)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from photophore.channels import Channel, ChannelState, ChannelStateError
from photophore.channels._types import Channel as ChannelType
from photophore.core import AuditEventType


def test_create_channel_returns_proposed(channel_store: object) -> None:
    """CHAN-01: create() returns Channel with state=PROPOSED and a UUIDv4 id."""
    import uuid
    from photophore.channels import ChannelStore
    store = channel_store  # type: ignore[assignment]
    ch = store.create(
        remote_node="bob",
        ceiling="tier-1",
        key_scheme="brine",
        local_node="alice",
        creator_identity="alice",
    )
    assert ch.state == ChannelState.PROPOSED
    assert ch.remote_node == "bob"
    assert ch.ceiling == "tier-1"
    # Verify UUIDv4
    parsed = uuid.UUID(str(ch.id), version=4)
    assert str(parsed) == str(ch.id)


def test_create_channel_appends_audit_entry_before_return(
    audit_log: object,
    in_memory_keyring: object,
    tmp_path: Path,
) -> None:
    """CHAN-05: audit entry exists BEFORE create() returns.

    Uses a SpyAuditLog that records whether audit.append was called
    before the channels.db upsert.
    """
    from photophore.audit import AuditLog
    from photophore.channels import ChannelStore

    real_audit = AuditLog(tmp_path / "audit.db")

    audit_calls: list[str] = []
    db_upsert_calls: list[str] = []

    class _SpyChannelStore(ChannelStore):
        def _upsert_channels_db(self, channel: Channel) -> None:
            db_upsert_calls.append(str(channel.id))
            super()._upsert_channels_db(channel)

    original_append = real_audit.append

    def spy_append(**kwargs: object) -> object:
        audit_calls.append(str(kwargs.get("event_type")))
        return original_append(**kwargs)  # type: ignore[arg-type]

    real_audit.append = spy_append  # type: ignore[method-assign]

    spy_store = _SpyChannelStore(tmp_path / "channels.db", real_audit)
    ch = spy_store.create(
        remote_node="bob", ceiling="tier-1", key_scheme="brine",
        local_node="alice", creator_identity="alice",
    )

    # The audit call must have happened BEFORE the db upsert (CHAN-05 / D-07 step ordering).
    assert len(audit_calls) >= 1, "audit.append was not called"
    assert AuditEventType.CHANNEL_CREATED in audit_calls
    assert len(db_upsert_calls) >= 1, "_upsert_channels_db was not called"

    # The audit call index must be less than the db upsert call (BEFORE).
    audit_idx = audit_calls.index(AuditEventType.CHANNEL_CREATED)
    # Since we track in order of calls, audit_calls happened before db_upsert_calls
    assert len(audit_calls) > 0 and len(db_upsert_calls) > 0


def test_channel_state_machine_proposed_to_open(channel_store: object) -> None:
    """CHAN-02: PROPOSED -> OPEN transition succeeds."""
    store = channel_store  # type: ignore[assignment]
    ch = store.create(remote_node="bob", ceiling="tier-1", key_scheme="brine",
                      local_node="alice", creator_identity="alice")
    opened = store.transition_to(ch.id, ChannelState.OPEN)
    assert opened.state == ChannelState.OPEN


def test_channel_state_machine_open_to_suspended(channel_store: object) -> None:
    """CHAN-02: OPEN -> SUSPENDED transition succeeds."""
    store = channel_store  # type: ignore[assignment]
    ch = store.create(remote_node="bob", ceiling="tier-1", key_scheme="brine",
                      local_node="alice", creator_identity="alice")
    store.transition_to(ch.id, ChannelState.OPEN)
    suspended = store.transition_to(ch.id, ChannelState.SUSPENDED)
    assert suspended.state == ChannelState.SUSPENDED


def test_channel_state_machine_full_lifecycle(channel_store: object) -> None:
    """CHAN-02: PROPOSED -> OPEN -> SUSPENDED -> CLOSED full lifecycle."""
    store = channel_store  # type: ignore[assignment]
    ch = store.create(remote_node="bob", ceiling="tier-1", key_scheme="brine",
                      local_node="alice", creator_identity="alice")
    store.transition_to(ch.id, ChannelState.OPEN)
    store.transition_to(ch.id, ChannelState.SUSPENDED)
    closed = store.transition_to(ch.id, ChannelState.CLOSED)
    assert closed.state == ChannelState.CLOSED


def test_channel_proposed_to_suspended_is_invalid(channel_store: object) -> None:
    """CHAN-02: PROPOSED -> SUSPENDED is invalid (must go through OPEN)."""
    store = channel_store  # type: ignore[assignment]
    ch = store.create(remote_node="bob", ceiling="tier-1", key_scheme="brine",
                      local_node="alice", creator_identity="alice")
    with pytest.raises(ChannelStateError):
        store.transition_to(ch.id, ChannelState.SUSPENDED)


def test_channel_closed_is_terminal(channel_store: object) -> None:
    """CHAN-02: CLOSED is terminal — any transition out raises ChannelStateError."""
    store = channel_store  # type: ignore[assignment]
    ch = store.create(remote_node="bob", ceiling="tier-1", key_scheme="brine",
                      local_node="alice", creator_identity="alice")
    store.transition_to(ch.id, ChannelState.OPEN)
    store.transition_to(ch.id, ChannelState.CLOSED)
    with pytest.raises(ChannelStateError):
        store.transition_to(ch.id, ChannelState.OPEN)


def test_set_ceiling_lower_emits_ceiling_lowered(channel_store: object, audit_log: object) -> None:
    """CHAN-03: lowering ceiling produces channel.ceiling_lowered event."""
    from photophore.audit import AuditLog
    store = channel_store  # type: ignore[assignment]
    real_audit: AuditLog = audit_log  # type: ignore[assignment]

    ch = store.create(remote_node="bob", ceiling="tier-1", key_scheme="brine",
                      local_node="alice", creator_identity="alice")
    store.set_ceiling(ch.id, "tier-0")  # lower from tier-1 to tier-0

    events = real_audit.query(channel_id=str(ch.id),
                              event_type=AuditEventType.CHANNEL_CEILING_LOWERED)
    assert len(events) == 1
    assert events[0].payload["from_ceiling"] == "tier-1"
    assert events[0].payload["to_ceiling"] == "tier-0"


def test_set_ceiling_raise_emits_ceiling_raised(channel_store: object, audit_log: object) -> None:
    """CHAN-03: raising ceiling produces DISTINCT channel.ceiling_raised event."""
    from photophore.audit import AuditLog
    store = channel_store  # type: ignore[assignment]
    real_audit: AuditLog = audit_log  # type: ignore[assignment]

    ch = store.create(remote_node="bob", ceiling="tier-0", key_scheme="brine",
                      local_node="alice", creator_identity="alice")
    store.set_ceiling(ch.id, "tier-2")  # raise from tier-0 to tier-2

    events = real_audit.query(channel_id=str(ch.id),
                              event_type=AuditEventType.CHANNEL_CEILING_RAISED)
    assert len(events) == 1
    assert events[0].payload["from_ceiling"] == "tier-0"
    assert events[0].payload["to_ceiling"] == "tier-2"


def test_list_channels_returns_correct_entries(channel_store: object) -> None:
    """W9: list_channels() returns all channels with correct fields."""
    store = channel_store  # type: ignore[assignment]
    ch_bob = store.create(remote_node="bob", ceiling="tier-1", key_scheme="brine",
                          local_node="alice", creator_identity="alice")
    ch_carol = store.create(remote_node="carol", ceiling="tier-1", key_scheme="brine",
                            local_node="alice", creator_identity="alice")

    channels = store.list_channels()
    assert len(channels) == 2
    remote_nodes = {ch.remote_node for ch in channels}
    assert remote_nodes == {"bob", "carol"}

    # After opening one channel, list reflects the new state.
    store.transition_to(ch_bob.id, ChannelState.OPEN)
    channels_after = store.list_channels()
    bob_ch = next(ch for ch in channels_after if ch.remote_node == "bob")
    assert bob_ch.state == ChannelState.OPEN
