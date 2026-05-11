"""asyncio.to_thread shim wrapping Phase 2 sync APIs (D-11 sync-core + thin async shim).

Rule-1 deviation note: the plan draft used positional log.append(entry) but the
real Phase 2 AuditLog.append is kwargs-only and returns AuditEntry. The shim
adapts and returns entry.entry_hash for the coordinator's pre/post_audit_hash
bookkeeping (D-03).
"""
from __future__ import annotations

import asyncio
from typing import Any, Mapping

from ..audit import AuditLog
from ..channels import ChannelStore
from ..channels._types import Channel
from ..classifier import classify, Classification
from ..policy import author as _policy_author, compare_result_against_policy, ResultPolicy
from ..shadow import ContentType, ShadowResult, generate as _shadow_generate


async def audit_append_async(log: AuditLog, *, event_type: str, channel_id: str | None = None,
                             envelope_id: str | None = None,
                             payload: dict[str, Any] | None = None) -> str:
    entry = await asyncio.to_thread(lambda: log.append(
        event_type=event_type, channel_id=channel_id,
        envelope_id=envelope_id, payload=payload))
    return entry.entry_hash


async def channel_show_async(store: ChannelStore, channel_id: str) -> Channel:
    return await asyncio.to_thread(store.show, channel_id)


async def classify_async(content: bytes, *, path: str | None = None) -> Classification:
    return await asyncio.to_thread(lambda: classify(content, path=path))


async def shadow_generate_async(content: bytes, content_type: ContentType) -> ShadowResult:
    return await asyncio.to_thread(_shadow_generate, content, content_type)


async def policy_author_async(channel: Channel, draft: Mapping[str, Any]) -> ResultPolicy:
    return await asyncio.to_thread(_policy_author, channel, draft)


async def policy_compare_async(received: Mapping[str, Any], policy: ResultPolicy) -> bool:
    return await asyncio.to_thread(compare_result_against_policy, received, policy)
