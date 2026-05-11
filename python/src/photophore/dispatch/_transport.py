"""httpx async transport for dispatch step 7 (DISP-05: the ONLY network I/O in photophore).

Maps httpx exceptions to the appropriate DispatchSubcode per CONTEXT D-03:
  - httpx.TimeoutException → TRANSPORT_TIMEOUT (retryable)
  - httpx.ConnectError → TRANSPORT_REFUSED (retryable)
  - httpx.HTTPError (catch-all) → TRANSPORT_REFUSED (retryable)
  - Non-JSON response body → RECEIPT_MALFORMED (non-retryable, stage 8)
"""
from __future__ import annotations

from typing import Any

import httpx

from ._errors import DispatchError, DispatchSubcode


async def send_async(
    url: str,
    *,
    signed_envelope: dict[str, Any],
    timeout_s: float = 30.0,
    envelope_id: str | None = None,
    channel_id: str | None = None,
    audit_entry_hash: str | None = None,
) -> dict[str, Any]:
    """POST signed_envelope to forge URL. Returns parsed task_result JSON dict.

    Raises DispatchError(TRANSPORT_TIMEOUT) on httpx.TimeoutException.
    Raises DispatchError(TRANSPORT_REFUSED) on httpx.ConnectError or other httpx errors.
    Raises DispatchError(RECEIPT_MALFORMED, stage=8) on non-JSON response body.
    """
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_s)) as client:
        try:
            response = await client.post(
                url,
                json=signed_envelope,
                headers={"Content-Type": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise DispatchError(
                f"forge timeout: {exc}",
                subcode=DispatchSubcode.TRANSPORT_TIMEOUT,
                stage=7,
                envelope_id=envelope_id,
                channel_id=channel_id,
                audit_entry_hash=audit_entry_hash,
            ) from exc
        except httpx.ConnectError as exc:
            raise DispatchError(
                f"forge connection refused: {exc}",
                subcode=DispatchSubcode.TRANSPORT_REFUSED,
                stage=7,
                envelope_id=envelope_id,
                channel_id=channel_id,
                audit_entry_hash=audit_entry_hash,
            ) from exc
        except httpx.HTTPError as exc:
            raise DispatchError(
                f"forge http error: {exc}",
                subcode=DispatchSubcode.TRANSPORT_REFUSED,
                stage=7,
                envelope_id=envelope_id,
                channel_id=channel_id,
                audit_entry_hash=audit_entry_hash,
            ) from exc
    try:
        return response.json()  # type: ignore[no-any-return]
    except Exception as exc:  # noqa: BLE001 — broad: any deserialization failure is malformed
        raise DispatchError(
            f"forge response not JSON: {exc}",
            subcode=DispatchSubcode.RECEIPT_MALFORMED,
            stage=8,
            envelope_id=envelope_id,
            channel_id=channel_id,
            audit_entry_hash=audit_entry_hash,
        ) from exc


__all__ = ["send_async"]
