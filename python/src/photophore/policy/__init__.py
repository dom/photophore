"""photophore.policy — result policy authoring (POLICY-01, POLICY-02, POLICY-03).

Public API:
  author(channel, envelope_draft) -> ResultPolicy     — POLICY-01 + POLICY-02
  compare_result_against_policy(received, policy) -> bool  — POLICY-03 helper
  ResultPolicy  — re-exported from thermocline-py (public since Plan 02-03)
  PolicyError   — base exception for policy authoring failures

Phase 3 dispatch coordinator wires compare_result_against_policy into step 9
(verify-receipt then reject if policy violated; DISP-03).
"""
from __future__ import annotations

from thermocline import ResultPolicy

from ._author import author, compare_result_against_policy
from ..errors import PolicyError

__all__ = [
    "author",
    "compare_result_against_policy",
    "ResultPolicy",
    "PolicyError",
]
