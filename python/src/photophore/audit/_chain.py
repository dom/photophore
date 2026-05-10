"""BLAKE3 chain hash with versioned algo dispatch (AUDIT-02).

Hash domain (D-03):
    entry_hash = blake3(canonicalize(entry_dict minus entry_hash field))

The algo_version field encodes both the hash function AND the domain rule.
A future blake3-v2 may change either; the verifier dispatches per entry's
own algo_version so old entries remain verifiable forever (AUDIT-02).

Pitfall 11 compliance: hash domain uses thermocline.canonicalize (RFC 8785 / JCS),
NEVER json.dumps. The rfc8785 library guarantees stable ordering.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping

import blake3 as _blake3
from thermocline import canonicalize

from ..errors import UnsupportedChainAlgoError

__all__ = [
    "ALGO_VERSION_DEFAULT",
    "_HASH_ALGO_REGISTRY",
    "compute_hash_by_version",
    "compute_entry_hash",
    "verify_entry_hash",
]

ALGO_VERSION_DEFAULT: str = "blake3-v1"

# Forward-compatible registry. Future versions (blake3-v2, sha3-v1) are added here.
# The single entry in v0.1 prevents speculative complexity while keeping the dispatch path.
_HASH_ALGO_REGISTRY: dict[str, Callable[[bytes], str]] = {
    "blake3-v1": lambda data: _blake3.blake3(data).hexdigest(),
}


def compute_hash_by_version(algo_version: str, data: bytes) -> str:
    """Dispatch to the correct hash function by algo_version string.

    Raises UnsupportedChainAlgoError for any version not in _HASH_ALGO_REGISTRY.
    This is the AUDIT-02 forward-compatibility gate: old entries remain verifiable
    even after _HASH_ALGO_REGISTRY gains new entries.
    """
    fn = _HASH_ALGO_REGISTRY.get(algo_version)
    if fn is None:
        raise UnsupportedChainAlgoError(
            f"unknown algo_version: {algo_version!r}; known versions: {sorted(_HASH_ALGO_REGISTRY)}",
            code="UNSUPPORTED_CHAIN_ALGO",
        )
    return fn(data)


def compute_entry_hash(entry_minus_hash: Mapping[str, Any]) -> str:
    """Compute entry_hash = blake3(canonicalize(entry minus entry_hash field)).

    D-03: the hash domain is the canonical-JSON of the whole entry EXCLUDING
    the entry_hash field itself. The caller MUST strip entry_hash before calling.

    Raises ValueError if entry_minus_hash still contains the entry_hash key
    (defensive: prevents accidental circular hashing).
    """
    if "entry_hash" in entry_minus_hash:
        raise ValueError(
            "compute_entry_hash refuses input that still carries the entry_hash field; "
            "strip it before calling."
        )
    algo = str(entry_minus_hash.get("algo_version", ALGO_VERSION_DEFAULT))
    canonical_bytes = canonicalize(dict(entry_minus_hash))
    return compute_hash_by_version(algo, canonical_bytes)


def verify_entry_hash(entry: Mapping[str, Any]) -> bool:
    """Return True if entry['entry_hash'] matches the recomputed hash of the entry.

    Returns False (not raises) so the chain walker can report the broken entry_id.
    """
    if "entry_hash" not in entry:
        return False
    entry_minus = {k: v for k, v in entry.items() if k != "entry_hash"}
    try:
        expected = compute_entry_hash(entry_minus)
    except (UnsupportedChainAlgoError, ValueError):
        return False
    return expected == str(entry["entry_hash"])
