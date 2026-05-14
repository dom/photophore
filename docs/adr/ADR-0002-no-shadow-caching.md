# ADR-0002: No shadow caching

**Status:** Accepted · 2026-05-12

## Context

Shadows are tier-1 abstractions generated at dispatch time. Their identifiers
(`shadow_id`) MUST be unique per dispatch — if they were not, an observer of
the wire traffic could correlate multiple dispatches of the same source content,
defeating the privacy tier. SHADOW-06 mandates the uniqueness invariant.

Caching shadows would be a tempting performance optimization (regenerating the
same abstraction string is wasteful) but would create exactly the correlation
risk the tier exists to prevent. AT-A2 and AT-C3 specifically test this.

## Decision

`photophore.shadow.generate()` produces a fresh `shadow_id` via
`secrets.token_bytes` (UUIDv4 over `os.urandom`) on every call. No caching layer
exists at any level (function, module, process, IPC). The classifier_default
property test plus the dispatch-integrated shadow uniqueness property test
(`tests/integration/test_property_dispatch_shadow_uniqueness.py`) prove the
invariant under N=200 generation cycles.

## Consequences

- ✓ AT-A2 (shadow inference via shadow_id correlation) is structurally prevented.
- ✓ The abstraction string itself MAY repeat (acceptable — it's the visible
  abstraction); only the `shadow_id` MUST differ.
- ✗ Regenerating identical abstractions wastes minor CPU (acceptable cost for
  the privacy guarantee).
- ✗ Distributed coordination is harder: shadow generators in two processes
  must coordinate on uniqueness only via `os.urandom` collision probability
  (acceptable — birthday-paradox math gives 50% collision at ~2^64 shadows).

## References

- SHADOW-06 in REQUIREMENTS.md
- `photophore/python/tests/test_shadow_no_caching.py`
- `photophore/python/tests/test_shadow_uniqueness_property.py` (CONF-03 #4)
- [AT-A2 negative test](../../python/tests/at_negative/test_at_a2_shadow_correlation.py)
