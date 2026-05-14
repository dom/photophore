# ADR-0001: Trust-store separation from audit log

**Status:** Accepted · 2026-05-12

## Context

The Photophore trust store records channel state (remote node identity, trust
ceiling, key scheme). The audit log records every operation that produced or
modified that state. If both were backed by the same storage, a tamper of the
audit log could silently rewrite history without detection by the trust store
(and vice versa). The third store — the IdentityProvider — must also be
independent so that key material lives nowhere except the platform secure
keystore.

This is the three-store model: each store has its own backing technology, its
own access pattern, and its own threat model. CHAN-04 mandates separation as
a v0.1 requirement; AT-A5 specifically tests for co-location.

## Decision

The Photophore trust store is backed by `python-keyring` (Keychain / libsecret /
Credential Manager). The audit log is backed by SQLite with append-only
triggers. The IdentityProvider's private key material lives in `python-keyring`
under a separate service namespace (`thermocline.brine`, `seamount.piforge`,
etc.). The three stores share no backing technology and no namespace.

## Consequences

- ✓ Tamper of any one store leaves evidence in the other two.
- ✓ `python-keyring` and SQLite have different operational characteristics
  (different threat models); a single attack class rarely defeats both.
- ✓ Test `test_channels_separation.py` enforces the no-mixing rule at CI time.
- ✗ Three stores = three points of operational concern (backup, migration, recovery).
- ✗ Cross-store consistency is application-layer (atomic three-step write pattern in the reference implementation).

## References

- CHAN-04 in `photophore/README.md`
- `photophore/python/tests/test_channels_separation.py`
- [AT-A5 negative test](../../python/tests/at_negative/test_at_a5_trust_store_tampering.py)
