# Changelog

All notable changes to Photophore are documented here. The format is a lite
variant of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semantic
versioning per [SemVer](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-07-07

Security-hardening release driven by the zero-trust review findings; version
aligned with the Thermocline 0.4.0 contract (see README inline changelog
§0.4.0 for the spec-facing summary).

### Security

- Dispatch coordinator enforces classification before signing: tier-0 blocks
  are hard-dropped (raw bytes never reach the wire) and tier-1 blocks cross
  only as freshly generated shadows.
- Channel trust ceiling is enforced against effective block tiers; a single
  over-ceiling block aborts the dispatch (fail closed), and an unknown
  ceiling string refuses to dispatch.
- Envelopes are signed per the SP-3.3 wire contract (thermocline 0.4.0
  `sign_envelope` / `verify_envelope`).
- Embedded `@photophore:(local|shared|public)` tags are parsed from untrusted
  content bytes and may only LOWER a block's tier, never raise it above the
  path-rule/classifier assignment (AT-A3 classifier-evasion fix);
  `@photophore:public` inside a `~/Private/**` secret stays local.
- Result policies fail closed: tier-0 `return_only=[]` means "return
  nothing" (any returned field is a POLICY-03 violation), and tier-1
  persistence is an allow-list of shadow-reference field names (unknown
  names are rejected; the old content/raw_output name-blacklist remains as
  defense in depth). Tier-2 keeps its permissive v0.1 template by opting in
  explicitly with a `"*"` wildcard.
- Audit tail truncation is detected via an out-of-band head anchor
  (expected head hash + entry count in the platform keystore, updated on
  every append and checked by `verify_chain`). Residual: detection requires
  the anchor; a bare Ring-1 chain without it still verifies after
  truncation, and keystore compromise defeats the anchor (outside the
  threat boundary).
- `AuditLog.append()` serializes its read-then-write with a lock; concurrent
  appends can no longer fork the chain.

### Fixed

- Audit chain verification, query, and export walk entries by `rowid`
  (true append order) instead of timestamp; same-millisecond bursts and
  caller-supplied timestamps no longer scramble or reorder the walk
  (closes the 0.1.0 "timestamp ordering quirk" known limitation).
- `photophore dispatch` loads path rules for dispatch-time classification
  (new `--rules` flag; D-09 default location fallback), so enforcement and
  warnings see the same rules as `photophore classify`.

### Changed

- Dependency: `thermocline>=0.4.0` (ContentBlock rejects raw tier-0 content
  and requires tier-1 to be shadow-only).
- Package version 0.4.0 (`pyproject.toml`, `photophore.version`).
- README: version banner 0.4.0; Trust Score pillar and job/per-step
  shadow generation explicitly marked UNIMPLEMENTED (deferred); AT-A6
  mitigation/residual restated honestly.

## [0.1.0] - 2026-05-13

### Added

- Photophore reference implementation (`photophore/python/`) shipping channels,
  audit log, classifier, shadow generator, policy authoring, dispatch coordinator,
  and full CLI surface.
- New `cli.invoked` audit-entry kind (CLI-06); every CLI subcommand emits an
  invocation entry via `@audit_cli_invocation`. Args containing file paths are
  hashed via BLAKE3 (matches audit-chain hash family); non-secret identifiers
  pass through verbatim.
- `SensitiveFilter` privacy-aware logging filter (CONF-06 / D-09). Walks
  `record.__dict__` + `record.args`; redacts any `Sensitive[T]` instance.
- `_assert_no_sensitive` runtime guard at `AuditLog.append()` boundary
  (defense-in-depth on top of `Sensitive[T]` static typing).
- 6 AT-A* negative tests in `python/tests/at_negative/` (CONF-02).
- Property tests: classifier default, audit chain integrity, shadow uniqueness
  (CONF-03), all at `max_examples=200`.
- New dispatch-integrated shadow uniqueness property test
  (`tests/integration/test_property_dispatch_shadow_uniqueness.py`).
- `(tier=X, reason=Y)` augmentation to `DispatchError` for policy-violation
  and classification-failure paths (CLI-07).

### Implemented

- **CHAN-01..06** — Channel lifecycle, trust store (`python-keyring`), ceiling
  monotonicity (lower unilaterally; raise requires deliberate human act).
- **AUDIT-01..08** — Append-only SQLite audit log with BLAKE3 chain
  (`algo_version="blake3-v1"`). Query/export/verify CLI subcommands.
- **CLASS-01..06** — Explicit tag + path rule + rule-based classifier; default
  every unmatched block to `LOCAL` (tier-0).
- **SHADOW-01..06** — Per-content-type abstractions; UUIDv4 IDs via
  `secrets.token_bytes` over `os.urandom`; no caching at any level.
- **POLICY-01..03** — `result_policy` authoring from channel + envelope draft.
- **DISP-01..06** — 9-step dispatch coordinator; AST-lint network isolation
  forbids non-dispatch HTTP egress from library code.
- **CLI-01..07** — Full CLI surface: audit (query/export/verify), channel
  (new/list/show/suspend/close/set-ceiling/register-pubkey), classify,
  policy preview, dispatch. CLI-06 audit retrofit + CLI-07 (tier, reason)
  error messages.
- **CONF-01..04, CONF-06** — Conformance fixture coverage, AT-* surface
  enumeration, property test cadence, CI gates (ruff + mypy --strict +
  pip-audit + AST lints + at_coverage + property_coverage + pytest),
  `Sensitive[T]` + print-lint + SensitiveFilter.

### Spec dependencies

- Requires **`thermocline-py` 0.3.1** for the SP-3.3-01..03 envelope-signature
  invariants — see `thermocline/README.md` §"Identity Provider Interface"
  §"Dispatch Signatures" + §"Receipt Signatures" and
  `thermocline/CHANGELOG.md` §[0.3.1]. The dispatch coordinator implements
  the matching pre-fill ordering (`dispatch_signature` non-`sig` fields filled
  BEFORE canonicalization), `receipt_signature.sig=""` (empty string, not
  removed) canonicalization on verify, and `sig`/`bytes_hex` tolerance. These
  invariants were co-discovered while integrating the coordinator with the
  reference forges, then promoted to spec-level after we confirmed any
  third-party implementation would otherwise reverse-engineer the Python
  coordinator to discover them.

### Deferred to subsequent milestones

- Job envelopes + per-step shadow generation (Photophore spec v0.2)
- Manifest-embedded `result_policy` authoring (v0.2)
- Ring 2 reconciliation protocol (v0.2)
- Trust score algorithm + model-based classifier (v0.3)
- Multi-hop channels + Ring 3 anchoring (v0.4)
- Per-content trust overrides (v0.5)
- Channel negotiation protocol (v1.0)
- Chain archival (`photophore audit archive`) — v0.1 ships query/export/verify only
- Daemon mode — v0.1 is per-invocation only

### Known limitations

- Default `python-keyring` macOS Keychain entries are software-backed
  (encrypted at rest, gated by user's login session). Hardware-anchored Apple
  Silicon Secure Enclave entries require a developer signing identity; deferred
  to v0.2. The v0.1 threat model is satisfied without Secure Enclave: key
  material never leaves the keystore.
- Linux + Windows ops paths documented best-effort; CI-tested matrix only
  covers `ubuntu-latest` (non-keystore) + `macos-latest` (keystore).
- AT-A5 trust-store tamper-detector is `pytest.skip()` for v0.1; defense is the
  three-store separation (CHAN-04 + ADR-0001).
- Audit-chain timestamp ordering quirk: same-millisecond writes reorder by UUID
  in `verify_chain`. v0.1 workaround: callers pass strictly-monotonic
  timestamps (decorators + test fixtures both do this). v0.2 may switch the
  query to `ORDER BY rowid ASC`.
