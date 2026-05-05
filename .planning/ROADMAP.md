# Roadmap: Photophore v0.1

## Overview

The journey is from a published spec (README.md, Photophore v0.3.0-draft) to a working v0.1 reference implementation in Rust. Phase 1 lays the privacy-critical foundations (audit log with versioned chain hashing; trust store backed by the platform keystore — separate from SQLite by mandate). Phase 2 builds the privacy primitives in isolation (three-tier classifier, shadow generator with hard-fail irreversibility test, result-policy authoring) — all pure functions, easy to unit-test. Phase 3 integrates everything through the dispatch coordinator and identity-provider adapter, closing the round-trip privacy receipt over real envelopes. Phase 4 hardens the surface with property tests, conformance fixtures, ADRs, and ops docs, and tags the v0.1 release. At completion, a sovereign-node user can establish trusted channels, dispatch Thermocline `task` envelopes through the full classify→shadow→sign→verify pipeline, and receive a tamper-evident audit log proving exactly what crossed each boundary.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3, 4): Planned milestone work
- Decimal phases (e.g., 2.1): Reserved for urgent insertions only (none planned)

- [ ] **Phase 1: Foundations — Audit Log and Trust Store** — SQLite-backed append-only audit log with versioned chain hashing, plus channel registry backed by the platform keystore.
- [ ] **Phase 2: Privacy Primitives — Classifier, Shadow, Policy** — Three-tier classification, dispatch-time shadow generation with quality gates, and result-policy authoring.
- [ ] **Phase 3: Integration — Identity Provider and Dispatch Coordinator** — End-to-end dispatch flow with delegated signing and round-trip privacy receipts.
- [ ] **Phase 4: Hardening, Conformance, and v0.1 Release** — Property tests, threat-model negative tests, ADRs, ops docs, and tagged release.

## Phase Details

### Phase 1: Foundations — Audit Log and Trust Store

**Goal**: Establish the two non-negotiable foundations that every other phase builds on — the cryptographically chained audit log (with versioned `algo_version`) and the platform-keystore-backed channel registry. Audit-log schema is a forever-decision; getting it right (and getting trust-store separation right) before any privacy logic exists is essential.

**Depends on**: Nothing (first phase)

**Requirements**:
- CHAN-01, CHAN-02, CHAN-03, CHAN-04, CHAN-05, CHAN-06
- AUDIT-01, AUDIT-02, AUDIT-03, AUDIT-04, AUDIT-05, AUDIT-06, AUDIT-07, AUDIT-08
- CLI-01, CLI-02

**Success Criteria** (what must be TRUE):
  1. User can run `photophore channel new --remote-node <id> --ceiling tier-1 --key-scheme ed25519` and the channel appears in `photophore channel list` with status PROPOSED.
  2. User can advance, suspend, and close a channel; `photophore channel show <id>` reflects each lifecycle transition and each transition produces an audit log entry recorded before the operation reports success.
  3. User can run `photophore audit query --channel <id>` and receive chronologically ordered entries with chain integrity verified over the returned slice; tampering with any entry's bytes invalidates all subsequent entries on a re-verify.
  4. The trust store persists across process restarts via the platform keystore and is not present in the SQLite audit database (separate backing stores demonstrably enforced).
  5. `photophore audit export --output audit.jsonl` produces a JSON Lines file plus a separate chain-head proof; the export records the `algo_version` so a future verifier can re-validate.

**Plans**: 3 plans

Plans:
- [ ] 01-01: Workspace skeleton, `core/` crate, and shared types (Channel, Tier, Reason, ShadowId, Envelope alias, error taxonomy).
- [ ] 01-02: `audit/` crate — SQLite append-only chained log with `algo_version` field, query/export, `AnchorTarget` trait + no-op default; `photophore audit` CLI subcommand.
- [ ] 01-03: `channels/` crate — trust store backed by `keyring`, channel lifecycle + ceiling rules; `photophore channel` CLI subcommand; integration test demonstrating audit emissions on every channel mutation.

---

### Phase 2: Privacy Primitives — Classifier, Shadow, Policy

**Goal**: Build the three privacy-critical primitives in isolation as pure functions: the three-tier classifier with strict priority order, the shadow generator with the hard-fail irreversibility test, and the result-policy author. These have no I/O; they can be developed and unit-tested without coordinator complexity.

**Depends on**: Phase 1 (uses `core/` types; emits explanations into the audit log defined in Phase 1)

**Requirements**:
- CLASS-01, CLASS-02, CLASS-03, CLASS-04, CLASS-05, CLASS-06
- SHADOW-01, SHADOW-02, SHADOW-03, SHADOW-04, SHADOW-05, SHADOW-06
- POLICY-01, POLICY-02, POLICY-03
- CLI-04, CLI-05

**Success Criteria** (what must be TRUE):
  1. User can run `photophore classify <path>` and receive `(tier, reason)` for each block, where the reason is one of `explicit_tag`, `path_rule:<pattern>`, `classifier:<rule>`, `classifier:default`; explicit tags demonstrably override path rules, which override the rule-based classifier.
  2. Loading a path-rules config that lacks the mandatory `**` → `local` catch-all is refused with a specific error; loading a valid config reports rule count and order; an invariant test asserts that any unmatched block returns `(Local, ClassifierDefault)`.
  3. Generating shadows over arbitrary content produces a unique `shadow_id` per call (UUIDv4 over OsRng); any abstraction string that fails the irreversibility test is rejected before being returned to the caller; the spec's per-content-type abstraction strategies are demonstrably enforced for document, conversation, credential, file, identity, and code types.
  4. User can run `photophore policy preview --channel <id> --task <draft.json>` and see the `result_policy` that would be authored from channel ceiling + envelope draft, without dispatching; any `result_policy` field present in the input draft is ignored.
  5. Given a mixed-tier envelope draft, the in-memory transformation strips tier-0 blocks, replaces tier-1 blocks with shadows, and passes tier-2 blocks unchanged.

**Plans**: 3 plans

Plans:
- [ ] 02-01: `classifier/` crate — explicit tag parser, path-rule engine with mandatory catch-all validation, rule-based default classifier (credential/PII/sensitive types → local; default `local` via explicit `default_tier()`); `photophore classify` CLI subcommand.
- [ ] 02-02: `shadow/` crate — per-content-type abstraction strategies per the v0.3 quality table, three quality tests (irreversibility hard-fail; relevance + distinguishability soft-fail), UUIDv4-over-OsRng shadow IDs.
- [ ] 02-03: `policy/` crate — `result_policy` authoring from channel + envelope draft (`task` envelopes only; manifest authoring deferred to v0.2); `photophore policy preview` CLI subcommand.

---

### Phase 3: Integration — Identity Provider and Dispatch Coordinator

**Goal**: Integrate everything into the dispatch coordinator. Define the `IdentityProvider` trait and ship one reference adapter (Ed25519 via platform keystore). Implement the 9-step dispatch flow including round-trip receipt verification. The receipt-verification gate is type-system enforced: `Receipt` is constructible only by `IdentityProvider::verify` returning `Ok`.

**Depends on**: Phase 1 (audit log, channels) and Phase 2 (classifier, shadow, policy)

**Requirements**:
- IDENT-01, IDENT-02, IDENT-03
- DISP-01, DISP-02, DISP-03, DISP-04, DISP-05, DISP-06
- CLI-03

**Success Criteria** (what must be TRUE):
  1. User can run `photophore dispatch --channel <id> --task <draft.json>` and the system executes the full 9-step flow: resolve channel → classify → shadow → policy → audit-pre → sign → send → verify-receipt → audit-post; on success the user sees a receipt summary including the verified signature hash.
  2. A test forge that returns a forged receipt signature causes the dispatch to fail with `DispatchError::ReceiptVerificationFailed`, and no audit log entry references the forged receipt; an integration test exercises this path.
  3. The reference `IdentityProvider` adapter signs every dispatch by calling the platform keystore (verifiable via macOS Keychain Access or equivalent) and the Photophore process never holds the private key in memory; an inspection of the adapter type confirms `Signature` is the only crypto-material output.
  4. A pre-dispatch audit write failure (induced via a poisoned audit DB) aborts the dispatch before signing; the envelope is never sent and the user receives `DispatchError::AuditFailed`.
  5. Dispatch correctly enforces the network-isolation contract — `cargo deny` confirms that `classifier`, `audit`, `shadow`, `policy`, `channels`, `identity`, and `core` crates have no transitive HTTP dependencies; only the `dispatch` crate links any HTTP client.

**Plans**: 2 plans

Plans:
- [ ] 03-01: `identity/` crate — `IdentityProvider` trait (sign/verify/scheme), reference adapter using `keyring` + `ed25519-dalek` (per-signature keystore RPC, no in-process keys), key-scheme dispatch on verify.
- [ ] 03-02: `dispatch/` crate — the 9-step coordinator with canonical-JSON signing input (`olpc-cjson`), audit-pre/audit-post writes with hard-fail semantics, type-enforced receipt verification gate; `photophore dispatch` CLI subcommand; first round-trip integration test against a stub forge.

---

### Phase 4: Hardening, Conformance, and v0.1 Release

**Goal**: Validate that the system actually meets the spec and the threat model. Property tests for invariants. Negative tests for each AT-* surface in the threat model. ADRs documenting the forever-decisions. Ops/install docs. CI gates. Tagged v0.1 release.

**Depends on**: Phase 3 (and transitively Phases 1 and 2)

**Requirements**:
- CONF-01, CONF-02, CONF-03, CONF-04, CONF-05, CONF-06, CONF-07
- CLI-06, CLI-07

**Success Criteria** (what must be TRUE):
  1. CI is green on a clean clone: `cargo deny`, `cargo audit`, `cargo clippy --deny warnings`, `cargo nextest run --all-features`; the network-isolation contract from Phase 3 is enforced as a CI gate, not a convention.
  2. Property tests cover the four critical invariants and run with at least 100 generated cases each: classifier default fallthrough is `Local`, audit chain integrity (any single-byte tamper invalidates), canonical-JSON round-trip stability, shadow ID uniqueness across dispatches of identical content.
  3. At least one negative test exists per AT-* threat-model surface (AT-A1 through AT-A6), each documenting which surface it exercises and what failure mode it asserts.
  4. ADRs exist (one page or less each, cross-linked from README) for: Rust as primary language, BLAKE3 with `algo_version` chain, trust-store separation from audit log, no shadow caching, no in-process key material in identity adapter; the "looks done but isn't" checklist from PITFALLS.md is verified end-to-end.
  5. Install and ops documentation walks a new user from clone → first dispatch → audit query → audit export on macOS in under 30 minutes; a v0.1 git tag exists with a CHANGELOG describing what is implemented vs. what is deferred (jobs, model classifier, trust score, Ring 2/3, multi-hop, channel negotiation).

**Plans**: 2 plans

Plans:
- [ ] 04-01: Property test suite (proptest) for the four invariants; conformance fixtures vs. Thermocline `task` envelope shape (vendor or stub if canonical Thermocline schemas are unavailable); negative tests per AT-* surface; CI gates for `cargo deny`/`cargo audit`/`cargo clippy --deny warnings`/network-isolation.
- [ ] 04-02: ADR documents (`docs/adr/`); ops/install documentation; CHANGELOG; `secrecy::Secret<T>` audit across content-bearing types; `tracing` filter for `sensitive=true`; `cargo` lint forbidding `derive(Debug)` on raw-content structs; v0.1 git tag.

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundations — Audit Log and Trust Store | 0/3 | Not started | - |
| 2. Privacy Primitives — Classifier, Shadow, Policy | 0/3 | Not started | - |
| 3. Integration — Identity Provider and Dispatch Coordinator | 0/2 | Not started | - |
| 4. Hardening, Conformance, and v0.1 Release | 0/2 | Not started | - |

**Coverage:** 52 of 52 v1 requirements mapped to phases ✓
