# Project Research Summary

**Project:** Photophore (zero-trust context membrane / shadow protocol)
**Domain:** Sovereign-node policy engine and privacy primitive for distributed AI systems
**Researched:** 2026-05-05
**Confidence:** HIGH (the spec is the source of truth; research focused on implementation choices and pitfalls)

## Executive Summary

Photophore is the policy engine that runs on the originating ("sovereign") node in a distributed AI system. The spec (README.md, v0.3.0-draft) is comprehensive and prescriptive: classify content into three privacy tiers, generate ephemeral shadows for tier-1 content at dispatch time, author result policies on outgoing Thermocline envelopes, delegate signing to an external identity provider, and write every boundary crossing to an append-only cryptographically chained audit log. The first implementation milestone targets the spec's v0.1 feature set; later spec versions (v0.2 jobs, v0.3 model classifier and trust score, v0.4 multi-hop and Ring 3, v0.5+ per-content overrides, v1.0 channel negotiation) are deferred.

The recommended approach is a Rust workspace with sharply separated crates that mirror the spec's components (`channels`, `classifier`, `shadow`, `policy`, `identity`, `audit`, `dispatch`, `cli`). The `classifier` and `audit` crates are network-free by construction (enforced via `cargo deny`); only the `dispatch` crate performs network I/O. Trust store lives in the platform keystore via the `keyring` crate; audit log is SQLite with a BLAKE3 hash chain. The Identity Provider is a trait, not a concrete struct — the v0.1 reference adapter calls into the platform keystore per-signature and never holds keys in process memory.

The dominant risks are subtle privacy regressions: classifier default drift (a future PR accidentally permits `shared` as a default), shadow abstraction leakage (schema-valid abstractions that contain identifying detail), audit chain algorithm lock-in (forgetting a `chain_algo` version field), and "helpful" log statements that print tier-0 content. Each of these is mitigated by structural decisions baked into v0.1: explicit `default_tier()` function, hard-fail irreversibility test as a dispatch gate, versioned audit-entry schema from day 1, and `secrecy::Secret`-wrapped content types with a custom-only `Debug` policy.

## Key Findings

### Recommended Stack

Rust 1.83+ workspace with mature, single-purpose crates. Cryptography uses Ed25519 (signing, via `ed25519-dalek` v3) and BLAKE3 (chain hashing, via `blake3`). Persistence uses SQLite (via `rusqlite` with bundled feature). Trust store uses the platform keystore (via `keyring` crate). Async via Tokio, CLI via `clap` derive, structured logs via `tracing`. Privacy-critical secrets wrapped in `secrecy::Secret<T>` to redact from `Debug`/`Display` output. CI gates: `cargo deny` (forbids HTTP deps in classifier/audit crates), `cargo audit` (vuln scan), `proptest` (invariant tests for classifier and chain).

**Core technologies:**
- **Rust 1.83+** — sovereign-node binary discipline, memory safety without GC, mature crypto/SQLite ecosystem
- **SQLite (bundled, 3.46+)** — append-only audit log per spec
- **Ed25519** (`ed25519-dalek` v3) — signing scheme for declared `key_scheme=ed25519` channels
- **BLAKE3** — chain hashing (faster than SHA-256, modern; track via versioned `chain_algo` field)
- **`keyring` crate** — cross-platform secure keystore wrapper (Keychain / libsecret / Credential Manager)

### Expected Features

The spec enumerates the v0.1 feature set directly. There are no surprises. Features fall into three categories:

**Must have (table stakes — all required for v0.1):**
- Channel registry with full lifecycle (PROPOSED → OPEN → SUSPENDED → CLOSED), explicit ceilings, immutable per-channel key scheme
- Three-tier classification with strict priority order (Explicit Tag → Path Rule → Classifier)
- Rule-based v0.1 classifier (credentials/PII/sensitive types → local; everything else default local)
- Classification explanation API (every assignment carries `tier` + `reason`)
- Dispatch-time shadow generation for `task` envelopes (per-content-type abstraction strategies, UUIDv4 shadow IDs, three quality tests)
- `result_policy` authoring on outgoing `task` envelopes
- Identity provider trait + reference adapter (Ed25519 via platform keystore)
- Privacy receipts (dispatch + receipt signature round-trip verification)
- Append-only cryptographically chained audit log (Ring 1, SQLite)
- Audit log query CLI + JSON Lines export
- Anchoring hook (interface only — Ring 3 deferred to v0.4)
- CLI: `channel`, `audit`, `dispatch`, `classify`, `policy` subcommands
- Conformance test suite vs. Thermocline `task` envelope schema

**Should have (deferred to next milestones):**
- Per-step shadow generation for `job` envelopes — Photophore spec v0.2
- Ring 2 reconciliation protocol — Photophore spec v0.2
- Trust score algorithm — Photophore spec v0.3
- Model-based classifier — Photophore spec v0.3 (opt-in, local-only, ≤4B params)

**Defer (v0.4+):**
- Multi-hop channels and membrane chaining
- Ring 3 blockchain anchor (Arweave reference impl)
- Per-content trust overrides
- Channel negotiation protocol with cryptographic commitment

### Architecture Approach

A Rust workspace of single-purpose crates mirroring the spec's components, with strict separation of concerns:

**Major components:**
1. **`core/`** — shared types (Channel, Tier, Reason, ShadowId, Envelope alias). Pure, dependency leaf.
2. **`channels/`** — trust registry + lifecycle. Backed by platform keystore (NEVER SQLite).
3. **`classifier/`** — three-tier rule pipeline. Pure, network-free, sync.
4. **`shadow/`** — shadow generator + per-content-type abstraction strategies + three quality tests (irreversibility = hard fail).
5. **`policy/`** — `result_policy` authoring from channel + envelope draft.
6. **`identity/`** — `IdentityProvider` trait + reference adapter (Ed25519 via `keyring`).
7. **`audit/`** — SQLite chained log + export + `AnchorTarget` trait (no-op default).
8. **`dispatch/`** — coordinator (the only crate with network I/O; orchestrates the 9-step dispatch flow).
9. **`cli/`** — `photophore` binary using `clap`.

**Architectural patterns:**
- **Pure-core / imperative-shell**: classifier/shadow/policy are pure functions; dispatch is the imperative shell.
- **Trait-boundaried adapters**: identity provider, transport, anchor target are traits. Reference impls in v0.1; alternatives slot in later.
- **Append-only with hash-chained verification**: each audit entry hashes the canonical bytes of the previous entry.
- **Newtype + secrecy wrappers**: any value that could be tier-0 wrapped in `Secret<T>` so accidental logging redacts.

### Critical Pitfalls

1. **Classifier default drift** — a maintainer adds a new branch and forgets the conservative `local` fallthrough. Mitigation: explicit `default_tier()` function, proptest invariant, CI lint that catches `Tier::Public` outside tag/path-rule branches.
2. **Shadow abstraction leakage** — schema-valid abstractions that contain identifying detail. Mitigation: hard-fail irreversibility test gates dispatch; per-content-type abstraction strategies per the spec's v0.3 quality table.
3. **Audit chain algorithm lock-in** — hardcoding BLAKE3 in entry struct without a `chain_algo` version field. Mitigation: include `algo_version` in every audit entry from day 1.
4. **Implicit trust elevation through "helpful" logging** — `tracing::info!` happily formats tier-0 content. Mitigation: `secrecy::Secret<T>` wrapping + custom `Debug` policy + lint.
5. **Receipt verification skipped or short-circuited** — appending a receipt to the audit log without verifying its signature. Mitigation: `Receipt` constructible only by `IdentityProvider::verify`; type-system enforced.

(See `PITFALLS.md` for the full set — ten critical pitfalls plus technical-debt patterns, integration gotchas, performance traps, security mistakes, UX pitfalls, and a "looks done but isn't" checklist.)

## Implications for Roadmap

Based on research, suggested phase structure for v0.1. **Granularity: coarse** (per the project config; 3–5 phases, broader scope each). All v0.1 requirements should map across these phases.

### Phase 1: Core types, audit log foundations, and trust store

**Rationale:** Two non-negotiable foundations have to land first. The audit log schema (with versioned `chain_algo`) is a forever-decision; the trust store's separation from SQLite is a threat-model invariant. Building these together establishes the privacy boundary before any dispatch logic exists.
**Delivers:** `core/` crate (types: Channel, Tier, Reason, ShadowId, etc.); `audit/` crate (SQLite append-only chained log, BLAKE3 chain hash, `algo_version` field, query + export + `AnchorTarget` trait with no-op default); `channels/` crate (trust store backed by platform keystore via `keyring`, full lifecycle, explicit ceiling, immutable key scheme); `cli` skeleton with `audit` and `channel` subcommands.
**Addresses:** Pitfalls 3, 6, 8 (audit chain lock-in, trust store backup, path-rule catch-all — though catch-all itself lands in Phase 2 with the classifier).
**Avoids:** "Demo first, security later" trap.

### Phase 2: Classification, shadows, policy authoring (the privacy primitives)

**Rationale:** With trust + audit foundations in place, the privacy logic can be built and unit-tested in isolation (these are pure functions). Each component has its own testable surface; they don't need a coordinator yet.
**Delivers:** `classifier/` crate (explicit-tag parser, path-rule engine with mandatory `**` → `local` catch-all validation, rule-based default classifier — credentials/PII/sensitive types → local, everything else → local with explicit `default_tier()` fallthrough); `shadow/` crate (per-content-type abstraction strategies per the v0.3 quality table; irreversibility test as hard fail; relevance and distinguishability tests as warns; UUIDv4 shadow IDs over OsRng); `policy/` crate (`result_policy` authoring from channel + envelope draft); `cli`'s `classify` subcommand for dry-run classification.
**Addresses:** Pitfalls 1, 2, 4, 8 (classifier default drift, shadow leakage, trust-elevation via logging, path-rule catch-all).
**Uses:** `core/` types from Phase 1.
**Implements:** spec's "Three Pillars" — classification + shadow generation; policy authoring.

### Phase 3: Identity provider adapter and dispatch coordinator (the integration phase)

**Rationale:** With privacy primitives in place and audit/trust foundations available, the dispatch coordinator integrates everything. The Identity Provider trait + reference adapter must land before dispatch (signing is required on the wire); ordering is forced.
**Delivers:** `identity/` crate (`IdentityProvider` trait — `sign`/`verify`/`scheme`; reference adapter using `keyring` + `ed25519-dalek`; never holds keys in process memory); `dispatch/` crate (the 9-step coordinator: resolve channel → classify → shadow → policy → audit-pre → sign → transport → verify receipt → audit-post; the only crate with HTTP access; canonical-JSON for signing input); `cli`'s `dispatch` subcommand; conformance test suite vs. Thermocline `task` envelope schema with at least one negative test per AT-* threat-model surface.
**Addresses:** Pitfalls 5, 9, 10 (receipt verification skipped, identity provider holding keys, missing negative tests).
**Implements:** end-to-end dispatch protocol; closes the round-trip privacy receipt.

### Phase 4: Hardening, conformance, and v0.1 release

**Rationale:** A separate phase to harden the surface, write the docs, and validate against external fixtures. Includes the "looks done but isn't" checklist verification (PITFALLS.md), property tests for invariants, and ADRs documenting the forever-decisions made in earlier phases.
**Delivers:** Property test suite (proptest) for classifier invariants and audit chain integrity; "looks done but isn't" checklist verified end-to-end; ADR documents (`001-rust-as-primary-language.md`, `002-blake3-chain-with-algo-version.md`, `003-trust-store-platform-keystore-only.md`, etc.); CI gates (`cargo deny`, `cargo audit`, network-free crate enforcement); ops/install documentation; v0.1 release tagged.
**Addresses:** All pitfalls — verification phase.
**Implements:** the contract that v0.1 actually satisfies the spec.

### Phase Ordering Rationale

- **Phase 1 first** because audit log schema and trust store separation are forever-decisions that everything else builds on. Get them right before adding components that would need to migrate later.
- **Phase 2 second** because the classifier and shadow generator are pure (no I/O), so they can be developed and unit-tested without integration overhead. Building them next isolates the privacy logic from the coordinator complexity.
- **Phase 3 third** because dispatch requires both the privacy primitives (Phase 2) and the audit/trust foundations (Phase 1). It's the natural integration point. The Identity Provider trait fits here because it's only needed when something is signed (which is at dispatch time).
- **Phase 4 last** because hardening and external conformance need a complete system. ADRs benefit from being written *after* the trade-offs were faced, while details are fresh.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 1 (audit log schema):** SQLite WAL tuning, BLAKE3 streaming for large audit log scans, chain-archival format. Needs implementation-time benchmarks.
- **Phase 2 (shadow quality tests):** the irreversibility test heuristics need iteration with real fixtures. Plan time for "leaky abstraction" fixture collection.
- **Phase 3 (canonical JSON for signing):** verify chosen library (`olpc-cjson` vs alternatives) handles the full Thermocline envelope shape; property-test for round-trip stability. Verify Tokio/`rusqlite` interaction patterns under load.

Phases with standard patterns (skip research-phase):
- **Phase 1 (trust store backed by platform keystore):** `keyring` crate is well-documented; standard pattern.
- **Phase 4 (CI gates and ADR writing):** standard practice.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Rust + Ed25519 + BLAKE3 + SQLite + platform keystore is the canonical sovereign-node stack; individual crate versions need to be re-verified at install time (MEDIUM there) |
| Features | HIGH | Spec enumerates v0.1 feature set directly |
| Architecture | HIGH | Crate boundaries map to spec components; pure-core / imperative-shell pattern is well-tested |
| Pitfalls | HIGH | Drawn from the spec's threat model + common privacy-engineering failure modes |

**Overall confidence:** HIGH

### Gaps to Address

- **Thermocline schema artifact**: The Thermocline 0.3.0+ spec is referenced as a dependency but is not in this repo. Phase 3 (and conformance test fixtures) will need access to canonical envelope/manifest schemas. Plan: at the start of Phase 3, locate or vendor the Thermocline JSON Schema files; if unavailable, write a stub that captures the v0.3 envelope shape from this README and flag for revision when Thermocline lands.
- **Identity Provider Interface artifact**: same as above — referenced but not in repo. The trait `IdentityProvider` will be defined in `identity/` crate; expect minor revisions when the canonical Thermocline interface lands.
- **Apple Silicon Secure Enclave testing**: needs a physical Apple Silicon machine with a developer signing identity for full coverage. Plan: target macOS 12+ via standard Keychain in Phase 1; add Secure Enclave entry tests in Phase 4 as a polish item.
- **Performance baseline**: no benchmarks exist yet for "dispatches per second" on a typical sovereign node. Plan: add criterion benchmarks in Phase 4; do not optimize prematurely in earlier phases.

## Sources

### Primary (HIGH confidence)
- `/Users/dom/Projects/dom/photophore/README.md` — Photophore v0.3.0-draft spec; the only normative source for what v0.1 must satisfy
- Spec sections referenced: Three Pillars, Tier System, Classifier Specification (v0.1), Shadow Generation Quality, Trust Score, Audit Log, Threat Model (six AT-* surfaces), Design Constraints (10 normative)

### Secondary (MEDIUM confidence — implementation details)
- Rust ecosystem norms (RustCrypto org, async-rust patterns, `keyring` crate platform coverage)
- BLAKE3 specification (https://github.com/BLAKE3-team/BLAKE3)
- "Pure Core, Imperative Shell" pattern (Gary Bernhardt) — applied to privacy-critical components
- OPA / Cedar / DLP system docs (https://www.openpolicyagent.org/) — for cross-referencing UX patterns and anti-features

### Tertiary (LOW confidence — to validate during implementation)
- Specific crate versions (re-verify at `cargo add` time)
- Apple Silicon Secure Enclave behavior under various keychain entry attributes (test on real hardware)
- WAL checkpoint thresholds for typical dispatch rates (benchmark in Phase 4)

---
*Research completed: 2026-05-05*
*Ready for roadmap: yes*
