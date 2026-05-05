# Requirements: Photophore v0.1

**Defined:** 2026-05-05
**Core Value:** Reveal only what the receiver needs to know, and nothing else — every content block is `local` by default, transmission is the exception earned by explicit trust, and every boundary crossing produces a verifiable, append-only privacy receipt.

## v1 Requirements

Requirements for the v0.1 implementation milestone. Each maps to a roadmap phase.

### Channels (Trust Store and Lifecycle)

- [ ] **CHAN-01**: User can create a channel with a unique ID, local node identity, remote node identity, explicit trust ceiling (`tier-0` / `tier-1` / `tier-2`), key scheme (declared and immutable at creation), creation timestamp, creator identity, and optional description.
- [ ] **CHAN-02**: Channel state advances through the lifecycle PROPOSED → OPEN → SUSPENDED → CLOSED with explicit user-invoked transitions; CLOSED is terminal and channel IDs are never reused.
- [ ] **CHAN-03**: Trust ceilings are monotonically decreasing on suspicion — any user can lower a ceiling unilaterally at any time; raising a ceiling requires a deliberate human action and is recorded as a distinct audit event.
- [ ] **CHAN-04**: Channel registry is backed by the platform secure keystore (Keychain on macOS, libsecret on Linux, Credential Manager on Windows) via the `keyring` crate; the trust store is never co-located with the audit log and is never synced or backed up to remote storage.
- [ ] **CHAN-05**: Channel-creation, suspension, ceiling-change, and closure operations each produce a corresponding append-only audit log entry before the operation is reported successful.
- [ ] **CHAN-06**: Channel state is queryable via `photophore channel list` and `photophore channel show <id>` with both human-readable and JSON output modes.

### Classification (Three-Tier Privacy Model)

- [ ] **CLASS-01**: Classification follows strict priority order — Explicit Tag (Priority 1) overrides Path Rule (Priority 2), which overrides the rule-based Classifier (Priority 3); higher priority always wins.
- [ ] **CLASS-02**: Explicit tags `@photophore:local`, `@photophore:shared`, `@photophore:public` are parsed from content and treated as authoritative tier assignments.
- [ ] **CLASS-03**: Path rules support glob-style patterns; the rules config MUST end with a `**` → `local` catch-all and Photophore refuses to load any config lacking it.
- [ ] **CLASS-04**: Rule-based classifier (v0.1) defaults all unmatched content to `local`; positively detects credential patterns, PII patterns, and known sensitive file types and assigns them `local`; never promotes content to `public` from inference alone.
- [ ] **CLASS-05**: Every classification produces an explanation in the form `(tier, reason)` where reason is one of `explicit_tag`, `path_rule:<pattern>`, `classifier:<rule_name>`, `classifier:default`; the explanation is queryable via `photophore classify <input>` as a dry-run.
- [ ] **CLASS-06**: The default-tier function is implemented as a single explicit named function returning `Tier::Local`; an invariant test asserts that any randomly generated `ContentBlock` with no explicit tag and no path-rule match is classified as `(Local, ClassifierDefault)`.

### Shadow Generation

- [ ] **SHADOW-01**: Shadows are generated only at dispatch time (never at write time); a fresh shadow is produced for every dispatch even of identical source content.
- [ ] **SHADOW-02**: Shadow contains exactly: `shadow_id` (UUIDv4 over OsRng, unique per dispatch), `content_type` (coarse-grained: document, conversation, credential, file, identity, code), `abstraction` (human-readable string per the v0.3 spec quality table), `relevance` (float 0.0–1.0), and `tier` (always 1).
- [ ] **SHADOW-03**: Shadow content_type-specific abstraction strategies are implemented per the spec's v0.3 quality table — each type's abstraction MUST include only the listed signals and MUST NOT include any prohibited signal (filenames, names, dates, organization names, identifiers, etc.).
- [ ] **SHADOW-04**: Every generated shadow runs the irreversibility test (hard fail — dispatch aborts if the test fails) and the relevance preservation and distinguishability tests (soft fail — dispatch continues with a warning recorded to audit).
- [ ] **SHADOW-05**: Tier-0 (`local`) content blocks are stripped from outgoing envelopes; tier-1 (`shared`) blocks are replaced with shadows; tier-2 (`public`) blocks pass through unchanged.
- [ ] **SHADOW-06**: Shadows are never cached, persisted, or referenced after dispatch — each shadow exists only for the lifetime of one dispatch.

### Result Policy Authoring

- [ ] **POLICY-01**: `result_policy` for outgoing `task` envelopes is authored on the issuer node (Photophore) before signing; any `result_policy` field present in the input draft is ignored.
- [ ] **POLICY-02**: Result policy is derived from the channel's trust ceiling, the envelope's declared `output_contract` type and destination, and any explicit policy tags on the task's intent.
- [ ] **POLICY-03**: A negative test confirms that envelopes whose received result violates the authored `result_policy` are rejected at the receipt step.

### Identity Provider Adapter

- [ ] **IDENT-01**: `IdentityProvider` is defined as a Rust trait with methods `scheme()`, `sign(message: &[u8]) -> Signature`, and `verify(message: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<()>`; the trait is the only path through which signing or verification occurs anywhere in the codebase.
- [ ] **IDENT-02**: Reference implementation uses Ed25519 via `ed25519-dalek` v3 with key material backed by the platform secure keystore via the `keyring` crate; the reference implementation never returns or holds a private key in process memory and never copies key material outside the keystore.
- [ ] **IDENT-03**: Verifier dispatches on the channel's declared `key_scheme` field and refuses to verify a signature whose declared scheme does not match the channel's; v0.1 implements only `ed25519` but the dispatch path exists.

### Audit Log

- [ ] **AUDIT-01**: Audit log is append-only — no API exists to delete or modify entries; the SQLite schema enforces append-only behavior via triggers; archival is performed by closing the current chain and starting a new chain (the archive remains on disk).
- [ ] **AUDIT-02**: Each audit entry contains an `algo_version` field (e.g., `"blake3-v1"`); verifier code reads this field and dispatches to the appropriate hash function; v0.1 implements only `blake3-v1` but the field is present from day 1.
- [ ] **AUDIT-03**: Each audit entry includes a `prev_hash` field equal to the BLAKE3 hash of the canonical-JSON serialization of the previous entry, forming a chain that detects tampering.
- [ ] **AUDIT-04**: For each dispatched `task` envelope, the audit log records: timestamp, channel ID, remote node ID, envelope ID, tier of each context block, shadow IDs and abstractions generated, classification reason for each block, dispatch signature hash, and (after receipt) receipt signature hash plus result-persist decisions.
- [ ] **AUDIT-05**: The audit log is queryable by channel, node, tier, date range, shadow ID, envelope ID, and receipt status via `photophore audit query` with both human-readable and JSON Lines output.
- [ ] **AUDIT-06**: Audit log is exportable as JSON Lines plus a chain-head proof via `photophore audit export`; the export format includes the `algo_version` so future verifiers can re-validate.
- [ ] **AUDIT-07**: An `AnchorTarget` trait is defined for Ring 3 (blockchain) anchoring; v0.1 ships only the trait plus a no-op default implementation; a smoke test confirms the dispatch flow works with the no-op anchor selected.
- [ ] **AUDIT-08**: Chain integrity is verifiable on read — querying audit entries verifies the chain over the returned slice and refuses to return entries whose `prev_hash` does not match.

### Dispatch and Privacy Receipts

- [ ] **DISP-01**: The dispatch coordinator orchestrates the full 9-step flow: resolve channel → classify each block → generate shadows / strip tier-0 → author result_policy → write pre-dispatch audit entry → delegate signing to identity provider → send envelope (transport) → verify receipt signature → write receipt audit entry.
- [ ] **DISP-02**: If the pre-dispatch audit write fails, the envelope is not signed and not sent; the dispatch returns `DispatchError::AuditFailed` and no partial state is observable.
- [ ] **DISP-03**: Receipt signature verification occurs before the receipt is appended to the audit log; if verification fails, the dispatch returns an error and no audit entry referencing the (invalid) receipt is appended; an integration test exercises this path with a forged receipt.
- [ ] **DISP-04**: The `Receipt` value type is constructible only by `IdentityProvider::verify` returning `Ok` — no public constructor exists, making "skipped verification" impossible to express in code.
- [ ] **DISP-05**: Signing input is canonical-JSON (via `olpc-cjson` or equivalent) — the same envelope produces the same canonical bytes regardless of map ordering or whitespace; a property test asserts canonical-JSON round-trip stability over arbitrary envelope shapes.
- [ ] **DISP-06**: The dispatch crate is the only crate in the workspace permitted to perform network I/O; this constraint is enforced at CI via `cargo deny` rules forbidding HTTP-related dependencies in `classifier`, `audit`, `shadow`, `policy`, `channels`, `identity`, and `core` crates.

### CLI Surface

- [ ] **CLI-01**: `photophore channel` subcommand supports `new`, `list`, `show`, `suspend`, `close`, and `set-ceiling` operations with both human-readable and JSON output modes.
- [ ] **CLI-02**: `photophore audit` subcommand supports `query` (with all spec-mandated filters), `export`, and `verify` (chain integrity verification of a specified range) operations.
- [ ] **CLI-03**: `photophore dispatch` subcommand accepts a Thermocline `task` envelope draft, channel ID, and dispatches per the full 9-step flow; outputs the receipt summary on success or a structured error on failure.
- [ ] **CLI-04**: `photophore classify` subcommand performs dry-run classification of a path or content blob and prints the `(tier, reason)` for each block without dispatching or generating shadows.
- [ ] **CLI-05**: `photophore policy preview` subcommand shows the `result_policy` that would be authored for a given channel + envelope draft, without dispatching.
- [ ] **CLI-06**: Every CLI subcommand emits an audit log entry recording the operation invoked and its outcome (success/failure) — verified by an integration test that greps the audit DB after each subcommand.
- [ ] **CLI-07**: Every CLI error message that involves classification or policy includes the relevant `(tier, reason)` so the user can diagnose why a dispatch was blocked or a tier was assigned.

### Conformance and Hardening

- [ ] **CONF-01**: A conformance test suite verifies behavior against canonical Thermocline `task` envelope fixtures (vendored or stubbed if Thermocline canonical schemas are unavailable); both happy-path and rejection cases are covered.
- [ ] **CONF-02**: At least one negative test exists per AT-* threat-model surface enumerated in the spec (AT-A1 through AT-A6) — six negative tests minimum, each documenting which surface it exercises.
- [ ] **CONF-03**: Property tests (proptest) cover: classifier default invariant (always `Local` for unmatched), audit chain integrity (any single-byte tamper invalidates the chain), canonical-JSON round-trip stability, and shadow ID uniqueness across dispatches of identical content.
- [ ] **CONF-04**: CI gates: `cargo deny` (forbids HTTP deps in non-dispatch crates), `cargo audit` (vulnerability scan), `cargo clippy --deny warnings`, `cargo nextest` for parallel test runs.
- [ ] **CONF-05**: Architecture Decision Records (ADRs) document the forever-decisions: language choice (Rust), chain hash algorithm with versioning (BLAKE3 with `algo_version`), trust-store separation from audit log (platform keystore mandate), no shadow caching, no key material in Photophore process memory.
- [ ] **CONF-06**: Privacy-critical content types use `secrecy::Secret<T>` wrappers; CI lint forbids `#[derive(Debug)]` on structs containing raw content; tracing filter drops fields tagged `sensitive=true`.
- [ ] **CONF-07**: Install and ops documentation covers: dependency installation, platform keystore prerequisites (macOS Keychain access, Linux libsecret D-Bus session, Windows Credential Manager), recommended config layout including the mandatory path-rule catch-all, and the chain-archival rotation procedure.

## v2 Requirements

Deferred to subsequent milestones (Photophore spec v0.2, v0.3, v0.4, v0.5, v1.0).

### Jobs (v0.2 of spec)

- **JOB-01**: Per-step shadow generation for `job` envelopes during manifest authorship (6-step authorship sequence).
- **JOB-02**: `result_policy` authoring inside the `manifest` block for jobs.
- **JOB-03**: Per-step classification explanations recorded in audit log.

### Federation (v0.2 of spec)

- **RING2-01**: Ring 2 (shared channel ledger) reconciliation protocol — two nodes optionally cross-post audit entries; divergence is itself a signal.

### Trust Score and Model Classifier (v0.3 of spec)

- **SCORE-01**: Trust score algorithm with six input signals (receipt verification rate, result policy compliance, channel age, dispatch volume, error rate, halt rate), composite score formula, decay function, and threshold table.
- **MODEL-01**: Model-based classifier — local-only, opt-in, ≤4B parameters, default-local below confidence threshold (default 0.9), can only promote `local` → `shared`.
- **THREAT-01**: Hardened mitigations for the six AT-* threat-model surfaces beyond v0.1's structural defenses.

### Multi-hop and Anchoring (v0.4 of spec)

- **HOP-01**: Multi-hop channels and membrane chaining.
- **RING3-01**: Ring 3 blockchain adapter (chain-agnostic) with Arweave reference implementation.

### Granular Trust (v0.5 of spec)

- **OVR-01**: File-level and task-level granularity within channels; per-content trust overrides beyond the explicit tag system.

### Channel Negotiation (v1.0 of spec)

- **NEG-01**: Channel negotiation protocol — two Photophore nodes agreeing on a shared trust level before a channel opens, with cryptographic commitment on both sides.

## Out of Scope

Explicitly excluded from Photophore — either by design forever, or as out-of-scope for the project entirely.

| Feature | Reason |
|---------|--------|
| Receiver-side enforcement of policy | That is the forge (Seamount), a separate project. Photophore runs only on the originating ("sovereign") node. |
| Direct key management (key generation, storage, rotation) | Spec mandates delegation to the Thermocline Identity Provider Interface. Photophore is a policy engine, not a keystore. |
| Automatic trust escalation, channel auto-opening, or any non-human trust decision | Foundational design constraint: trust is always a human act. Forever. |
| Cloud or remote inference for content classification | Foundational design constraint: classifier must run entirely on the sovereign node. Forever. |
| Trust store remote sync, cloud backup, or any remote access path to the trust store | Spec mandate: trust store never leaves the node. Forever. |
| Audit log delete/edit APIs | Spec mandate: audit log is immutable. Archival starts a new chain; archives remain. Forever. |
| Caching of generated shadows across dispatches | Defeats per-dispatch shadow ID uniqueness; enables AT-A2 inference attack. |
| Permissive default tier for unmatched content | Foundational: default is always `local`. The privacy guarantee depends on this asymmetry. |
| In-process key material in the identity provider adapter | Defeats the delegation guarantee. Reference adapter calls the platform keystore per signature. |
| Eager classification at content-write time, with results cached for later dispatch | Spec mandate: classification runs at dispatch time, every dispatch. |
| GUI / web frontend | Out of scope for v0.1; CLI-first. May be added in a future milestone but is not on the v0.1 roadmap. |
| Multi-tenant gateway operation | Photophore is a single-node engine. Organizational gateway use is beyond v0.1's design center. |

## Traceability

Which phases cover which requirements. Updated during roadmap creation by the roadmapper agent.

| Requirement | Phase | Status |
|-------------|-------|--------|
| CHAN-01 through CHAN-06 | Phase 1 | Pending |
| AUDIT-01 through AUDIT-08 | Phase 1 | Pending |
| CLASS-01 through CLASS-06 | Phase 2 | Pending |
| SHADOW-01 through SHADOW-06 | Phase 2 | Pending |
| POLICY-01 through POLICY-03 | Phase 2 | Pending |
| IDENT-01 through IDENT-03 | Phase 3 | Pending |
| DISP-01 through DISP-06 | Phase 3 | Pending |
| CLI-01 through CLI-07 | Phase 1 (channel/audit), Phase 2 (classify/policy preview), Phase 3 (dispatch) | Pending |
| CONF-01 through CONF-07 | Phase 4 | Pending |

**Coverage:**
- v1 requirements: 47 total
- Mapped to phases: 47 (preliminary; roadmapper will refine)
- Unmapped: 0

---
*Requirements defined: 2026-05-05*
*Last updated: 2026-05-05 after initialization*
