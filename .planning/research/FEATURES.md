# Feature Research

**Domain:** Sovereign-node zero-trust policy engine and privacy membrane (Photophore v0.1)
**Researched:** 2026-05-05
**Confidence:** HIGH (the spec itself enumerates the feature set; this document categorizes and prioritizes)

## Feature Landscape

### Table Stakes (Users Expect These)

Features that *any* zero-trust policy engine must have. Missing these = the system is not credibly a privacy membrane.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Channel registry CRUD | Spec primary abstraction; without it, nothing flows | MEDIUM | Trust store backed by platform keystore; full lifecycle (PROPOSED → OPEN → SUSPENDED → CLOSED). |
| Three-tier classification with priority order | Spec foundation: Explicit Tag → Path Rule → Classifier | MEDIUM | Priority ordering must be enforced; higher priority always wins. |
| Rule-based classifier (credentials/PII/sensitive types → local; default local) | Spec v0.1 classifier definition | MEDIUM | Conservative by design; false negatives acceptable, false positives never. |
| Classification explanation surface | Spec: "user can always ask why" | LOW | Every assignment carries `tier` + `reason` (`explicit_tag`, `path_rule:<pattern>`, `classifier:<rule>`, `classifier:default`). |
| Dispatch-time shadow generation for `task` envelopes | Spec primary protocol element | HIGH | Per-dispatch, ephemeral, never cached. Must satisfy three quality tests. |
| Shadow quality tests (irreversibility, relevance preservation, distinguishability) | Spec v0.3 quality criteria — irreversibility is HARD constraint | HIGH | Must run on every generated shadow; failures block dispatch (irreversibility) or warn (relevance/distinguishability). |
| Per-content-type abstraction strategies | Spec v0.3 table mandates what abstractions MUST/MUST NOT include per type | MEDIUM | document, conversation, credential, file, identity, code. |
| `result_policy` authoring on outgoing `task` envelopes | Spec: forge cannot modify result policy | MEDIUM | Authored before signing; based on channel ceiling + output_contract + intent tags. |
| Identity provider delegation (no in-process key management) | Spec design constraint | MEDIUM | Trait-based adapter; ed25519 first, others pluggable. |
| Privacy receipts (dispatch-sig + receipt-sig round trip) | Spec: cryptographically verifiable round-trip proof | MEDIUM | Verify receipt signature on every result; store both signature hashes in audit. |
| Append-only cryptographically chained audit log (Ring 1, SQLite) | Spec first-class infrastructure | HIGH | Each entry hashes the previous; no delete API; archive-and-restart pattern only. |
| Audit log queryability (by channel, node, tier, date, shadow ID, envelope ID, receipt status) | Spec mandates query surface | MEDIUM | SQL views/indexes; must not expose write APIs that bypass chaining. |
| CLI surface (`photophore channel list/add/suspend`, `audit query/export`, `dispatch`) | Operability | MEDIUM | First-class for v0.1; GUI deferred. |
| Path rule engine with mandatory `**` catch-all → `local` | Spec mandate | LOW | Reject configs that lack the catch-all. |
| Explicit tag parsing (`@photophore:local|shared|public`) | Spec Priority 1 signal | LOW | Inline tag syntax; tag wins over everything else. |

### Differentiators (Competitive Advantage)

Features unique to Photophore that distinguish it from generic DLP / WAF / OPA-style engines.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Cryptographic chaining of audit log | Tampering becomes mathematically detectable | MEDIUM | BLAKE3 + previous-entry hash; chain-head export. |
| Per-dispatch unique shadow IDs | Prevents cross-dispatch correlation attacks (AT-A2 mitigation) | LOW | Wrap UUIDv4 over OsRng. |
| Trust score derived from history (not configured) | Trust as a living signal, not a static field | HIGH | v0.3 spec — deferred from v0.1 milestone but architecture must accommodate. |
| Three-ring storage model (local → shared → blockchain anchor) | Same record, escalating provenance | HIGH | v0.1 ships Ring 1 + Ring 3 *hook only*. |
| Issuer-authored result policy that forge cannot escalate | Inverts normal client-server trust | MEDIUM | Already in table stakes; calling out as differentiator vs. typical API gateway patterns. |
| Channel-scoped key scheme declaration (immutable at creation) | Prevents downgrade attacks during channel lifetime | LOW | Reject envelopes whose signature scheme doesn't match channel's declared scheme. |
| Identity provider role separation (Photophore never holds keys) | Eliminates key-exfiltration surface from the policy engine | MEDIUM | Trait + reference adapter for platform keystore. |

### Anti-Features (Commonly Requested, Often Problematic)

Features that look reasonable but contradict the spec's foundational premises.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| Auto-trust escalation on "good behavior" | "It's tedious to keep raising ceilings manually" | Violates Design Constraint 2 — trust is always a human act | Surface trust-score *suggestions*; user always decides. Implement nice CLI prompts so the human cost is low. |
| Cloud-hosted classifier ("just call OpenAI to classify") | Higher accuracy, no local model burden | Direct violation of sovereign-node principle (AT-A4 surface, design constraint) | v0.1 rule classifier; v0.3 local model only. |
| Caching shadows for performance | "Don't regenerate the same shadow twice" | Defeats per-dispatch uniqueness; shadow IDs become correlatable; AT-A2 attack becomes viable | Shadows are ephemeral by design. Performance: cache the *upstream classification result*, not the shadow itself. |
| Eager classification at content-write time | "Index everything once so dispatch is fast" | Spec mandates dispatch-time classification; channel-specific context informs the shadow | Run a fast pre-pass for path rules at write time *only* as a hint; final classification still happens at dispatch. |
| Co-locating trust store with audit log | "One database is simpler" | AT-A5 mitigation depends on separate backing stores | Trust store in platform keystore; audit log in SQLite. Always. |
| Trust store cloud sync ("for backup") | Disaster recovery convenience | Spec mandate: trust store never leaves the node | Document an export-and-encrypt-locally backup procedure that the user runs manually. |
| Automatic key rotation without user signal | "Best practice" | The user must be aware of rotation; silent rotation breaks audit-log interpretability | Scheduled prompts; user-confirmed rotation events recorded in audit log. |
| Permissive default tier ("nothing important here") | Easier onboarding | The whole privacy guarantee depends on the default being `local` | Onboarding UX that *explains* the default and walks through tag/rule setup. |
| Allowing audit log entries to be deleted/edited | "GDPR right to be forgotten" | Audit log is the proof that no privacy violation occurred — deleting it destroys that proof | Archive-and-restart-chain pattern; archives remain. Document the GDPR posture (audit log records *that* a dispatch happened, not *what content* was — content lives in the originating store, which is deletable). |
| Filtering at the file/field level inside a content block | "More granular than tier" | Pushes complexity to the wrong abstraction layer; violates "calibrated revelation" framing | v0.5+ feature; not v0.1. The block-level tier is the right abstraction for now. |

## Feature Dependencies

```
Channel Registry ──required by──> Dispatch
        │
        └──required by──> Result Policy Authoring
        │
        └──reads from──> Trust Store (platform keystore)

Classifier ──required by──> Shadow Generator
        │
        └──depends on──> Path Rule Engine
                                │
                                └──depends on──> Explicit Tag Parser

Shadow Generator ──required by──> Dispatch (for tier-1 content)
        │
        └──depends on──> Shadow Quality Tests

Identity Provider Adapter ──required by──> Dispatch (signing)
                                       │
                                       └──required by──> Receipt Verification

Audit Log ──written by──> EVERY operation
        │
        └──read by──> CLI query / export
        │
        └──hooks for──> Ring 2 (deferred), Ring 3 (deferred — hook only in v0.1)

Dispatch (Coordinator) ──orchestrates──> Classifier + Shadow + Policy + IdP + Audit
```

### Dependency Notes

- **Audit Log is a leaf in the write graph and a source for the trust score** — it must be implemented early because *every* other component writes to it. Designing the schema first prevents rework when later components need new entry types.
- **Classifier is on the critical path before Shadow** — shadow generation only operates on `shared` (tier-1) content, which the classifier produces.
- **Path Rule and Explicit Tag are simple but ordering matters** — implement Explicit Tag first (it has highest priority), then Path Rule, then the classifier rules. Each layer can be tested independently with the higher-priority layers stubbed.
- **Identity Provider Adapter is a TRAIT, not an impl** — v0.1 ships one reference adapter (platform keystore via `keyring`); the trait must support future adapters (HSM, hardware tokens) without changing the dispatch crate.
- **Result Policy Authoring conflicts with Forge-side modifications** — design assumes forge cannot edit; conformance test suite must verify a tampered `result_policy` is rejected on receipt.

## MVP Definition

### Launch With (v0.1)

Minimum viable Photophore — proves the spec on a single sovereign node with a single forge.

- [ ] Channel registry: create / open / suspend / close, with explicit ceiling and immutable key scheme
- [ ] Trust store backed by platform keystore (Keychain on macOS first)
- [ ] Three-tier classification with full priority order (Explicit Tag → Path Rule → Classifier)
- [ ] Rule-based classifier (credentials, PII, sensitive file types → local; everything else default local)
- [ ] Classification explanation API (every assignment queryable for tier + reason)
- [ ] Dispatch-time shadow generation for `task` envelopes (per-content-type abstraction strategies; UUIDv4 shadow IDs over OsRng)
- [ ] Shadow quality tests: irreversibility (hard fail), relevance preservation (warn), distinguishability (warn)
- [ ] `result_policy` authoring on outgoing `task` envelopes
- [ ] Identity provider adapter trait + reference adapter using platform keystore signing (Ed25519)
- [ ] Privacy receipts: dispatch-signature emission + receipt-signature verification
- [ ] Append-only cryptographically chained audit log (SQLite, BLAKE3 chain)
- [ ] Audit log query CLI (by channel / node / tier / date / shadow ID / envelope ID / receipt status)
- [ ] Audit log export (JSON Lines + chain-head proof)
- [ ] Anchoring hook (interface only — `AnchorTarget` trait; no Ring 3 implementation in v0.1)
- [ ] CLI: `photophore channel`, `photophore audit`, `photophore dispatch`, `photophore classify`
- [ ] Conformance test suite vs. Thermocline `task` envelope schema

### Add After Validation (v0.2 of Photophore spec)

- [ ] Per-step shadow generation for `job` envelopes (manifest authorship sequence, 6 steps)
- [ ] `result_policy` authoring inside `manifest` for jobs
- [ ] Per-step classification explanations
- [ ] Ring 2 (shared channel ledger) reconciliation protocol

### Future Consideration (v0.3+ of Photophore spec)

- [ ] Model-based classifier (local-only, opt-in, ≤4B params, default-local below confidence threshold)
- [ ] Trust score algorithm (six signals, decay function, threshold table)
- [ ] Multi-hop channels and membrane chaining (v0.4)
- [ ] Ring 3 blockchain adapter — Arweave reference impl (v0.4)
- [ ] Per-content trust overrides beyond explicit tag (v0.5)
- [ ] Channel negotiation protocol with cryptographic commitment on both sides (v1.0)

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Channel registry + trust store | HIGH | MEDIUM | P1 |
| Audit log (chained, SQLite) | HIGH | HIGH | P1 |
| Three-tier classifier with priority order | HIGH | MEDIUM | P1 |
| Rule-based classifier | HIGH | MEDIUM | P1 |
| Shadow generation + quality tests | HIGH | HIGH | P1 |
| Identity provider adapter (trait + reference) | HIGH | MEDIUM | P1 |
| Privacy receipts (sign + verify) | HIGH | MEDIUM | P1 |
| `result_policy` authoring | HIGH | MEDIUM | P1 |
| CLI surface (channel / audit / dispatch / classify) | HIGH | MEDIUM | P1 |
| Audit log export + anchoring hook (interface only) | MEDIUM | LOW | P1 |
| Conformance test suite | HIGH | MEDIUM | P1 |
| Per-step job shadow generation | HIGH | HIGH | P2 (v0.2) |
| Trust score algorithm | MEDIUM | HIGH | P2 (v0.3) |
| Model-based classifier | MEDIUM | HIGH | P3 (v0.3) |
| Ring 2 / Ring 3 implementations | MEDIUM | HIGH | P3 (v0.4) |

**Priority key:**
- P1: Must have for v0.1 (this milestone)
- P2: Should have, next milestones (v0.2 / v0.3)
- P3: Future roadmap (v0.3+)

## Competitor Feature Analysis

Photophore occupies a niche — none of these are direct competitors, but each has overlapping concerns worth borrowing from.

| Feature | Open Policy Agent (OPA) | AWS Cedar | DLP systems (e.g., Symantec DLP) | Our Approach |
|---------|--------------------------|-----------|----------------------------------|--------------|
| Policy authoring | Rego DSL | Cedar DSL | Pattern + rule UI | Per-channel ceiling + global path rules + explicit tags. No DSL needed for v0.1; consider one in v0.5 for per-content overrides. |
| Classification | N/A (policy on inputs) | N/A | Pattern matching on content | Three-tier with priority order; conservative default. |
| Audit | Decision logs (configurable destinations) | CloudTrail | SIEM integration | Append-only cryptographically chained log; export hook; Ring 2/3 deferred. |
| Trust model | Caller authorization | Principal/resource | DLP zones | Channel-scoped trust with explicit ceilings; immutable key scheme per channel. |
| Tampering resistance | None native | None native | Limited | Hash chaining + (deferred) blockchain anchor; immutable archives. |
| Key management | External (caller) | External (caller) | Internal | External (delegated to identity provider) — matches OPA/Cedar philosophy and avoids the DLP-style internal-keystore antipattern. |

## Sources

- Spec: `/Users/dom/Projects/dom/photophore/README.md` (Photophore v0.3.0-draft)
- Companion specs (referenced but not yet in repo): Thermocline (envelope format), Seamount (forge)
- Mental models from Open Policy Agent docs (https://www.openpolicyagent.org/) — for *what* policy engines surface to operators
- Mental models from AWS Cedar docs — for *how* per-resource trust attestation works
- Confidence: HIGH on the v0.1 feature list (it comes directly from the spec's roadmap section); MEDIUM on the prioritization (which is our judgment)

---
*Feature research for: Photophore v0.1*
*Researched: 2026-05-05*
