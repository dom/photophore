# Photophore

## What This Is

Photophore is a **zero-trust context membrane and shadow protocol** that runs on the originating ("sovereign") node in a distributed AI system. It decides — based on explicit human-authorized trust relationships — what context may cross to a receiving node (a "forge"), generates safe shadow representations of sensitive content at dispatch time, authors result policies on Thermocline task and job envelopes, and writes every boundary crossing to an append-only cryptographically chained audit log. It is for engineers building multi-node AI systems where private context must stay sovereign while still enabling useful cross-node collaboration.

## Core Value

**Reveal only what the receiver needs to know, and nothing else** — every content block is `local` by default, transmission is the exception earned by explicit trust, and every boundary crossing produces a verifiable, append-only privacy receipt.

If everything else fails, this must hold: tier-0 (`local`) content never leaves the originating node.

## Requirements

### Validated

(None yet — ship to validate)

### Active

The first implementation milestone targets the **v0.1 feature set** from the spec roadmap. All items below are hypotheses until shipped:

- [ ] Channel registry with explicit trust ceilings (tier-0/1/2), human-only channel establishment, full lifecycle (PROPOSED → OPEN → SUSPENDED → CLOSED)
- [ ] Three-tier privacy classification (`local`/`shared`/`public`) with strict priority ordering (Explicit Tag → Path Rule → Classifier)
- [ ] Rule-based v0.1 classifier (credentials, PII, sensitive file types → `local`; everything else defaults to `local`)
- [ ] Dispatch-time shadow generation for `task` envelopes (per-envelope, ephemeral, never cached)
- [ ] `result_policy` authorship on outgoing Thermocline `task` envelopes
- [ ] Identity provider delegation for all signing/verification (no direct key management in Photophore)
- [ ] Privacy receipts: dispatch signature + receipt signature round-trip verification
- [ ] Append-only cryptographically chained audit log (Ring 1: local SQLite)
- [ ] Classification explanation surface (every assignment is queryable: tier + reason)
- [ ] Export interface for audit log entries
- [ ] Anchoring hook (interface only — Ring 3 implementation deferred to v0.4)

### Out of Scope

- **Per-step shadow generation for `job` envelopes** — deferred to v0.2 of the spec
- **Result policy authorship for job manifests** — deferred to v0.2
- **Ring 2 (shared channel ledger) reconciliation protocol** — deferred to v0.2
- **Model-based classifier** — deferred to v0.3 (requires v0.2 work first; spec exists in v0.3 but is opt-in by design)
- **Trust score algorithm** — deferred to v0.3
- **Threat model implementation hardening beyond v0.1 surfaces** — deferred to v0.3
- **Multi-hop channels and membrane chaining** — deferred to v0.4
- **Ring 3 blockchain anchor (Arweave reference impl)** — deferred to v0.4 (only the *hook* is in v0.1)
- **Per-content trust overrides beyond explicit tags** — deferred to v0.5
- **Channel negotiation protocol** — deferred to v1.0
- **Automated trust decisions of any kind** — out by design forever; trust is always a human act
- **Cloud inference for classification** — out by design forever; classifier must run on the sovereign node
- **Trust store sync to remote storage** — out by design forever; the trust store never leaves the node
- **Receiver-side enforcement** — out of scope; that is the forge (Seamount), not Photophore

## Context

- **Companion specs:** Thermocline (envelope format with task and job envelope types; defines the Identity Provider Interface used for all signing/verification) and Seamount (the compute forge that lives on the receiving node). Photophore depends on Thermocline 0.3.0+ for full feature set.
- **Spec status:** v0.3.0-draft, RFC, MIT licensed. Implementation is greenfield.
- **Architectural premise:** Three concentric rings of audit storage (Ring 1 local SQLite, Ring 2 shared channel ledger, Ring 3 public blockchain anchor) — same record at different scopes, not competing options. v0.1 implements Ring 1 only and exposes the Ring 3 hook.
- **Key abstraction (channel):** named, configured trust relationship between two nodes; carries trust ceiling, key scheme (declared and immutable at creation), and lifecycle state.
- **Key abstraction (shadow):** safe representation of `shared` content generated *at dispatch time*, calibrated to the specific channel and task, with `shadow_id` (per-dispatch unique), `content_type`, `abstraction`, `relevance` (0.0–1.0), and `tier=1`. Shadows must satisfy three quality tests: irreversibility (hard constraint), relevance preservation, distinguishability.
- **Three pillars:** Channel store (who do I trust, and what may they receive?) ↔ Trust score (how is that trust performing?) ↔ Audit log (what did I actually do?). Audit log is first-class, not supporting infrastructure.
- **Threat model (six attack surfaces named in v0.3 spec):** AT-A1 compromised sovereign node (terminal — accepted), AT-A2 shadow inference, AT-A3 classifier evasion, AT-A4 channel MITM, AT-A5 trust store tampering, AT-A6 audit log manipulation.
- **The "Last Moat" thesis** (non-normative appendix): in a world where anything can be generated, human relationships are the only remaining moat. Photophore exists to make trust expressible, auditable, and worth having.

## Constraints

- **Spec compliance**: Implementation MUST conform to Photophore v0.3.0-draft semantics (the README in this repo is the source of truth; deviations require spec amendment).
- **Tech stack — sovereign-only**: classifier and trust store MUST run entirely on the sovereign node. No cloud inference for classification, ever. No remote sync of the trust store, ever.
- **Tech stack — storage**: audit log MUST be append-only SQLite with cryptographic chaining (each entry hashes the previous). Trust store MUST be backed by the platform secure keystore (Keychain on macOS, libsecret on Linux, Credential Manager on Windows) — never co-located with the audit log.
- **Tech stack — keys**: Photophore MUST NOT manage keys directly. All signing and verification MUST be delegated to the identity provider role defined in Thermocline 0.3.0+.
- **Dependencies**: Thermocline 0.3.0+ for envelope schema (task + job + identity provider interface). Seamount for end-to-end testing of dispatch/receipt round-trips.
- **Security — classifier**: false negatives (private content stays private) are acceptable; false positives (private content classified as safe) are never acceptable. The classifier defaults everything it cannot positively clear to `local`.
- **Security — trust ceiling**: monotonically decreasing on suspicion. May be lowered at any time unilaterally; may only be raised by deliberate human act.
- **Security — result policy**: authored by the issuer (Photophore on sovereign node) before dispatch; the forge cannot modify or escalate it.
- **Security — audit log**: immutable. Append only. No deletion API. To "clear" a log, archive it and start a new chain — the archive remains.
- **Compatibility**: cross-platform sovereign node (macOS first-class via Apple Silicon Secure Enclave; Linux/Windows secondary via libsecret/Credential Manager).
- **License**: MIT. Spec and implementation are open community artifacts.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Implement Photophore v0.1 feature set as the first milestone | Matches the spec's own roadmap; defers v0.2+ surfaces (job-step shadows, Ring 2, model classifier, trust score) to subsequent milestones | — Pending |
| Keep README.md as the canonical spec source of truth | Spec is at v0.3.0-draft and already comprehensive; PROJECT.md captures what we're *building* against the spec | — Pending |
| Delegate all key management to the Thermocline Identity Provider Interface | Spec design constraint; Photophore is a policy engine, not a keystore | — Pending |
| Defer Ring 2 and Ring 3 implementations; v0.1 ships only Ring 1 + anchoring hook | Spec roadmap explicitly stages these; shipping v0.1 first proves the local primitive before federating | — Pending |
| Trust is never automated — Photophore only suggests, the human always decides | Foundational design principle (Design Constraint 2); not negotiable across any version | ✓ Good |
| Zero-trust default — every content block starts as `local`, no permissive default exists | Foundational design principle (Design Constraint 1); the entire privacy guarantee depends on this asymmetry | ✓ Good |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-05 after initialization*
