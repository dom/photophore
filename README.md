# Photophore

### A Zero-Trust Context Membrane and Shadow Protocol for Distributed AI Nodes

**Version:** 0.3.0-draft
**Status:** RFC — Pre-release, seeking feedback
**License:** MIT
**Depends on:** Thermocline 0.3.0+

---

## The Problem

Every AI system that moves context between nodes faces the same question: what
should cross the boundary, and what should not?

Current systems answer this badly. They either move everything (no boundary) or
nothing (no utility). The few that attempt selective sharing do so at the wrong
level — filtering individual files or fields rather than reasoning about the
relationship between the nodes involved.

The result is a false choice: full exposure or full isolation. Neither is how trust
actually works between humans.

Photophore offers a third model: **calibrated revelation.** The originating node
decides, based on its relationship with the receiving node, what the receiver needs
to know — and reveals exactly that, and nothing else.

---

## What Photophore Is

Photophore is a **zero-trust context membrane** that runs on the originating node. It:

- Maintains a registry of trusted channels and their trust ceilings
- Classifies all local content against a three-tier privacy model
- Generates shadows for content that may not cross a boundary raw
- Authors `result_policy` blocks for outgoing Thermocline task and job envelopes
- For `job` envelopes: classifies and shadows context at the per-step level during
  manifest authorship, before dispatch
- Delegates signing to the identity provider (see Thermocline Identity Provider Interface)
- Verifies incoming result signatures from receiving nodes
- Maintains an append-only, cryptographically chained audit log of all boundary
  crossings — first-class infrastructure, co-equal with the channel store
- Enforces a zero-trust default: everything is opaque until trust is explicitly granted

Photophore does **not**:

- Run on the receiving node (that is the forge)
- Make trust decisions automatically (trust is always a human act)
- Store or cache private content outside the originating node
- Negotiate trust levels on behalf of the user
- Implement its own key management (delegates to the identity provider)

---

## Zero Trust as Foundation

The default state of every piece of content in Photophore is `local` — opaque,
locked, not eligible for transmission. This is not a configuration option. It is
the foundational assumption of the system.

Transmission is not the default. It is the exception, earned by explicit trust
establishment.

> *Reveal only what the receiver needs to know, and nothing else.*

This is the north star of every design decision in this spec. When in doubt,
the answer is always to reveal less.

---

## Core Concepts

### The Three Pillars

Photophore rests on three co-equal pillars:

```
Channel Store  →  governs what may cross
      ↑                    ↓
Trust Score    ←  Audit Log
(informed by)     (records what did cross)
```

**The Channel Store** answers: *who do I trust, and what may they receive?*
**The Trust Score** answers: *how is that trust performing over time?*
**The Audit Log** answers: *what did I actually do?*

Without the audit log, the first two are claims. With it, they are provable.

### Channels

A channel is a named, configured trust relationship between two nodes. It is the
central abstraction in Photophore.

A channel has:

- A unique ID
- A local node identity (the Photophore node)
- A remote node identity (the receiver)
- A trust ceiling (the highest tier permitted to cross this channel)
- A key scheme (how envelopes on this channel are signed — declared at creation, immutable)
- A creation timestamp and creator identity
- An optional description

A channel does not have:

- An automatic trust level (always set explicitly by a human)
- Inherited trust from other channels
- A default that permits any transmission

**Channel establishment is always a human act.** Photophore will never open a
channel, raise a trust ceiling, or negotiate trust parameters automatically.
The system may suggest; only the user may decide.

**Trust ceilings map directly to Thermocline tiers:**

| Ceiling | Meaning |
|---------|---------|
| `tier-0` | No content crosses. Channel exists for metadata only. |
| `tier-1` | Shadows only. Raw content never leaves the node. |
| `tier-2` | Public content crosses in full. Shadows for tier-1. Tier-0 stays home. |

### The Tier System

Every content block has a privacy tier, assigned by the classification engine in
strict priority order. A higher-priority signal always wins.

**Priority 1 — Explicit Tag**
A tag set directly on the content by the user or a trusted agent at creation time.
The highest-trust signal: a deliberate human decision.

```
@photophore:local    — never leaves this node
@photophore:shared   — may cross as a shadow
@photophore:public   — crosses in full
```

**Priority 2 — Path Rule**
A standing rule assigning a default tier to all content matching a path pattern.

```yaml
path_rules:
  - pattern: "~/Private/**"
    tier: local
  - pattern: "~/Work/Projects/**"
    tier: shared
  - pattern: "~/Public/**"
    tier: public
  - pattern: "**"
    tier: local    # mandatory catch-all: when in doubt, lock it down
```

The catch-all rule is mandatory and must assign `local`. There is no implicit
permissive fallback.

**Priority 3 — Classifier**
Last-resort inference about what is demonstrably safe to reveal. The classifier's
job is not to find what is private — everything is private by default. Its job is
to find what is *demonstrably safe to reveal*, which is a harder and more
conservative test.

**Classification is always explained:**

```
assigned: local    reason: explicit_tag
assigned: shared   reason: path_rule:~/Work/GrayWhale/**
assigned: local    reason: classifier:credential_pattern
assigned: local    reason: classifier:default
```

A user can always ask why a content block received its tier and receive a precise,
auditable answer.

### Classifier Specification

**v0.1 — Rule-Based (current)**

The v0.1 classifier is deterministic and conservative:

- Credential patterns (tokens, keys, passwords, API keys) → `local`
- PII patterns (names, addresses, phone numbers, SSNs, emails) → `local`
- Known sensitive file types (keychains, certificates, private keys, .env files) → `local`
- Everything else → `local`

The classifier defaults everything it cannot positively clear to `local`. It will
produce false negatives (treating safe content as private). It will not produce
false positives (treating private content as safe). This asymmetry is intentional.

**v0.2 — Model-Based (planned)**

The model-based classifier runs locally on-device. It never makes network calls.

Requirements:
- MUST run entirely on the sovereign node (no cloud inference for classification)
- MUST be opt-in (rule-based classifier remains the default)
- MUST produce the same explanation format as the rule-based classifier
- MUST default to `local` when confidence is below a configurable threshold (default: 0.9)
- MUST NOT override explicit tags or path rules (Priority 1 and 2 always win)
- SHOULD be a small model optimized for classification, not generation (target: <4B parameters)

The model-based classifier supplements the rule-based classifier — it does not
replace it. Both run in sequence: rule-based first (fast, deterministic), then
model-based for content that rule-based classified as `local` by default (the
"everything else" catch-all). The model-based classifier can only promote content
from `local` to `shared` — it cannot promote to `public` (that requires an
explicit tag or path rule).

### Shadows

A shadow is the safe representation of a `shared` (tier-1) content block, generated
at dispatch time and calibrated to the specific channel and task.

**Shadows are generated at dispatch time, not at write time.** The same content may
produce different shadows for different channels. Shadows are ephemeral — they exist
to cross a boundary, not to be stored. No shadow corpus accumulates that could
itself become a privacy liability.

A shadow contains:

- `shadow_id` — opaque, locally meaningful, not reversible by the receiver
- `content_type` — type hint (`document`, `conversation`, `credential`, `file`, etc.)
- `abstraction` — human-readable description with no identifying detail
- `relevance` — float (0.0–1.0) indicating pertinence to the current task
- `tier` — always `1`

A shadow never contains file contents, names, identifiers, locations, or anything
that could reconstruct the original.

### Shadow Generation Quality

Shadow quality determines whether the privacy guarantee holds in practice. A
technically valid shadow that leaks identifying detail through its abstraction
string is a privacy failure regardless of schema compliance.

**Abstraction Strategies by Content Type**

| Content Type | Abstraction MUST Include | Abstraction MUST NOT Include |
|-------------|------------------------|----------------------------|
| `document` | Topic category, approximate length class (short/medium/long), temporal indicator (recent/historical) | Filename, author, specific dates, organization names, unique identifiers |
| `conversation` | Participant count, topic domain, tone indicator (formal/informal) | Participant names, quotes, specific claims, timestamps |
| `credential` | Credential type only (API key, password, certificate) | The credential value, the service name, the account identifier |
| `file` | File type category (image/document/code/data), approximate size class | Filename, path components, EXIF data, embedded metadata |
| `identity` | Identity type only (person, organization, device) | The identity value, associated accounts, contact information |
| `code` | Language, approximate complexity (script/module/application), domain (web/data/infrastructure) | Repository name, function names, variable names, comments |

**Quality Criteria**

Every shadow MUST satisfy three tests:

**1. Irreversibility Test**
Given only the shadow (abstraction + content_type + relevance), can the original
content be reconstructed or uniquely identified? If yes, the shadow fails.

**2. Relevance Preservation Test**
Given the shadow, can the receiving node make a meaningful decision about whether
this context matters for the task? If no, the shadow is too abstract and fails.

**3. Distinguishability Test**
Given two shadows from different source content of the same type, are they
distinguishable enough that the receiver can reason about them independently? If
they are identical for meaningfully different content, the shadow is too generic
and fails.

The irreversibility test is the hard constraint. The relevance and
distinguishability tests are quality criteria — shadows that fail them are valid
but low-quality. A shadow that fails the irreversibility test is a privacy
violation.

**Shadow ID Uniqueness**

Shadow IDs MUST be unique per dispatch. The same source content shadowed in two
different dispatches MUST produce two different shadow IDs. This prevents a
receiver from correlating shadows across dispatches to track which content
recurs.

### Shadow Generation for Job Envelopes

For `task` envelopes, shadow generation is a single operation over the top-level
`context[]` block at dispatch time.

For `job` envelopes, shadow generation occurs **per step**, during manifest
authorship on the issuer node — before the job is dispatched. Photophore processes
each step's `context[]` block independently.

**The authorship sequence for a job manifest:**

```
1. Human or agent drafts step definitions with raw context references
2. Photophore classifies each context block in each step
3. Photophore replaces tier-1 blocks with shadows, strips tier-0 blocks
4. Photophore populates manifest.result_policy
5. Photophore delegates signing to the identity provider
6. Sealed manifest is dispatched to the forge
```

Photophore's classification explanation applies at the step level:

```
step:s1 context[0]  assigned: public   reason: explicit_tag
step:s1 context[1]  assigned: local    reason: classifier:credential_pattern — STRIPPED
step:s2 context[0]  assigned: shared   reason: path_rule:~/Work/GrayWhale/** — SHADOWED
```

### Result Policy Authorship

For both `task` and `job` envelopes, `result_policy` is authored by Photophore on
the issuer node before dispatch. The forge cannot modify or escalate it.

For `job` envelopes, `result_policy` appears inside `manifest`. Photophore populates
it during the manifest authorship sequence (step 4 above), based on:

- The channel's trust ceiling
- The declared `output_contract` type and destination
- Any explicit policy tags on the job's intent

---

## Trust Score

The trust score is a living signal derived from the audit log — not a static
configuration. It answers: *how well is this channel performing against its
declared trust relationship?*

### Input Signals

| Signal | Weight | Source |
|--------|--------|--------|
| Receipt verification rate | 0.30 | Percentage of dispatches that received a valid, verifiable receipt signature |
| Result policy compliance | 0.25 | Percentage of results that respected the declared result_policy (no unexpected fields persisted) |
| Channel age | 0.15 | Older channels with clean histories score higher (log scale, caps at 90 days) |
| Dispatch volume | 0.10 | Channels with more successful round-trips score higher (log scale, caps at 1000) |
| Error rate | 0.10 | Percentage of dispatches that returned errors (inversely weighted) |
| Halt rate (jobs only) | 0.10 | Percentage of jobs that halted (inversely weighted; `TIMEOUT` weighted less than `PRIVACY_VIOLATION`) |

### Composite Score

```
trust_score = Σ(signal_i × weight_i) → [0.0, 1.0]
```

The score is recalculated on every audit log entry. It is not smoothed or averaged
over a window — it reflects the full history of the channel.

### Decay Function

A channel with no activity decays toward 0.5 (neutral) at a rate of 0.01 per day
of inactivity. This prevents stale channels from maintaining artificially high
trust scores.

### Thresholds

| Score Range | Status | Action |
|------------|--------|--------|
| 0.8–1.0 | Healthy | No action |
| 0.6–0.79 | Degraded | Surface warning to user on next dispatch |
| 0.4–0.59 | Suspicious | RECOMMEND suspension (human must confirm) |
| 0.0–0.39 | Critical | RECOMMEND immediate suspension + audit review |

Photophore RECOMMENDS but never suspends automatically. The human always decides.

---

## The Audit Log

The audit log is not a supporting feature. It is first-class infrastructure,
co-equal with the channel store and the trust score.

### Properties

- **Append-only** — entries are never modified or deleted, not even by the node owner
- **Cryptographically chained** — each entry hashes the previous, forming an
  unbroken chain. Tampering with any entry invalidates all subsequent entries.
- **Immutable by design** — there is no deletion API. To "clear" a log, archive it
  and start a new chain. The archive remains.
- **Queryable** — searchable by channel, node, tier, date range, shadow ID, envelope
  ID, or receipt status.
- **Feeds the trust score** — every verified receipt is a data point.

### What Each Entry Records

For `task` envelopes:

- Timestamp
- Channel ID and remote node ID
- Envelope ID
- Tier of each context block dispatched
- Shadow IDs generated and their abstractions
- Classification reason for each content block
- Dispatch signature hash
- Receipt signature hash (added when receipt arrives)
- Result persist decisions (what, if anything, was committed to shared memory)

For `job` envelopes, additionally:

- Job ID
- Per-step shadow IDs generated and their abstractions
- Per-step classification reasons
- Halt code, if applicable (no content — only the code)
- Steps declared vs. steps executed (from job result provenance)

### The Three-Ring Storage Model

Local storage and blockchain are not competing options. They are the same audit log
at different scopes — three concentric rings of the same record.

**Ring 1 — Local (node-sovereign)**
SQLite, append-only, cryptographically chained. The default. Always sufficient for
personal use. Fast, private, zero dependencies.

**Ring 2 — Shared (channel-scoped)**
Two nodes on the same channel optionally cross-post audit entries to a shared
ledger. Neither can modify the other's entries. If they diverge, the divergence is
itself a signal.

**Ring 3 — Public (blockchain-anchored)**
The hash of a local audit chain anchored to a public blockchain. Never the content —
only the hash. Content stays local. The proof becomes public and permanent.

Arweave is the recommended anchoring target: permanent content-addressed proof
storage, one-time cost, no ongoing fees.

### The Privacy Receipt

The dispatch signature and receipt signature together form a **privacy receipt** — a
cryptographically verifiable round-trip proof that:

1. The originating node applied its declared policy before dispatch
2. The receiving node operated only on what the envelope contained
3. No tier-0 content crossed the boundary
4. The channel's trust ceiling was honored

For `job` envelopes, the privacy receipt additionally proves that:

5. The manifest was sealed and signed before dispatch
6. The forge returned a signed result without intermediate state

---

## Threat Model

Photophore's threat model addresses attacks against the policy engine, the
classification system, and the trust infrastructure. Attacks against the envelope
format are covered in the Thermocline spec. Attacks against the forge are covered in
the Seamount spec.

### Trust Assumptions

| Assumption | Implication |
|------------|------------|
| The sovereign node is not compromised | The node owner controls their own machine. If this fails, all guarantees fail — by design. |
| The identity provider's keystore is intact | Private keys have not been exfiltrated. Platform keystore compromise is outside Photophore's threat boundary. |
| The user's tier assignments reflect their intent | Explicit tags and path rules are authoritative. The user is the final authority on what is private. |
| The classifier is conservative | False negatives (private content stays private) are acceptable. False positives (private content classified as safe) are not. |

### Attack Surfaces and Mitigations

**AT-A1: Compromised Sovereign Node**
*Attack:* Malware, unauthorized physical access, or coerced operator gains control
of the node running Photophore. The attacker can read all local content, modify
classification rules, lower trust ceilings, forge dispatches.
*Mitigation:* This is the terminal threat. By design, Photophore places the trust
root at the sovereign node. There is no higher authority to appeal to.
*Structural defenses:*
- Audit log immutability: even a compromised node cannot silently delete past
  entries. A forensic review can detect when the chain was broken.
- Key rotation with published schedule: if the node is recovered, old keys can
  be revoked and new keys established. The window of exposure is bounded.
- Channel suspension: receiving nodes that detect anomalies (unusual dispatch
  patterns, signature timestamp gaps, trust score degradation) can unilaterally
  suspend their end of the channel.
*Residual:* Full compromise of the sovereign node breaks all privacy guarantees
for the duration of compromise. This is accepted. A system that attempted to
protect against its own operator would require trusting a third party, which
contradicts the design premise.

**AT-A2: Shadow Inference Attack**
*Attack:* A receiver (or observer with access to multiple dispatches) correlates
shadow patterns across sessions to infer private content. Examples:
- Same content_type + similar relevance scores recurring across dispatches →
  infer which private documents the user works with regularly
- Shadow abstraction phrasing contains implicit identifiers ("a financial document
  from a Bay Area technology company" narrows the universe significantly)
- Temporal correlation: shadows appearing around public events (earnings reports,
  product launches) allow inference about what private content relates to
*Mitigation:*
- Shadow IDs MUST be unique per dispatch (prevents ID-based correlation)
- Abstraction strings SHOULD be varied across dispatches for the same content
  (the policy engine SHOULD maintain an abstraction variation strategy)
- Abstraction strings MUST satisfy the shadow quality criteria (irreversibility
  test, specifically)
- Content_type hints are deliberately coarse (document, not "financial report")
*Residual:* Statistical inference from metadata patterns is theoretically possible
with sufficient dispatch volume. This is the fundamental tradeoff of the shadow
primitive — conveying any relevance signal necessarily leaks some information
about the existence of private context. The mitigation is volume-based: vary
abstractions, rotate shadow IDs, use coarse content types.

**AT-A3: Classifier Evasion**
*Attack:* Content is crafted to bypass the classifier — structured to avoid
credential patterns, PII patterns, and sensitive file type detection, causing
the classifier to assign `shared` or `public` to content that should be `local`.
*Mitigation:*
- The v0.1 classifier defaults everything to `local`. Evasion is not meaningful
  when the default is the most restrictive tier.
- The v0.2 model-based classifier MUST default to `local` below confidence
  threshold (0.9). It can only promote from `local` to `shared`, never to `public`.
- Explicit tags (Priority 1) always override the classifier. Users can always
  lock content regardless of what the classifier infers.
- Path rules (Priority 2) override the classifier. Sensitive directories stay
  locked regardless of content analysis.
*Residual:* A sufficiently sophisticated adversary who controls the content
being classified (e.g., a malicious document designed to look benign) could
theoretically evade the model-based classifier. The defense-in-depth is
Priority 1 + Priority 2 overrides, plus the classifier's conservative default.

**AT-A4: Channel MITM**
*Attack:* An attacker intercepts the communication channel between the sovereign
node and the forge, reading dispatched envelopes and returned results.
*Mitigation:* Thermocline is transport-agnostic but RECOMMENDS TLS or equivalent.
Dispatch signatures and receipt signatures provide envelope-level integrity
independent of transport. An attacker who intercepts an envelope sees only
public content and shadows (never tier-0 content). Shadows are designed to
resist reconstruction.
*Residual:* A MITM who breaks transport encryption sees the shadow abstractions
and public content. This is bounded by the trust ceiling — on a tier-1 channel,
the attacker sees only shadows and metadata. On a tier-2 channel, public content
is visible by design.

**AT-A5: Trust Store Tampering**
*Attack:* An attacker modifies the trust store to raise channel trust ceilings,
add unauthorized channels, or remove suspension records.
*Mitigation:*
- The trust store is backed by the platform secure keystore (Keychain, libsecret,
  Credential Manager)
- On macOS with Apple Silicon, modification requires biometric or password
  authentication via Secure Enclave
- The trust store maintains an append-only modification log — changes are recorded
  and cannot be silently overwritten
- The audit log independently records all dispatches; a discrepancy between trust
  store configuration and audit log dispatch patterns is detectable
*Residual:* Platform keystore compromise (OS-level exploit) enables trust store
tampering. This is outside Photophore's threat boundary.

**AT-A6: Audit Log Manipulation**
*Attack:* An attacker attempts to modify or delete audit log entries to conceal
unauthorized dispatches or trust store changes.
*Mitigation:*
- The audit log is cryptographically chained: each entry hashes the previous.
  Modifying any entry invalidates all subsequent entries.
- Ring 2 (shared channel ledger) provides an independent copy that neither party
  can unilaterally modify.
- Ring 3 (blockchain-anchored hash) provides an irrefutable external timestamp.
*Residual:* An attacker who compromises the sovereign node can append new entries
to the chain (legitimate operation) but cannot remove or modify existing ones
without breaking the chain. Starting a new chain is detectable (the chain head
changes). Ring 2 and Ring 3 provide independent verification.

### Residual Risks — Accepted by Design

**Sovereign node compromise is terminal.** This is the cost of not trusting a
third party. The audit log, key rotation, and channel suspension mechanisms bound
the damage window but cannot prevent it.

**Shadow metadata leaks existence.** Every shadow reveals that relevant private
context exists. This is inherent to the design — a system that reveals nothing
cannot help a forge reason about private context.

**Human trust decisions may be wrong.** A user who sets a trust ceiling too high
or classifies content incorrectly enables exposure. Photophore does not second-guess
the user. It provides classification explanations and trust score warnings, but the
human is the final authority.

---

## The Trust Store and Audit Storage

The trust store and the audit log are distinct structures with distinct storage
requirements. They must not be conflated.

### Trust Store

The trust store contains the channel registry and all associated trust grants. It
is small, sensitive, and access-controlled.

- Stored locally, never synced to any remote node
- Backed by the platform secure keystore (see Thermocline Identity Provider Interface
  for platform-specific recommendations)
- Append-only modification log — changes are recorded, never silently overwritten
- No remote access path exists by design

### Audit Log Storage

The audit log is append-only, potentially large, and queryable — the right profile
for SQLite, not a keychain.

- SQLite, local, append-only
- Cryptographically chained — each entry hashes the previous
- Queryable by channel, node, tier, date range, shadow ID, envelope ID, receipt status
- Separate from the trust store — never co-located in the same backing store

---

## Channel Lifecycle

```
PROPOSED → OPEN → SUSPENDED → CLOSED
              ↑         |
              └─────────┘  (re-openable)
```

**PROPOSED** — parameters defined locally, remote node not yet notified. No content flows.
**OPEN** — both nodes have acknowledged the channel. Content flows up to trust ceiling.
**SUSPENDED** — temporarily closed, pending trust review. No new content flows.
**CLOSED** — permanently closed. Receipts archived. Channel ID never reused.

Suspension and closure are always available to either party unilaterally. Trust can
always be withdrawn.

---

## Design Constraints

**1. Zero trust is the default.** Every content block starts as `local`. No
configuration produces a permissive default.

**2. Trust is always a human act.** Photophore will never open a channel, raise a
trust ceiling, or negotiate trust parameters without explicit human authorization.

**3. Shadows are generated at dispatch time.** For task envelopes, this is a single
operation at the envelope level. For job envelopes, this occurs per step during
manifest authorship. Never proactively, never cached remotely, never stored outside
the originating node.

**4. The classifier is conservative.** When uncertain, assign `local`. Never
escalate on inference alone.

**5. The trust store never leaves the node.** No sync, no backup to remote storage,
no remote access path.

**6. Audit log entries are immutable.** Append only. No deletion. No modification.
The log is the proof.

**7. Key scheme is declared, not inferred.** Every signature block carries its
scheme explicitly. Verifiers must reject missing or unrecognized schemes.

**8. Channel trust ceilings are monotonically decreasing on suspicion.** A ceiling
may be lowered at any time unilaterally. It may only be raised by a deliberate
human act.

**9. The audit log feeds the trust score.** Trust is not a static configuration.
It is a living signal derived from the history of what actually happened on a channel.

**10. Result policy is authored by the issuer, never the forge.** For both task and
job envelopes, Photophore populates `result_policy` on the issuer node before dispatch.
The forge operates within it. It cannot escalate permissions.

---

## Roadmap

**v0.1** — Channel registry, three-tier classification, rule-based classifier,
dispatch-time shadow generation, identity provider delegation, privacy receipts,
append-only cryptographically chained audit log (Ring 1), export interface,
anchoring hook.

**v0.2** — Per-step shadow generation for job envelopes. Result policy authorship
for job manifests. Ring 2 reconciliation protocol.

**v0.3** — Model-based classifier spec (opt-in, local-only). Shadow quality
criteria and abstraction strategies. Trust score algorithm. Threat model.

**v0.4** — Multi-hop channels. Membrane chaining. Ring 3 blockchain adapter
(chain-agnostic). Arweave reference implementation.

**v0.5** — File-level and task-level granularity within channels. Per-content trust
overrides beyond the explicit tag system.

**v1.0** — Channel negotiation protocol. Two Photophore nodes agreeing on a shared
trust level before a channel opens, with cryptographic commitment on both sides.

---

## Relationship to the Suite

| Component | Relationship |
|-----------|-------------|
| Thermocline | Photophore generates Thermocline task and job envelopes and delegates signing to the identity provider. The `channel_id` field in Thermocline is Photophore's primary key into the channel registry. Photophore authors `result_policy` for both envelope types. |
| Seamount | Photophore dispatches to forges. Forges return receipt signatures that Photophore verifies and logs. |
| Identity Provider | Photophore delegates all signing and verification to the identity provider defined in Thermocline 0.3.0+. It does not manage keys directly. |

---

## Architecture Decision Records

### Photophore-specific
- [ADR-0001: Trust-store separation from audit log](docs/adr/ADR-0001-trust-store-separation-from-audit-log.md)
- [ADR-0002: No shadow caching](docs/adr/ADR-0002-no-shadow-caching.md)

### Inherited from `thermocline-py`
- [ADR-0001: Python 3.11 as primary language](../thermocline/docs/adr/ADR-0001-python-3-11-as-primary-language.md)
- [ADR-0003: Single canonical JSON path](../thermocline/docs/adr/ADR-0003-single-canonical-json-path.md)
- [ADR-0004: BLAKE3 with `algo_version` chain](../thermocline/docs/adr/ADR-0004-blake3-with-algo-version.md)
- [ADR-0005: No in-process key material](../thermocline/docs/adr/ADR-0005-no-in-process-key-material.md)

See [docs/adr/index.md](docs/adr/index.md) for status + dates.

---

## Changelog

### 0.3.0
- Added Threat Model section — six attack surfaces (compromised sovereign node,
  shadow inference, classifier evasion, channel MITM, trust store tampering,
  audit log manipulation) with mitigations and residual risk analysis
- Added Shadow Generation Quality section — abstraction strategies per content type,
  three quality criteria (irreversibility, relevance preservation, distinguishability),
  shadow ID uniqueness requirement
- Added Trust Score section — input signals with weights, composite score formula,
  decay function for inactive channels, threshold table with recommended actions
- Added Classifier Specification section — v0.1 rule-based (current), v0.2 model-based
  (planned) with requirements: local-only, opt-in, confidence threshold, can only
  promote local→shared
- Replaced direct key management with delegation to Thermocline Identity Provider Interface —
  Photophore no longer owns key lifecycle, delegates to identity provider role
- Removed `osaurus` as explicit key scheme reference — identity provider is role-based
  per Thermocline 0.3.0 role architecture
- Moved "The Last Moat" essay, "Relational Technology" section, and naming note to
  Appendix A (non-normative)
- Updated roadmap: v0.3 now covers model-based classifier, shadow quality, trust
  score, threat model
- Simplified dependency declaration to Thermocline 0.3.0+ (minimum version for full feature set)

### 0.2.0
- Added per-step shadow generation for `job` envelopes
- Added manifest authorship sequence (6-step process)
- Added `result_policy` authorship responsibility
- Added job-specific audit log fields
- Extended privacy receipt for job guarantees
- Added Design Constraint 10 (result policy authored by issuer)
- Updated dependency: Thermocline 0.2.0+ for job envelopes

### 0.1.0
- Initial draft release
- Channel registry and trust ceiling model
- Three-tier privacy classification
- Rule-based classifier
- Dispatch-time shadow generation
- Brine signature system
- Privacy receipts
- Append-only cryptographically chained audit log (Ring 1)
- Three-ring storage model
- Channel lifecycle
- Design constraints 1–9

---

## Appendix A — Non-Normative

### The Last Moat

We can now generate almost anything. Agents write code, compose music, draft
legislation, design proteins, run the engines of commerce. The cost of generation
approaches zero. The abundance of capable systems approaches infinity.

In a world where anything can be made, what cannot be copied?

The answer is the same as it has always been: **human relationships.** Not the
products of relationship — those can be generated. The relationship itself. The
history between two people, or two teams, or two nodes that someone deliberately
chose to trust. The moment of extension — *I give this to you, and not to others* —
that no model can perform on your behalf, because it requires you.

This is the only remaining technical moat. Not code. Not data. Not models. The
deliberate, irreducible, human act of deciding who to trust with the good things
you make. This principle — that cooperative advantage derives from human
relationships rather than technical capability alone — will be developed in a
forthcoming thought leadership publication by Dom Sagolla. A reference will be
added here when available.

Photophore is built on this premise. It does not try to automate trust. It tries to
make trust expressible, auditable, and worth having — so that the relationships you
build compound over time into something no one can fork.

You can fork this code. You cannot fork what runs on it.

### Relational Technology

This suite — Thermocline, Photophore, and Seamount — is designed as an expression of
Relational Technology, a framework developed by Anna Spisak as part of her doctoral
research in integral psychology. We reference it here with respect for her ongoing
work and without attempting to define it in her place. Her publication will speak
for itself.

### Who Was Photophore?


This spec carries his name. The shadow protocol follows the same principle: it does
its most important work invisibly, at the moment of dispatch, before anything crosses
a boundary.

### A Note on Naming

See the naming note in the Thermocline specification appendix. The same philosophy applies.
Name your implementations well. Name your channels well. The names you choose reflect
the relationships they carry.

---

*Photophore is maintained as an open community specification. MIT licensed.*
*Companion projects: Thermocline (envelope spec) · Seamount (compute forge)*
