# Architecture Research

**Domain:** Sovereign-node zero-trust policy engine and privacy membrane (Photophore v0.1)
**Researched:** 2026-05-05
**Confidence:** HIGH (architecture is constrained by the spec; this document maps spec components to crate boundaries)

## Standard Architecture

### System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Sovereign Node (User's Machine)                   │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                    CLI Layer (`photophore`)                     │  │
│  │   channel  |  audit  |  dispatch  |  classify  |  policy        │  │
│  └────────────────────────────┬───────────────────────────────────┘  │
│                               │                                       │
│  ┌────────────────────────────┴───────────────────────────────────┐  │
│  │                  Dispatch Coordinator (orchestrator)             │  │
│  │   1. Resolve channel & ceiling                                   │  │
│  │   2. Classify each context block                                 │  │
│  │   3. Generate shadows for tier-1 / strip tier-0                  │  │
│  │   4. Author result_policy                                        │  │
│  │   5. Delegate signing → identity provider                        │  │
│  │   6. Write audit entry (pre-dispatch)                            │  │
│  │   7. Send envelope (transport)                                   │  │
│  │   8. Verify receipt signature                                    │  │
│  │   9. Append receipt to audit chain                               │  │
│  └────┬─────────┬─────────┬─────────┬───────────┬────────┬─────────┘  │
│       │         │         │         │           │        │            │
│  ┌────┴───┐ ┌──┴────┐ ┌──┴───┐ ┌──┴───┐ ┌────┴────┐ ┌─┴──────┐      │
│  │Channel │ │Class- │ │Shadow │ │Policy│ │Identity │ │ Audit  │      │
│  │ Store  │ │ ifier │ │ Gen   │ │Author│ │Provider │ │  Log   │      │
│  └────┬───┘ └───────┘ └───────┘ └──────┘ │ Adapter │ └───┬────┘      │
│       │                                   └────┬────┘     │          │
│  ┌────┴────────────────────┐               ┌──┴────┐ ┌───┴────┐     │
│  │  Platform Keystore       │               │  IdP  │ │ SQLite │     │
│  │  (Keychain / libsecret / │               │  RPC  │ │   +    │     │
│  │   Credential Manager)    │               │ (TBD) │ │ chain  │     │
│  └──────────────────────────┘               └───────┘ └────────┘     │
│                                                                       │
│  ─── Anchoring Hook (trait) ─── Ring 3 implementation deferred ───   │
└──────────────────────────────────────────────────────────────────────┘
                              │     ▲
                              │     │
                              ▼     │
                          [Network Boundary]
                              │     │
                              ▼     │
                  ┌──────────────────────┐
                  │   Receiving Node     │
                  │   (Forge / Seamount) │
                  │   — out of scope —   │
                  └──────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Typical Implementation |
|-----------|----------------|------------------------|
| Channel Store | Owns the trust registry. Reads/writes channel metadata (id, local/remote node identity, ceiling, key scheme, lifecycle state, creation timestamp). Enforces immutability rules (key scheme immutable; ceiling monotonically decreasing on suspicion). | Rust crate `channels`; backing store is platform keystore via `keyring` crate. SQLite NEVER touches trust store data. |
| Classifier | Owns the three-tier assignment logic. Strict priority order. Produces `(tier, reason)` for every input block. v0.1 is rule-based and deterministic. | Rust crate `classifier`; pure functions (no I/O), unit-testable, no async. Path-rule matcher uses `glob` crate. Network-free by construction (enforced by `cargo deny`). |
| Shadow Generator | Generates shadows for tier-1 content at dispatch time. Per-content-type abstraction strategies. Runs three quality tests (irreversibility = hard fail; relevance + distinguishability = warn). Produces unique shadow IDs per dispatch. | Rust crate `shadow`; pure functions for abstraction; UUIDv4 over OsRng for IDs; quality tests as separate validators. |
| Policy Authoring | Builds `result_policy` block for outgoing envelopes from channel ceiling + output_contract + intent tags. v0.1 covers `task` envelopes; `manifest`-embedded policies are v0.2. | Rust crate `policy`; pure functions; takes channel + envelope draft → returns `result_policy`. |
| Identity Provider Adapter | Trait-based delegation interface for all signing and verification. Photophore never holds keys directly. v0.1 ships one reference adapter (platform keystore, Ed25519). | Rust crate `identity`; trait `IdentityProvider { fn sign(...); fn verify(...); fn scheme(...); }`; reference impl wraps `keyring` + `ed25519-dalek`. |
| Audit Log | Append-only cryptographically chained record of every operation. Each entry hashes the previous (BLAKE3). Queryable. Exportable. Immutable by construction (no delete API). | Rust crate `audit`; SQLite via `rusqlite`; schema enforces append-only via triggers; hash chain verified on every read of "head". |
| Anchoring Hook | Trait for Ring 3 anchoring. v0.1 ships only the trait + a no-op default implementation. Ring 3 implementation deferred. | Rust crate `audit` (sub-module); trait `AnchorTarget { fn anchor_head(hash: BlockHash) -> Result<AnchorReceipt>; }`. |
| Dispatch Coordinator | Orchestrates the 9-step dispatch flow. Owns the lifecycle of a dispatch from envelope draft to receipt verification. Audit-writes happen here, not in individual components. | Rust crate `dispatch`; async (Tokio); only crate that performs network I/O (transport to forge); allowed `reqwest`/`hyper`. |
| CLI | Operability surface. Subcommands: `channel`, `audit`, `dispatch`, `classify`, `policy`. JSON output mode for scripting. | Rust crate `cli` (binary); `clap` derive; uses dispatch coordinator + each underlying crate. |

## Recommended Project Structure

```
photophore/
├── Cargo.toml                    # workspace root
├── rust-toolchain.toml           # pinned toolchain
├── README.md                     # the spec (canonical)
├── deny.toml                     # cargo deny rules (forbid network in classifier/audit)
├── crates/
│   ├── core/                     # shared types: Channel, Tier, Reason, Envelope alias
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── channel.rs        # Channel struct + ChannelId + Ceiling + KeyScheme
│   │       ├── tier.rs           # Tier enum + Reason enum
│   │       ├── shadow.rs         # ShadowId, Abstraction, Relevance newtypes
│   │       ├── envelope.rs       # Thermocline alias types (re-export from `thermocline-spec`)
│   │       └── error.rs          # PhotophoreError (thiserror)
│   ├── channels/                 # trust registry + lifecycle
│   ├── classifier/               # three-tier rule pipeline (network-free)
│   ├── shadow/                   # shadow generator + quality tests
│   ├── policy/                   # result_policy authoring
│   ├── identity/                 # IdentityProvider trait + reference adapter
│   ├── audit/                    # SQLite chained log + export + anchor trait
│   ├── dispatch/                 # coordinator (the only network-allowed crate)
│   └── cli/                      # `photophore` binary
├── tests/                        # cross-crate conformance fixtures
│   ├── conformance/              # JSON envelope fixtures from Thermocline spec
│   └── integration/              # end-to-end CLI flows using `assert_cmd`
└── docs/
    └── adr/                      # Architecture Decision Records (numbered)
```

### Structure Rationale

- **`core/` is the only crate every other crate depends on.** Keeps the dependency graph a clean DAG.
- **`classifier/` and `audit/` are network-free.** This is enforced by `deny.toml` rules that forbid any transitive HTTP dependency. Privacy primitive — must be auditable in isolation.
- **`dispatch/` is the only crate with network access.** Concentrates the AT-A4 (channel MITM) attack surface in one auditable place.
- **`identity/` exports a trait, not a struct.** The reference adapter is a single impl module; HSM/hardware adapters can be added without changing the dispatch crate.
- **`channels/` and `audit/` use different backing stores.** Direct mapping of spec mandate (separate trust store from audit log).
- **The CLI is a separate binary crate.** Library crates remain importable for embedding (e.g., a future GUI or a Tauri app).
- **`docs/adr/`** holds Architecture Decision Records — each significant choice gets a numbered ADR (e.g., `001-rust-as-primary-language.md`, `002-blake3-for-chain-hash.md`). Helps future contributors understand why constraints exist.

## Architectural Patterns

### Pattern 1: Pure-Core / Imperative-Shell

**What:** Classifier, shadow generator, and policy author are pure functions with no I/O. The dispatch coordinator is the imperative shell that performs I/O (DB writes, network calls, signing RPC).
**When to use:** Always for the privacy-critical components.
**Trade-offs:** Forces values to be passed explicitly (no global state) — verbose but testable. Eliminates a whole class of "the classifier secretly hit the network" bugs.

**Example:**
```rust
// crates/classifier/src/lib.rs — pure, no I/O
pub fn classify(block: &ContentBlock, rules: &PathRules) -> Classification {
    if let Some(tag) = block.explicit_tag() {
        return Classification { tier: tag.into(), reason: Reason::ExplicitTag };
    }
    if let Some(rule) = rules.match_path(block.path()) {
        return Classification { tier: rule.tier, reason: Reason::PathRule(rule.pattern.clone()) };
    }
    rule_based_default(block) // also pure
}

// crates/dispatch/src/lib.rs — imperative shell
pub async fn dispatch(...) -> Result<Receipt, DispatchError> {
    let channel = channels.get(channel_id).await?;          // I/O
    let classifications = blocks.iter()
        .map(|b| classify(b, &channel.rules))               // PURE
        .collect::<Vec<_>>();
    let shadows = generate_shadows(&classifications)?;       // PURE
    let policy = author_policy(&channel, &draft);            // PURE
    audit.append(pre_dispatch_entry(...)).await?;           // I/O
    let signed = identity.sign(envelope_bytes).await?;       // I/O (delegated)
    let receipt = transport.send(signed).await?;             // I/O (network)
    identity.verify(&receipt.signature).await?;              // I/O (delegated)
    audit.append(receipt_entry(...)).await?;                // I/O
    Ok(receipt)
}
```

### Pattern 2: Trait-Boundaried Adapters

**What:** Every external dependency (identity provider, transport, anchor target) is a trait, not a concrete type. Reference implementations ship in v0.1; alternative implementations slot in without changing call sites.
**When to use:** Any boundary that crosses the sovereign-node trust boundary OR may have multiple legitimate implementations (HSM vs. software keystore; Ring 3 Arweave vs. Bitcoin vs. Ethereum).
**Trade-offs:** Slight indirection cost; massive flexibility for future migrations and for testability.

**Example:**
```rust
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    fn scheme(&self) -> KeyScheme;
    async fn sign(&self, message: &[u8]) -> Result<Signature, IdentityError>;
    async fn verify(&self, message: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<(), IdentityError>;
}
```

### Pattern 3: Append-Only with Hash-Chained Verification

**What:** Audit log entries form a Merkle-like chain — each entry includes `prev_hash = blake3(previous_entry_canonical_bytes)`. The chain head is the "current proof". Tampering at position N invalidates positions N+1..end.
**When to use:** This is the audit log; it's not optional.
**Trade-offs:** Cannot delete or amend entries (by design). Recovery from corruption requires archiving and starting a new chain — the archive remains as evidence.

**Example:**
```rust
#[derive(Serialize, Debug)]
pub struct AuditEntry {
    pub seq: u64,
    pub prev_hash: BlockHash,        // BLAKE3 of canonical prior entry
    pub timestamp: DateTime<Utc>,
    pub kind: AuditEntryKind,
    // ... fields per spec
}

impl AuditEntry {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Use canonical-JSON, NOT serde_json::to_vec
        olpc_cjson::to_vec(self).expect("canonical")
    }
    pub fn hash(&self) -> BlockHash {
        BlockHash(blake3::hash(&self.canonical_bytes()).into())
    }
}
```

### Pattern 4: Newtype Wrappers for Privacy-Critical Values

**What:** Wrap any tier-0-or-could-be value in a newtype that redacts on `Debug`/`Display`.
**When to use:** Any field that could carry private content. Use `secrecy::SecretString` / `SecretVec` from the `secrecy` crate.
**Trade-offs:** Need explicit `expose_secret()` calls when crossing trust boundaries — friction is the feature.

**Example:**
```rust
use secrecy::{Secret, SecretString};

pub struct ContentBlock {
    pub id: BlockId,
    pub tier: Tier,
    pub content: Secret<Vec<u8>>,   // redacted in any logs
}

// Logging this struct's Debug output produces:
//   ContentBlock { id: ..., tier: Local, content: [REDACTED] }
```

## Data Flow

### Dispatch Flow (the core protocol path)

```
[User invokes `photophore dispatch <task.json>`]
    ↓
[CLI parses → builds DispatchRequest]
    ↓
[Dispatch Coordinator: resolve Channel by id]
    ↓
[Classifier: classify each context block]
    ↓
[Shadow Generator: produce shadows for tier-1; strip tier-0]
    ↓
[Policy Author: build result_policy from ceiling + output_contract]
    ↓
[Audit Log: append PRE-DISPATCH entry (chain extends)]
    ↓
[Identity Provider Adapter: sign envelope bytes (RPC to keystore)]
    ↓
[Transport: send signed envelope to forge]                                        ◄─── only network I/O
    ↓
[Forge processes → returns signed receipt]
    ↓
[Identity Provider Adapter: verify receipt signature against channel's declared scheme]
    ↓
[Audit Log: append RECEIPT entry (chain extends)]
    ↓
[CLI: print result + receipt summary]
```

### Audit Read Flow

```
[CLI: `photophore audit query --channel CH123 --since 2025-01-01`]
    ↓
[Audit Log: SELECT FROM entries WHERE channel_id = ? AND ts >= ?]
    ↓
[Verify chain integrity for returned slice (re-hash each entry, check prev_hash links)]
    ↓
[Render: human / JSON / JSONL]
```

### State Management

There is no in-memory mutable state outside per-dispatch coordinators. Persistent state lives in:
- **Trust store** (platform keystore) — channel registry. Single writer (Channel Store crate). Concurrent reads safe.
- **Audit log** (SQLite) — append-only. Single writer per process; readers can run concurrently in WAL mode.
- **Path rules config** (YAML on disk) — read at startup; reload via SIGHUP or CLI command.

### Key Data Flows

1. **Dispatch (write path):** envelope draft → classifications → shadows + stripped → policy → signed → audit-pre → wire → receipt → verify → audit-post.
2. **Audit query (read path):** query → SQL → chain verification slice → render.
3. **Channel lifecycle:** human action (CLI) → Channel Store mutation → audit entry.
4. **Configuration (path rules):** edit YAML → reload → validation (catch-all `**` → local must exist) → in-memory rule table.

## Scaling Considerations

Photophore is a single-node policy engine. "Scale" here means dispatches/sec on one machine, and audit-log size over time.

| Scale | Architecture Adjustments |
|-------|--------------------------|
| 1–100 dispatches/day (typical personal use) | No optimization needed. SQLite WAL with default settings. Single Tokio runtime. |
| 100–10k dispatches/day (heavy individual or small team) | Index audit log by `(channel_id, ts)` and `(envelope_id)`. Use prepared statements for hot writes. Periodically `PRAGMA wal_checkpoint(TRUNCATE)`. Move shadow-quality-test execution off the hot path if it becomes a bottleneck (it shouldn't — these are pure functions). |
| 10k+ dispatches/day (organizational gateway use, beyond v0.1's design center) | Reconsider — Photophore is not designed as a multi-tenant gateway. If this scale is real, the architecture needs a "multi-channel batching" layer that v0.5+ might add. v0.1 should *not* design for this. |

### Scaling Priorities

1. **First bottleneck:** likely audit-log write fsync latency under burst dispatches. Mitigate with WAL + `synchronous=NORMAL` (still safe given checkpoint discipline) and batched commits where the dispatch coordinator can group multiple audit appends.
2. **Second bottleneck:** identity-provider RPC latency (signing requires keystore call, possibly with biometric prompt on macOS). Caching policy MUST NOT cache signatures themselves — but session-scoped authentication tokens can be cached briefly (with explicit user consent) to avoid prompt fatigue.

## Anti-Patterns

### Anti-Pattern 1: Trust Store in SQLite Alongside Audit Log

**What people do:** Put both stores in one SQLite file because "it's simpler."
**Why it's wrong:** The threat model (AT-A5: trust store tampering) explicitly relies on the trust store living in a tamper-resistant platform keystore. Co-location collapses two threat boundaries into one.
**Do this instead:** Trust store ALWAYS in platform keystore. Audit log ALWAYS in SQLite. Separate processes if necessary. Document the separation in ADR-001.

### Anti-Pattern 2: Caching Shadows

**What people do:** "Shadows are expensive to generate; let's memoize by content hash."
**Why it's wrong:** Per-dispatch shadow ID uniqueness is a cryptographic requirement (defeats AT-A2 shadow inference). A cache makes IDs correlatable across dispatches, breaking the privacy guarantee.
**Do this instead:** Cache the upstream classification *result* if needed. NEVER cache the shadow itself. Each dispatch generates fresh.

### Anti-Pattern 3: Optional Audit Writes

**What people do:** Add a `--quiet` flag or `audit_disabled` config option for "performance".
**Why it's wrong:** The audit log IS the proof that a privacy violation didn't occur. Optional audit makes the entire trust score system unreliable.
**Do this instead:** Audit writes are mandatory. If write fails, the dispatch fails. Use the WAL for performance, not bypass.

### Anti-Pattern 4: Generic Abstractions in Shadow Strings

**What people do:** Generate abstractions like `"a document"` or `"some content"` to be safe.
**Why it's wrong:** Fails the distinguishability test — different content produces identical shadows, the receiver can't reason about them. The whole point is to convey relevance.
**Do this instead:** Per-content-type abstraction strategies (spec table). Specific enough to be useful, vague enough to be irreversible. Test irreversibility on every shadow.

### Anti-Pattern 5: Implicit Network Calls in `classifier`

**What people do:** Pull in a "convenience" library for, e.g., URL parsing that has a transitive HTTP dependency.
**Why it's wrong:** The classifier MUST be network-free. A latent HTTP dependency, even unused, is an audit failure and a supply-chain attack surface.
**Do this instead:** Enforce via `cargo deny` rules (`crates/classifier` and `crates/audit` may not pull `reqwest`, `hyper`, `ureq`, etc.). CI gate.

### Anti-Pattern 6: `unwrap()` / `panic!` on Audit Write Failures

**What people do:** "If the audit log fails, we have bigger problems — just panic."
**Why it's wrong:** Panic might leave the dispatch in a half-committed state. Worse, panic in async tasks may abort silently.
**Do this instead:** Audit write failure is a `DispatchError::AuditFailed`. The dispatch surface returns an error; the user sees a clear "cannot dispatch — audit log unavailable" message. The signed envelope is NEVER sent if audit-pre failed.

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| Platform keystore (Keychain / libsecret / Credential Manager) | `keyring` crate trait + reference adapter in `identity/` | macOS Secure Enclave entries may require a code-signed binary in production; Apple developer account needed for distribution. |
| Forge (Seamount) | HTTP/JSON over TLS (recommended); transport-agnostic per Thermocline spec | The dispatch crate owns this. Receipt signature verification is the integrity boundary, not the transport. |
| Anchoring target (Ring 3) | Trait `AnchorTarget`; v0.1 ships only the trait + no-op default | Arweave reference impl deferred to v0.4. |
| Identity provider | Trait `IdentityProvider`; v0.1 reference adapter uses platform keystore + Ed25519 | Future: HSMs, hardware tokens, smartcards. The trait must be stable across these. |

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| `core` ↔ everything | Direct dependency | Pure types, no I/O. |
| `classifier` ↔ `dispatch` | Direct function calls (sync, no async) | Classifier is CPU-bound and pure; no need for async. |
| `shadow` ↔ `dispatch` | Direct function calls (sync) | Same as classifier — pure. |
| `audit` ↔ everywhere that writes | Async function calls | SQLite writes go through Tokio's blocking-task pool to avoid blocking the runtime. |
| `identity` (trait) ↔ `dispatch` | Async trait calls | RPC to keystore may take >100ms (biometric prompt); must be async. |
| `dispatch` ↔ transport (HTTP) | `reqwest` async client | Only HTTP-allowed crate per `cargo deny`. |
| CLI ↔ everything | Direct dependency on library crates | CLI is the only place where `anyhow` is acceptable; library crates use `thiserror`. |

## Sources

- Spec: `/Users/dom/Projects/dom/photophore/README.md` (Photophore v0.3.0-draft) — defines components, data flows, and threat boundaries
- "Pure Core, Imperative Shell" pattern (Gary Bernhardt, 2012) — applied to privacy-critical components
- Rust API Guidelines (https://rust-lang.github.io/api-guidelines/) — for trait + adapter design
- BLAKE3 paper / spec (https://github.com/BLAKE3-team/BLAKE3) — for chain-hash properties
- Confidence: HIGH on architecture (largely determined by the spec); HIGH on the crate boundaries (informed by Rust ecosystem norms)

---
*Architecture research for: Photophore v0.1*
*Researched: 2026-05-05*
