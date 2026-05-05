# Stack Research

**Domain:** Sovereign-node zero-trust policy engine and privacy membrane (Photophore v0.1)
**Researched:** 2026-05-05
**Confidence:** HIGH on language choice, MEDIUM on individual library versions (verify at install time)

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Rust | 1.83+ (stable, 2024 edition) | Implementation language | Memory safety without GC, single auditable static binary, mature crypto/SQLite ecosystem, idiomatic platform-keystore FFI. The sovereign-node ethos demands a small, auditable trust root — Rust delivers that better than any GC'd language. |
| SQLite | 3.46+ (bundled via `rusqlite` `bundled-sqlcipher` feature optional) | Audit log storage (Ring 1) | Spec-mandated. Append-only schema; we control writes; no server. Bundled is preferred for reproducibility. |
| Ed25519 (via `ed25519-dalek` v3) | 3.x | Signature scheme for declared `key_scheme=ed25519` channels | Modern, deterministic, fast verify. Maps directly to spec's "key scheme is declared, not inferred" rule. Audited. |
| BLAKE3 (via `blake3` crate) | 1.5+ | Audit log chain hash + shadow_id generation | Faster than SHA-256, parallelizable, modern. Hash chain dominates CPU on busy nodes — speed matters. |
| Tokio | 1.40+ | Async runtime | Required for dispatch I/O and identity-provider RPC without blocking the classifier pipeline. Ecosystem standard. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `rusqlite` (with `bundled` feature) | 0.32+ | SQLite client | Always — audit log driver. Pin `bundled` to avoid system-SQLite version drift. |
| `keyring` | 3.x | Cross-platform secure keystore wrapper | Trust store backing (Keychain / libsecret / Credential Manager). Spec requires platform keystore — this is the canonical Rust binding. |
| `serde` + `serde_json` | 1.x | Envelope serialization | Always — Thermocline envelopes are JSON. |
| `serde_canonical_json` or `olpc-cjson` | latest | Canonical JSON for signature input | Required — signing must be over a canonical byte representation. Non-canonical JSON breaks signature verification. |
| `uuid` | 1.10+ (`v4` + `v7` features) | Channel IDs, envelope IDs | Use UUIDv7 for monotonic envelope/dispatch IDs (helps audit log ordering); UUIDv4 for shadow IDs (must be unpredictable per spec). |
| `chrono` | 0.4+ (`serde` feature) | Timestamps in audit entries | Always. Use `DateTime<Utc>` exclusively. |
| `tracing` + `tracing-subscriber` | 0.1+ / 0.3+ | Structured logging | Always — debug visibility without leaking content (use `Debug` carefully on tier-0 types). |
| `thiserror` | 2.x | Library error types | Use in non-CLI crates. |
| `anyhow` | 1.x | Application error type | Use in CLI crate only. |
| `secrecy` | 0.10+ | Wrap raw secrets to redact from `Debug`/`Display` | Wrap any value that could be tier-0 or a credential. Defense against accidental log leakage. |
| `hmac` + `sha2` (via `ring` or RustCrypto) | latest | HMAC for receipt-signature verification helpers | Used if the identity provider scheme is HMAC-based; otherwise unused. Keep optional. |
| `clap` | 4.x (`derive` feature) | CLI argument parsing | For `photophore` CLI crate. |
| `assert_cmd` + `predicates` | dev | CLI integration tests | For end-to-end CLI tests of channel/audit/dispatch flows. |
| `tempfile` | 3.x (dev) | Test fixtures | Isolate per-test SQLite databases and trust stores. |
| `proptest` | 1.x (dev) | Property-based tests for classifier and audit chain | Crucial for invariants ("classifier never promotes above explicit tag"; "audit chain hashes always verify"). |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `cargo nextest` | Test runner | Faster than default `cargo test`; parallel-friendly; required for our SQLite-per-test fixtures. |
| `cargo deny` | Supply chain audit | Run in CI. Forbid copyleft and any unaudited transitive dep introducing network calls in classifier crate. |
| `cargo audit` | Vulnerability scan | CI gate. Privacy primitive — no known-vuln transitive deps allowed. |
| `cargo machete` | Detect unused deps | Reduces audit surface. |
| `cargo deadlinks` (mdbook) | Doc link checker | Spec lives alongside code; link rot is real. |
| `mdbook` | Spec/docs site | The README is currently the spec; promote to mdbook when v0.1 stabilizes. |
| `mise` or `rustup` | Toolchain pinning | Pin to 1.83 in `rust-toolchain.toml`. |

## Installation

```bash
# Rust toolchain (pin via rust-toolchain.toml)
rustup default 1.83.0
rustup component add rustfmt clippy

# Cargo workspace dependencies (representative — actual versions in Cargo.toml)
cargo add serde --features derive
cargo add serde_json
cargo add olpc-cjson
cargo add tokio --features full
cargo add ed25519-dalek
cargo add blake3
cargo add rusqlite --features bundled
cargo add keyring
cargo add uuid --features v4,v7,serde
cargo add chrono --features serde
cargo add tracing tracing-subscriber
cargo add thiserror anyhow
cargo add secrecy
cargo add clap --features derive

# Dev
cargo add --dev assert_cmd predicates tempfile proptest
```

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Rust | Go | If a contributor team is Go-native and a second reference implementation is desired. Go's GC and runtime size make it weaker for the primary sovereign-node binary, but a Go reference impl helps prove the spec is implementable in non-systems languages. |
| Rust | TypeScript / Deno | Only as an in-browser shadow generator demo. Not for the sovereign node — runtime size, supply-chain risk, and signing-key handling are unacceptable for the primary impl. |
| BLAKE3 | SHA-256 | If interoperability with an existing SHA-256-only audit log is required. SHA-256 is fine; BLAKE3 is faster. The chain hash algorithm should be declared in audit-log metadata so future migration is possible. |
| Ed25519 | Ed448 / secp256k1 | Ed448 for paranoid post-quantum-adjacent contexts (uncommon). secp256k1 only if interop with blockchain anchors (Ring 3) demands it — but Ring 3 is v0.4. |
| `rusqlite` | `sqlx` (with sqlite feature) | If we expand to async DB access patterns. For v0.1 the audit-log writes are short and rusqlite's blocking model is fine; pulling in sqlx adds query-macro complexity unneeded at this scale. |
| `keyring` crate | Direct platform FFI (Security.framework / libsecret / wincrypt) | Use direct FFI only if `keyring` proves insufficient on Apple Silicon for Secure-Enclave-gated entries (test early). |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| Any cloud or remote inference for classification | Direct spec violation (Design Constraint 1, AT-A4 surface). Even one cloud call defeats the threat model. | Local-only rule pipeline (v0.1); local model classifier (v0.3, opt-in). |
| Storing the trust store in SQLite alongside the audit log | Spec explicitly forbids co-location (AT-A5). Violates threat model. | Platform keystore via `keyring` crate. |
| `reqwest` or any HTTP client in the `classifier` or `audit` crates | These crates must be network-free by construction. Even a transitive HTTP dep is a smell. | HTTP only in the `dispatch` crate, where it talks to forges. Enforce via `cargo deny`. |
| `serde_json` non-canonical serialization for signing input | Signatures over non-canonical JSON are a classic break-the-signature bug. | `olpc-cjson` or `serde_canonical_json` for signing input only. |
| `rand::thread_rng` for shadow_id | Shadow IDs MUST be unpredictable per dispatch. `thread_rng` is fine; just be explicit and never use a deterministic seed. | `rand::rngs::OsRng` for cryptographic-strength uniqueness, plus UUIDv4 wrap for ergonomics. |
| Logging tier-0 content in `tracing` events at any level | Privacy violation. | Wrap tier-0 in `secrecy::SecretString`/`SecretVec` so accidental `Debug` redacts. Add a `tracing` filter that drops fields tagged `sensitive`. |
| `dotenvy` / env-var-based key material | Spec mandates identity provider delegation; keys never live in env. | Identity provider adapter trait — keys never enter Photophore process memory directly. |
| Unbounded SQLite WAL growth | Audit log is append-only and grows forever; default WAL settings can pin large temp files. | Configure `wal_autocheckpoint` carefully; document chain-archival rotation procedure. |

## Stack Patterns by Variant

**If targeting macOS-first deployment (recommended for v0.1):**
- Use `keyring` crate with `apple-native` feature where available
- Test biometric/Secure-Enclave-gated entries early — some Apple Silicon entitlements require code-signed binaries even in dev
- Recommend Homebrew as the install path for v0.1 dev preview

**If targeting Linux server-side use (uncommon for v0.1 but possible):**
- libsecret may not be available headless — fall back to a file-based keystore *only* with explicit user opt-in and with an audit-log warning
- Document that headless mode weakens AT-A5 mitigations

**If a contributor wants a cross-language reference impl:**
- Keep core types defined as JSON Schema in the spec repo (separate from Rust types)
- Generate Rust types from the schema; let other languages do the same
- Conformance test suite operates on JSON fixtures, not Rust APIs

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| `ed25519-dalek` 3.x | `rand_core` 0.6 | 3.x bumped from 2.x; signing API changed. Pin a single version across the workspace. |
| `rusqlite` 0.32 + `bundled` | SQLite 3.46.x | Bundled SQLite is the source of truth; do not mix with system SQLite. |
| Tokio 1.40+ | `tracing` 0.1+ | Use `tracing` not `log` for async-aware spans across dispatch pipelines. |
| `keyring` 3.x | macOS 12+ | Older macOS may lack required Security.framework APIs. Document minimum OS in README. |

## Sources

- Spec: `/Users/dom/Projects/dom/photophore/README.md` (Photophore v0.3.0-draft) — the only normative source for what the impl must satisfy
- RustCrypto org documentation (https://github.com/RustCrypto) — for `ed25519-dalek` v3 migration notes (verify at install)
- BLAKE3 official spec (https://github.com/BLAKE3-team/BLAKE3) — for hash properties
- `keyring` crate docs.rs page — for platform coverage matrix (verify at install)
- Confidence note: individual crate versions move fast; `cargo add` will pull current latest, and `cargo deny` will gate them. The *choice* of Rust + Ed25519 + BLAKE3 + SQLite is HIGH confidence; *exact patch versions* are MEDIUM and should be re-verified at install time.

---
*Stack research for: Photophore v0.1 sovereign-node policy engine*
*Researched: 2026-05-05*
