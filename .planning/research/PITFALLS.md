# Pitfalls Research

**Domain:** Sovereign-node zero-trust policy engine and privacy membrane (Photophore v0.1)
**Researched:** 2026-05-05
**Confidence:** HIGH (these are domain-specific failure modes drawn directly from the spec's threat model and from common privacy-engineering mistakes)

## Critical Pitfalls

### Pitfall 1: Classifier Default Drift

**What goes wrong:**
A maintainer adds a new content type or rule, and the implicit "everything else" branch ends up assigning `shared` or `public` to content that should be `local`. Privacy guarantee silently breaks.

**Why it happens:**
The conservative default is *easy to forget* in code review. When adding a new branch, it's natural to think "I'll handle the new case and let the rest fall through" — but the rest must always fall through to `local`, and that's not enforced by the type system unless the design makes it so.

**How to avoid:**
- Make `Tier::Local` the value returned by an explicit fallthrough function `default_tier()`. The classifier MUST call this function (not return a literal) for the default branch. Document the function as a privacy-critical primitive.
- Add a property test (proptest): for any randomly generated `ContentBlock` with no explicit tag and no path-rule match, the classifier returns `(Tier::Local, Reason::ClassifierDefault)`.
- Add a CI check that the string `Tier::Public` does not appear in classifier source files except in tag-handling and path-rule-handling branches.

**Warning signs:**
- A new test fails with "expected Local, got Shared" — investigate whether the test is wrong or the new rule is wrong (assume the new rule is wrong).
- Code review for any classifier change shows a new `match` arm without a `_ => Tier::Local` catch-all.

**Phase to address:**
Phase: classifier implementation. Property tests must land with the first classifier merge.

---

### Pitfall 2: Shadow Abstraction Leakage

**What goes wrong:**
A shadow's `abstraction` string passes the schema (it's a string of reasonable length) but contains identifying detail — for example, "a Q3 earnings memo from a Bay Area technology company" narrows the universe enough that the receiver (or an observer) can de-anonymize. Schema-valid, privacy-broken.

**Why it happens:**
- Developers writing per-content-type abstraction strategies optimize for relevance preservation and forget the irreversibility test.
- The temptation to be "helpful" leads to over-specific abstractions.
- Test fixtures use real-looking content, and abstractions inadvertently reflect specifics.

**How to avoid:**
- Implement an explicit `irreversibility_test(shadow: &Shadow) -> Result<(), QualityFailure>` that runs heuristic checks: no proper nouns, no specific dates, no organization-shaped tokens, length within a fixed budget per type. Hard fail on any check.
- Maintain a fixture list of "leaky abstractions caught in review" with explanations — refer to it during reviews.
- Run the irreversibility test as a hard gate in the dispatch coordinator. If it fails, the dispatch fails.

**Warning signs:**
- An abstraction string contains capital letters in the middle of words (likely proper nouns).
- An abstraction includes years, dates, or numeric ranges narrower than a calendar quarter.
- Two shadows from different source content produce wildly different abstraction lengths — possibly indicates one is too specific.

**Phase to address:**
Phase: shadow generator implementation. The irreversibility test ships with the first shadow code, not after.

---

### Pitfall 3: Audit Chain Algorithm Lock-In

**What goes wrong:**
The audit log uses a single hash algorithm (e.g., BLAKE3) baked into the entry struct without versioning. Years later, a vulnerability emerges or interop with another system requires migration, and the entire chain has to be re-hashed (impossible by definition for an append-only log) or abandoned.

**Why it happens:**
"YAGNI" — version fields feel premature when there's only one algorithm.

**How to avoid:**
- Include an `algo_version` field in every audit entry from day 1 (e.g., `"chain_algo": "blake3-v1"`).
- Verifier code reads the field and dispatches to the appropriate hash function. v0.1 only implements `blake3-v1`, but the dispatch path exists.
- Document an ADR explaining the design and the migration story (start a new chain with the new algorithm; the old chain remains as evidence).

**Warning signs:**
- Code review for the audit-log schema shows hash algorithm hardcoded in the struct literal.
- Discussion of "which hash algorithm is best" without discussion of "how do we migrate later".

**Phase to address:**
Phase: audit log schema design. This is a one-line decision that's easy to get right early and very expensive to retrofit.

---

### Pitfall 4: Implicit Trust Elevation Through "Helpful" Logging

**What goes wrong:**
A `tracing::info!` call writes a tier-0 content block to the structured-log output for "debugging convenience", or a `Debug` impl on a struct exposes inner content. Private content leaks into logs that may be shipped to a log aggregator, written to disk, or read by another process.

**Why it happens:**
Rust's `Debug` derive is reflexive — it includes every field. Developers add `#[derive(Debug)]` reflexively. Tracing macros happily format whatever you pass them.

**How to avoid:**
- Wrap any potentially-tier-0 value in `secrecy::Secret<T>` so its `Debug` impl prints `[REDACTED]`.
- Forbid `#[derive(Debug)]` on any struct containing raw content; require a custom impl that redacts.
- Add a `tracing` filter layer that drops fields tagged `sensitive=true`.
- CI lint: forbid `tracing::*!(... content_block ...)` patterns with a custom regex check.

**Warning signs:**
- A debug log contains a string longer than ~200 characters that looks like document content.
- A struct holding `Vec<u8>` content has `#[derive(Debug)]`.
- A bug report includes a log file with quoted content snippets.

**Phase to address:**
Phase: core types definition. Lint and types ship together with the first `core` crate merge.

---

### Pitfall 5: Receipt Verification Skipped Under Time Pressure

**What goes wrong:**
The dispatch coordinator returns `Ok(receipt)` after appending the receipt to the audit log but *before* (or without) verifying the receipt's signature. Forge could return forged receipts; audit log records "successful round-trip" that never happened.

**Why it happens:**
- Async error handling is easy to short-circuit.
- "We'll verify later" is a tempting refactor when chasing a flaky test.
- The privacy receipt design is "round-trip proof" — but only if both halves are verified.

**How to avoid:**
- Make `Receipt` a type that is constructed only by a verification function; there's no public constructor.
- The dispatch coordinator calls `verify_receipt()` before any audit write referring to the receipt.
- Add an integration test that returns a malformed receipt signature and asserts the dispatch errors.
- ADR: "Receipt is constructable only by IdentityProvider::verify."

**Warning signs:**
- Code review for dispatch flow shows an audit write between `transport.send()` and the verify call.
- A test fails by passing — i.e., a forged receipt path produces `Ok`.

**Phase to address:**
Phase: dispatch coordinator implementation. Verification path must land in the same PR as transport.

---

### Pitfall 6: Trust Store Backup That Defeats the Threat Model

**What goes wrong:**
Implementing a "trust store backup" feature that exports trust-store content to a file or to remote storage. The backup file (or its remote copy) becomes a new attack surface that bypasses the platform-keystore protection.

**Why it happens:**
- Operational pressure: "what if my Mac dies?"
- Borrowed expectation from password-manager UX where cloud sync is normal.
- Misreading the spec: backup feels like a basic feature.

**How to avoid:**
- Follow the spec literally: trust store NEVER leaves the node, no remote sync.
- Document a manual recovery procedure: re-establish channels with the remote nodes (which is a human act anyway). Re-establishment is a *feature*, not a bug — it forces fresh trust attestation.
- If a backup mechanism is added (v1.0+), encrypt with a hardware-key-protected secret on the same machine, and explicitly document that restoring on a different machine requires re-establishment of every channel.
- If a contributor opens a PR titled "trust store backup", apply spec-compliance review before any code review.

**Warning signs:**
- Discussion of trust-store sync, cloud backup, or "channel migration between machines".
- A new dependency on cloud-storage SDKs in any crate.

**Phase to address:**
Phase: channels (trust store) implementation. The non-existence of this feature is itself a design decision — capture it in ADR-005 or similar.

---

### Pitfall 7: Eager Classification at Write Time Instead of Dispatch Time

**What goes wrong:**
For "performance", the system classifies content when it's written (e.g., when a file is created on disk) rather than at dispatch time. The classification is then *cached*, and the cache becomes stale when content changes — or worse, the cached `shared` classification is reused across channels with different ceilings, leaking content that should have stayed local on the lower-ceiling channel.

**Why it happens:**
"Classification is expensive; let's amortize it" is a natural systems-engineering instinct. The spec mandate to classify at dispatch time is easy to misread as "first dispatch" rather than "every dispatch".

**How to avoid:**
- Spec compliance: classification runs every dispatch.
- Cache *path rule lookups* (cheap, channel-independent) but NOT classification *results*.
- If the cost of re-running rules is too high, optimize the rule engine, not the cache.
- Test: dispatch the same content twice in quick succession, assert the audit log shows two classification reasons (and the shadow IDs are different).

**Warning signs:**
- A "classification cache" data structure in the codebase keyed by content hash.
- A discussion of "speed up classification" without distinguishing which step is slow.

**Phase to address:**
Phase: dispatch coordinator. ADR explicitly forbids cross-dispatch classification caching.

---

### Pitfall 8: Insufficient Path-Rule Catch-All Validation

**What goes wrong:**
A user's path-rules YAML is missing the mandatory `**` → `local` catch-all (or it's mis-ordered above more specific rules). Photophore loads the config without complaining, and content that doesn't match any rule receives an undefined or permissive default.

**Why it happens:**
YAML parsers don't enforce semantic rules. The spec mandate is a paragraph in prose, not a schema constraint.

**How to avoid:**
- Validate path-rules config at load time. Reject any config that lacks an exact `**` → `local` entry as the LAST rule.
- Provide a `photophore config validate` CLI command and run it at startup; refuse to start if invalid.
- Provide a default config template that includes the catch-all and document that removing it is unsupported.

**Warning signs:**
- A path-rules config file shorter than ~5 lines (suspicious — minimal configs often forget the catch-all).
- A test that loads a config without the catch-all and the test passes.

**Phase to address:**
Phase: classifier or channels (whichever owns rule loading). Validation lands with the loader.

---

### Pitfall 9: Identity Provider Adapter That Holds Keys In Process

**What goes wrong:**
A "convenient" identity provider adapter that decrypts the private key into process memory at startup and signs in-process. Now Photophore's process memory contains key material — the threat model assumed it would not.

**Why it happens:**
- Performance optimization (avoid keystore RPC per signature).
- Initial implementation shortcut that "we'll fix later".
- Misreading "delegate signing" as "import keys at startup".

**How to avoid:**
- Reference adapter calls into the platform keystore for *every signature*. The keystore returns a signature, never the key.
- Trait method signature returns `Signature`, never `PrivateKey` — make the wrong implementation impossible to write.
- Apple Silicon Secure Enclave entries cannot be exported even if requested — leverage this when available.

**Warning signs:**
- An identity adapter with a struct field of type `PrivateKey` or `[u8; 32]` for a key.
- A configuration option to "cache the unlocked key for N minutes".

**Phase to address:**
Phase: identity provider adapter. Trait design phase, not implementation phase.

---

### Pitfall 10: Conformance Tests That Don't Test Negatives

**What goes wrong:**
Tests verify that valid envelopes round-trip correctly. They don't verify that *invalid* envelopes (forged signatures, mismatched key schemes, missing result_policy, escalated tiers) are rejected. A regression that silently accepts invalid input passes CI.

**Why it happens:**
Happy-path testing is faster to write and easier to reason about. Negative testing requires explicit attack-surface enumeration.

**How to avoid:**
- For each AT-* surface in the threat model, write at least one negative test that exercises the attack and asserts rejection.
- Maintain a fixture directory of "rejected envelopes with reasons" — each fixture documents what's wrong with it.
- CI: count negative tests, fail if it drops below the threat-model surface count.

**Warning signs:**
- A test directory with `valid/` but no `invalid/`.
- Test names of the form `test_foo_works` outnumbering `test_foo_rejects_*` by more than 3:1.

**Phase to address:**
Phase: conformance test suite (any phase that ships verification logic).

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Hardcoded `chain_algo` field instead of a versioned enum | One fewer line of code | Cannot migrate hash algorithm without abandoning the chain | Never — this is a one-line decision that determines forever-properties of the audit log. |
| Skipping the irreversibility test "for now" | Ships shadows faster | Privacy violation by default; every dispatch is a potential leak | Never — irreversibility is the hard constraint per the spec. |
| Single SQLite for trust store + audit log | Simpler ops | Conflates threat boundaries; AT-A5 mitigation collapses | Never — the spec mandates separation. |
| `unwrap()` on audit writes "because what could go wrong" | Cleaner code | Panic during dispatch; signed envelope sent without audit record | Never in production code paths. Only acceptable in tests with isolated DBs. |
| Caching identity-provider unlock state | Avoids biometric prompt fatigue | Breaks "delegated signing" guarantee; key material adjacent to process memory | Possibly v0.5+ with explicit user opt-in and audit-log entries for cache lifetime — never v0.1. |
| Skipping shadow distinguishability test (warn-level) | Faster dispatch on edge cases | Lower-quality shadows; eventually a privacy regression | Acceptable for v0.1 if the test runs and warns; never if the test is removed. |
| Ed25519 only, no scheme abstraction | Less indirection | Future migration to post-quantum signatures requires a v0.2+ rewrite | Acceptable in v0.1 IF the channel's `key_scheme` field is in the data model and verifier dispatches on it (just hardcoded to Ed25519). |
| `serde_json::to_vec` for signing input "it's deterministic enough" | One fewer dependency | Signature breaks with map-ordering or whitespace changes | Never — canonical-JSON is non-negotiable for signing. |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| macOS Keychain via `keyring` | Storing entries that require biometric unlock without user prompting infrastructure | Detect biometric requirement at channel-open time; surface a clear UX flow ("Touch ID required to access Keychain entry"). |
| macOS Secure Enclave | Assuming `keyring` crate transparently uses Secure Enclave | It doesn't always — verify the entry attributes; use lower-level `security-framework` crate for SE-specific entries. Test on Apple Silicon. |
| Linux `libsecret` | Failing on headless servers (no D-Bus session) | Detect at startup; if no `libsecret` available, refuse to run (don't silently fall back to file-based store). |
| Windows Credential Manager | UTF-8 vs UTF-16 string handling | The `keyring` crate handles this, but custom integrations historically don't. Test with non-ASCII channel names. |
| SQLite WAL mode | Forgetting to checkpoint; WAL grows indefinitely | Set `PRAGMA wal_autocheckpoint=1000`; manual checkpoint on graceful shutdown. |
| Thermocline envelope schema | Implementing an older spec version (e.g., v0.2) and tagging as 0.3 | Pin to Thermocline 0.3.0+ types; CI conformance run against canonical fixtures. |
| Tokio + blocking SQLite | Calling `rusqlite` directly in async functions | Wrap in `tokio::task::spawn_blocking` for any non-trivial query, or use a per-process write thread with channel-based dispatch. |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Recomputing path-rule matches per content block | Slow classification on dispatches with many blocks | Compile rules into a single matcher (e.g., aho-corasick or precomputed glob set) at config load time | Bursts of >100 blocks per dispatch |
| BLAKE3 chain-hash on full audit log on every read | Linear-time chain verification grows with log size | Verify only the slice of entries returned by query; expose chain-head verification as a separate explicit operation | After ~10k audit entries (still tractable, but doesn't scale to 1M+) |
| SQLite WAL bloat | Disk usage grows unboundedly | Periodic `wal_checkpoint(TRUNCATE)`; document in ops guide | Long-running dispatches on a busy node |
| Synchronous keystore RPC on every audit-log write | Latency spikes when writing audit | Audit writes don't need keystore — only signing does. Don't conflate the two. | Refactors that "unify" signing and audit |
| `serde_json` reflect-based serialization on hot dispatch path | CPU bound on dispatch when classifying many blocks | Pre-compile serde derives; benchmark before optimizing | Only on extremely high dispatch rates — likely premature for v0.1 |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Logging signed envelope bytes after signing | Signature material leaks to log aggregators | Wrap envelope post-sign in `Secret<...>`; redact in logs by default. |
| Using `rand::thread_rng` deterministically seeded in tests, then accidentally in prod | Predictable shadow IDs → AT-A2 viable | Tests use a separate constructor that takes `rng: &mut impl RngCore`; prod always uses `OsRng`. Type-checked. |
| Failing closed → failing open on transient errors | A keystore RPC timeout returns `Ok(())` instead of error | Audit failures are dispatch failures. No optimistic paths. |
| Using `==` to compare signatures (timing oracle) | Side-channel timing attacks on signature verification | Use `subtle::ConstantTimeEq` or signature library's built-in verify (which is constant-time). |
| Writing partial canonical JSON before signing | Canonicalization bug → signature verifies on receiver but doesn't actually cover full envelope | Canonical-JSON is one library call; verify with property tests over arbitrary envelope shapes. |
| Hardcoding `key_scheme = "ed25519"` instead of reading from channel | Future channels with different schemes silently downgrade | The verifier dispatches on `channel.key_scheme`; hardcoded values are a CI lint failure. |
| Allowing the user to suppress quality-test failures | Privacy violation by user choice; user blames the tool | Hard fails are non-suppressible. Warns can be suppressed but only with an audit-log annotation. |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Cryptic "tier mismatch" errors | User can't diagnose why their dispatch failed | Error messages include the classification reason: "Block 3 classified as `local` (reason: classifier:credential_pattern); ceiling on channel 'forge-1' is `tier-1`. Cannot dispatch tier-0 content." |
| No way to ask "why is this content `local`?" without dispatching | User over- or under-tags content | Provide `photophore classify <path>` as a dry-run with full reason output. |
| Channel-creation UX that requires editing JSON by hand | Adoption friction | First-class `photophore channel new` flow with prompts for each required field. Schema-validate before write. |
| Trust-score warnings that don't tell the user what to do | User dismisses warnings without action | Each threshold band ships with a recommended action ("RECOMMEND suspension; run `photophore channel suspend CH123`"). |
| Audit log queries that overwhelm the user with raw rows | User can't find the dispatch they care about | Default to `--format=summary` (one line per dispatch); offer `--format=json` for scripting; offer `--format=detail` per-entry. |
| Silent biometric prompts that look like the app froze | User retries, double-dispatch | Detect the prompt; print "Awaiting Keychain unlock..." before initiating. |

## "Looks Done But Isn't" Checklist

- [ ] **Classifier:** explicit-tag and path-rule branches produce `Reason::ExplicitTag` / `Reason::PathRule(pattern)` in the assignment record — verify both `tier` AND `reason` round-trip through audit.
- [ ] **Shadow generator:** every shadow runs the irreversibility test; failure surfaces as a hard error, not a warn — verify with a fixture that intentionally has a leaky abstraction.
- [ ] **Audit log:** chain verification on read covers the entire returned slice and refuses to return entries whose `prev_hash` doesn't match — verify with a fixture that tampers a single entry's bytes.
- [ ] **Identity provider adapter:** `IdentityProvider::sign` never returns the key; refuses to be called for a scheme other than the channel's declared scheme — verify via type-system constraint AND a runtime check.
- [ ] **Dispatch coordinator:** receipt verification happens before the receipt is appended to the audit log; failure to verify aborts the dispatch — verify with a fixture forge that returns a forged signature.
- [ ] **Trust store:** writing to the trust store is a single function `Channels::open_channel(...)`, and there's no path that mutates the store outside that function — verify by code search for direct keystore writes.
- [ ] **Path rules:** loading a config without the `**` → `local` catch-all returns an error before the rules are applied — verify with a fixture missing the catch-all.
- [ ] **Result policy:** the dispatch coordinator authors `result_policy` from channel + draft and the policy never comes from the input — verify by code review and by a fixture that includes a draft `result_policy` (must be ignored or rejected).
- [ ] **CLI:** every subcommand emits an audit log entry on completion (success or failure) — verify by integration test grep over audit DB after each subcommand.
- [ ] **Anchoring hook:** the trait exists, has at least one no-op default implementation, and the dispatch flow can be configured with the no-op without warnings — verify via a smoke test with the no-op explicitly selected.

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Audit chain corruption detected | MEDIUM | 1. Halt dispatches. 2. Archive the corrupted chain (DO NOT delete). 3. Run a forensic verification report. 4. Start a new chain rooted at the verification report's hash. 5. Document in audit-archive metadata. |
| Trust store entry tampered | HIGH | 1. Suspend all channels backed by the tampered entry. 2. Audit-log the suspension. 3. Re-establish channels with remote parties (human-in-the-loop). 4. Open a security incident ADR. |
| Shadow leakage discovered post-dispatch | HIGH | The bell can't be unrung — the receiver has the leaked data. 1. Suspend the channel. 2. Notify the human operator. 3. Update the abstraction strategy that produced the leak. 4. Add an irreversibility test fixture for the case. 5. Audit-log the incident. |
| Receipt verification regressed (CI miss) | LOW (caught early) / HIGH (caught late) | If pre-release: fix forward, add a negative test, ship. If post-release: yank the release if the bug is verified-late-only; communicate to channel operators. |
| Identity provider adapter accidentally cached keys | HIGH | 1. Treat all keys backed by the buggy adapter as compromised. 2. Rotate keys per the platform keystore's rotation procedure. 3. Re-sign any active envelopes (human-confirmed). 4. Patch and rebuild. |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Classifier default drift | Classifier implementation | Property test asserts `Local` default for any unmatched block |
| Shadow abstraction leakage | Shadow generator implementation | Irreversibility test gates dispatch; fixture suite of caught leaks |
| Audit chain algorithm lock-in | Audit log schema design (early) | `algo_version` field present in entry struct from day 1 |
| Implicit trust elevation through logging | Core types definition | `secrecy::Secret` wrapping; lint forbidding `derive(Debug)` on content-bearing structs |
| Receipt verification skipped | Dispatch coordinator | `Receipt` constructible only by verify; integration test with forged receipt |
| Trust store backup defeating threat model | Channels (trust store) | Spec-compliance review for any PR adding "backup"/"sync" |
| Eager classification at write time | Dispatch coordinator | ADR explicitly forbids cross-dispatch classification cache |
| Path-rule catch-all missing | Classifier or channels (rule loader) | Validation gate at config load |
| Identity provider holding keys | Identity adapter (trait + impl) | Trait signature returns `Signature` never `PrivateKey`; adapter calls keystore per-sign |
| Negative tests missing | Conformance test suite | CI gate counts negative tests vs. AT-* surfaces |

## Sources

- Spec: `/Users/dom/Projects/dom/photophore/README.md` — especially the Threat Model section (six attack surfaces) and Design Constraints (10 normative constraints)
- Practical privacy-engineering experience patterns from differential privacy and DLP system retrospectives (industry knowledge, not a single citation)
- Rust idioms: secrecy crate docs (https://crates.io/crates/secrecy), tracing best-practices
- Confidence: HIGH — these pitfalls are direct mappings from the spec's threat model and from common failure modes in privacy/policy systems

---
*Pitfalls research for: Photophore v0.1*
*Researched: 2026-05-05*
