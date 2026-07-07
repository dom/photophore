# Photophore Operations

## Audit log

- `photophore audit query --channel <id>`: list entries for a channel
  (CLI-02 / AUDIT-05). Add `--json` for machine-readable output.
- `photophore audit export > audit.jsonl`: export the full audit log as JSONL
  (AUDIT-06). Each line is one audit entry; the chain order matches `rowid`.
- `photophore audit verify`: verify chain integrity end-to-end. Walks every
  entry, recomputes the BLAKE3 chain link, and compares against the stored
  `prev_hash`. Exits 0 on success; non-zero with the first divergence reported.

## Channels

- `photophore channel new --remote-node <id> --ceiling tier-1 --key-scheme brine`:
  propose a new channel. Use `--fetch-pubkey-from <url>` for TOFU public-key
  acquisition from a running forge.
- `photophore channel list`: show all channels and their states.
- `photophore channel show <id>`: show single-channel detail (state, ceiling,
  key_scheme, created_ts, last_dispatch_ts).
- `photophore channel suspend <id> --reason "..."`: suspend a channel
  (reversible; new dispatches blocked until resumed).
- `photophore channel close <id> --reason "..."`: close a channel (terminal;
  cannot be re-opened).
- `photophore channel set-ceiling <id> --ceiling tier-0`: lower the trust
  ceiling. Ceilings can only be **lowered** unilaterally (CHAN-03 ceiling
  monotonicity); raising requires a deliberate human act recorded as a
  distinct audit event.
- `photophore channel register-pubkey <id> --fetch-pubkey-from <url>`: fetch
  and store the remote node's public key (TOFU).

## Known limitations (v0.1)

- **Chain archival (`audit archive`)** is deferred to v0.2. v0.1 ships query,
  export, and verify only. Operationally, audit logs grow append-only; periodic
  export + offsite-backup is the recommended workflow until archival ships.
- **Channel ceiling raising** requires a deliberate human action (CHAN-03);
  the audit entry records this as a distinct event type.
- **Daemon mode** is not in v0.1; every CLI invocation is independent.
