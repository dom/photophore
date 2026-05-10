# photophore

**Photophore** is the privacy policy engine for the Thermocline Suite. It implements
the policy-engine role: zero-trust classification, dispatch-time shadow generation,
result-policy authoring, and an append-only cryptographically chained audit log.

**Version:** 0.3.1 (implements Photophore spec v0.3.0+)  
**License:** MIT  
**Depends on:** thermocline>=0.3.1

## Install

```bash
pip install -e ".[dev]"  # development install
```

Requires Python 3.11+ and thermocline>=0.3.1.

## Quickstart

```python
from pathlib import Path
from photophore.audit import AuditLog
from photophore.channels import ChannelStore

# Create a chained, append-only audit log
audit = AuditLog(Path("/tmp/audit.db"))

# Create a channel store backed by the platform keystore
store = ChannelStore(Path("/tmp/channels.db"), audit)
channel = store.create(
    remote_node="bob",
    ceiling="tier-1",
    key_scheme="brine",
    local_node="alice",
    creator_identity="alice",
)
print(channel.id, channel.state)  # <uuid> ChannelState.PROPOSED
```

## Architecture

Photophore ships three discrete stores (D-04):
- **Trust store**: platform keystore via `python-keyring` — channel records (authoritative)
- **Channel index**: `channels.db` — a derived projection for fast list/show queries
- **Audit log**: `audit.db` — append-only, cryptographically chained via BLAKE3

These three stores are NEVER co-located (AT-A5 structural defense).

## Links

- Spec: `../README.md` (Photophore v0.3.0-draft)
- Planning context: `../../thermocline/.planning/phases/02-photophore-privacy-primitives-foundations/02-CONTEXT.md`
- Thermocline suite: https://github.com/dom/thermocline
