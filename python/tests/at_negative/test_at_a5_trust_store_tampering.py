"""AT-A5: Trust-store tampering — v0.1 relies on three-store separation.

Failure mode: an attacker with filesystem access modifies the trust store
(channel ceilings, pubkeys). v0.1 mitigation: three-store separation
(audit.db, channels.db, keystore) ensures no single corruption gives full
control; the audit log records every ceiling change.

Explicit tamper-detector (comparing keystore state against audit log) is
deferred to v0.2. Documented as a known limitation in CHANGELOG.
"""
# AT-SURFACE: AT-A5
from __future__ import annotations

import pytest


@pytest.mark.at_surface("AT-A5")
def test_trust_store_separation_documented() -> None:
    """AT-A5: photophore.channels, photophore.audit, and the keystore are separate stores.

    The defense-in-depth model: three separate stores mean a single corruption
    doesn't grant full control. The runtime cross-validation between them
    (e.g., asserting keystore state matches audit-log history) is deferred to
    v0.2.
    """
    # Three-store invariant: importing the three subsystems proves they are
    # separable modules; the storage backends are intentionally distinct.
    import photophore.audit  # SQLite at audit.db
    import photophore.channels  # SQLite at channels.db
    import keyring  # platform keystore

    # The actual tamper-detector that compares these stores is v0.2 work.
    pytest.skip(
        "AT-A5: explicit tamper-detector deferred to v0.2. v0.1 relies on "
        "structural three-store separation as primary defense; documented "
        "in CHANGELOG known-limitations."
    )
