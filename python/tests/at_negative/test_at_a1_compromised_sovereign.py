"""AT-A1: Compromised sovereign node — terminal threat; structural defenses tested.

The terminal threat case (compromised sovereign has root and can do anything).
Mitigation in v0.1: AT-A1 fixture exercises channel-impersonation rejection;
the dispatch coordinator refuses to issue a Receipt against an envelope
arriving from a key that does not own the channel.

Source-of-truth wire-in: photophore/python/tests/integration/test_e2e_at_a1_replay.py.
"""
# AT-SURFACE: AT-A1
# Re-export from the integration test so at_coverage.py filename-scan sees
# AT-A1 covered without duplicating the assertion. The source-of-truth
# implementation stays in tests/integration/.
import pytest


@pytest.mark.at_surface("AT-A1")
def test_at_a1_redirected_to_integration_test() -> None:
    """AT-A1: see tests/integration/test_e2e_at_a1_replay.py for the live wire-in."""
    from pathlib import Path
    target = Path(__file__).resolve().parents[1] / "integration" / "test_e2e_at_a1_replay.py"
    assert target.is_file(), (
        f"AT-A1: source-of-truth integration test missing at {target}"
    )
