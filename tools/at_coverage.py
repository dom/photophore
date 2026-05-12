#!/usr/bin/env python3
"""AT-A* coverage gate for photophore (AT-A1..A6).

Globs photophore/python/tests/at_negative/test_at_a*.py and asserts
all six AT-A surfaces have at least one test file.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

EXPECTED: frozenset[str] = frozenset({"AT-A1", "AT-A2", "AT-A3", "AT-A4", "AT-A5", "AT-A6"})
PATTERN = re.compile(r"^test_at_a(\d+)_")
ROOT = Path(__file__).resolve().parents[1] / "python" / "tests" / "at_negative"


def main() -> int:
    if not ROOT.is_dir():
        print(f"FAIL: {ROOT} does not exist", file=sys.stderr)
        return 1
    found: set[str] = set()
    for p in sorted(ROOT.glob("test_at_*.py")):
        m = PATTERN.match(p.name.lower())
        if m:
            found.add(f"AT-A{m.group(1)}")
    missing = EXPECTED - found
    if missing:
        print(f"FAIL: missing AT-A coverage: {sorted(missing)}", file=sys.stderr)
        return 1
    print(f"ok: AT-A coverage complete ({len(found)}/6).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
