#!/usr/bin/env python3
"""AST lint enforcing the DISP-05 network-isolation contract.

Forbids `import httpx | requests | aiohttp` and
`from httpx|requests|aiohttp import ...` in protected modules:
  - photophore.{classifier, shadow, policy, audit, channels, core}
  - thermocline.{envelope, canonical, identity, schemes, sensitive}

Allow-listed paths (override protected):
  - photophore/python/src/photophore/dispatch/   (the ONLY module that imports httpx)
  - photophore/python/src/photophore/cli/dispatch_cmds.py
  - photophore/python/src/photophore/cli/channel_cmds.py
    (single --fetch-pubkey-from carve-out)
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

FORBIDDEN: frozenset[str] = frozenset({"httpx", "requests", "aiohttp"})

# Protected module path fragments (POSIX-style; we normalize separators).
PROTECTED_FRAGMENTS: tuple[str, ...] = (
    "photophore/classifier",
    "photophore/shadow",
    "photophore/policy",
    "photophore/audit",
    "photophore/channels",
    "photophore/core.py",
    "thermocline/envelope.py",
    "thermocline/canonical.py",
    "thermocline/identity.py",
    "thermocline/schemes.py",
    "thermocline/sensitive.py",
)

# Allow-list fragments — checked FIRST; override PROTECTED_FRAGMENTS.
ALLOWED_FRAGMENTS: tuple[str, ...] = (
    "photophore/dispatch/",
    "photophore/cli/dispatch_cmds.py",
    "photophore/cli/channel_cmds.py",
)


def is_allowed(path: Path) -> bool:
    posix = path.as_posix()
    return any(frag in posix for frag in ALLOWED_FRAGMENTS)


def is_protected(path: Path) -> bool:
    posix = path.as_posix()
    return any(frag in posix for frag in PROTECTED_FRAGMENTS)


def check_file(path: Path) -> list[str]:
    """Return violation messages for one file (empty list if clean)."""
    if is_allowed(path):
        return []
    if not is_protected(path):
        return []
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [f"{path}:{exc.lineno}: parse error {exc.msg!r}"]
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in FORBIDDEN:
                    violations.append(
                        f"{path}:{node.lineno}: forbidden import {alias.name!r}"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                if top in FORBIDDEN:
                    violations.append(
                        f"{path}:{node.lineno}: forbidden import from {node.module!r}"
                    )
    return violations


def scan(roots: list[Path]) -> int:
    all_violations: list[str] = []
    for root in roots:
        if root.is_file() and root.suffix == ".py":
            all_violations.extend(check_file(root))
        elif root.is_dir():
            for py in root.rglob("*.py"):
                all_violations.extend(check_file(py))
    for v in all_violations:
        print(v, file=sys.stderr)
    if all_violations:
        print(
            f"FAILED: {len(all_violations)} network-isolation violations",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    roots = [Path(p) for p in sys.argv[1:]] or [Path.cwd()]
    sys.exit(scan(roots))
