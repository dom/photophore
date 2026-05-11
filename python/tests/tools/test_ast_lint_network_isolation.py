"""Task 3 AST lint tests: DISP-05 network-isolation contract enforcement.

The lint rejects `import httpx|requests|aiohttp` (and `from httpx|... import x`)
in protected modules:
  - photophore.{classifier, shadow, policy, audit, channels, core}
  - thermocline.{envelope, canonical, identity, schemes, sensitive}

Allow-listed paths:
  - photophore/python/src/photophore/dispatch/
  - photophore/python/src/photophore/cli/dispatch_cmds.py
  - photophore/python/src/photophore/cli/channel_cmds.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


# Import the tool's check_file/scan/is_protected/is_allowed via importlib —
# the file is at photophore/tools/ast_lint_network_isolation.py, NOT in the python/
# package, so a direct `from photophore.tools import ...` will not work.

@pytest.fixture(scope="module")
def lint_module():
    import importlib.util
    tool_path = (
        Path(__file__).resolve().parents[3]
        / "tools" / "ast_lint_network_isolation.py"
    )
    assert tool_path.exists(), f"missing tool: {tool_path}"
    spec = importlib.util.spec_from_file_location("ast_lint_iso", tool_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_protected(tmp_path: Path, fragment: str, content: str) -> Path:
    """Build a fake source file under a protected path fragment."""
    p = tmp_path / fragment
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def test_lint_clean_passes(tmp_path: Path, lint_module) -> None:
    """Scanning a directory with no forbidden imports returns 0 violations."""
    src = tmp_path / "photophore" / "classifier"
    src.mkdir(parents=True)
    (src / "ok.py").write_text("def f():\n    return 1\n")
    assert lint_module.check_file(src / "ok.py") == []


def test_lint_rejects_httpx_in_classifier(tmp_path: Path, lint_module) -> None:
    p = _make_protected(tmp_path, "photophore/classifier/foo.py", "import httpx\n")
    violations = lint_module.check_file(p)
    assert len(violations) == 1
    assert "httpx" in violations[0]
    assert str(p) in violations[0]


def test_lint_rejects_requests_from_form(tmp_path: Path, lint_module) -> None:
    p = _make_protected(tmp_path, "photophore/shadow/bar.py", "from requests import get\n")
    violations = lint_module.check_file(p)
    assert len(violations) == 1
    assert "requests" in violations[0]


def test_lint_rejects_aiohttp_dotted_import(tmp_path: Path, lint_module) -> None:
    p = _make_protected(tmp_path, "photophore/policy/baz.py", "import aiohttp.client\n")
    violations = lint_module.check_file(p)
    assert len(violations) == 1
    assert "aiohttp" in violations[0]


def test_lint_allows_dispatch_module(tmp_path: Path, lint_module) -> None:
    """Allow-list: photophore/dispatch/* may import httpx."""
    p = _make_protected(tmp_path, "photophore/dispatch/_transport.py", "import httpx\n")
    assert lint_module.check_file(p) == []


def test_lint_allows_cli_carveouts(tmp_path: Path, lint_module) -> None:
    """Allow-list: dispatch_cmds.py and channel_cmds.py may import httpx."""
    p1 = _make_protected(tmp_path, "photophore/cli/dispatch_cmds.py", "import httpx\n")
    p2 = _make_protected(tmp_path, "photophore/cli/channel_cmds.py", "import httpx\n")
    assert lint_module.check_file(p1) == []
    assert lint_module.check_file(p2) == []


def test_lint_rejects_in_thermocline_envelope(tmp_path: Path, lint_module) -> None:
    p = _make_protected(tmp_path, "thermocline/envelope.py", "import httpx\n")
    violations = lint_module.check_file(p)
    assert len(violations) == 1


def test_lint_exit_code_clean(tmp_path: Path, lint_module) -> None:
    """scan() returns 0 on a clean tree."""
    src = tmp_path / "photophore" / "classifier"
    src.mkdir(parents=True)
    (src / "ok.py").write_text("def f():\n    return 1\n")
    assert lint_module.scan([tmp_path]) == 0


def test_lint_exit_code_violation(tmp_path: Path, lint_module) -> None:
    """scan() returns non-zero when a violation is found."""
    _make_protected(tmp_path, "photophore/classifier/bad.py", "import httpx\n")
    assert lint_module.scan([tmp_path]) != 0


def test_lint_cli_invocation_clean(tmp_path: Path) -> None:
    """Running the script as a CLI on a clean tree exits 0."""
    tool = (Path(__file__).resolve().parents[3] / "tools"
            / "ast_lint_network_isolation.py")
    src = tmp_path / "photophore" / "shadow"
    src.mkdir(parents=True)
    (src / "ok.py").write_text("def f():\n    return 1\n")
    result = subprocess.run(
        [sys.executable, str(tool), str(tmp_path)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"


def test_lint_cli_invocation_violation(tmp_path: Path) -> None:
    """Running the script as a CLI on a dirty tree exits non-zero."""
    tool = (Path(__file__).resolve().parents[3] / "tools"
            / "ast_lint_network_isolation.py")
    bad = tmp_path / "photophore" / "classifier" / "bad.py"
    bad.parent.mkdir(parents=True)
    bad.write_text("import httpx\n")
    result = subprocess.run(
        [sys.executable, str(tool), str(tmp_path)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "httpx" in result.stderr
