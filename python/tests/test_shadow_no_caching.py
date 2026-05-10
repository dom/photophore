"""Structural + behavioral tests for SHADOW-06 (no shadow caching).

SHADOW-06: shadows must NEVER be cached, persisted, or referenced after dispatch.

Two defenses:
  1. STRUCTURAL: grep gate — assert zero occurrences of caching primitives in
     photophore/python/src/photophore/shadow/. This catches any future PR that adds
     @lru_cache, @functools.cache, or a _shadow_cache dict.
  2. BEHAVIORAL: 100 identical-input calls produce 100 distinct shadow_ids.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from photophore.shadow import ContentType, generate

_SHADOW_SRC = (
    Path(__file__).resolve().parents[1] / "src" / "photophore" / "shadow"
)


class TestNoCachingGrepGate:
    def test_no_lru_cache_or_functools_cache(self) -> None:
        """Grep gate: zero occurrences of caching DECORATORS applied to functions in shadow source.

        Pattern targets actual decorator/assignment usage, not comment or docstring mentions
        of caching concepts (which are present in the module docstrings for documentation).
        """
        result = subprocess.run(
            [
                "grep",
                "-rn",
                "--include=*.py",
                "-E",
                # Match actual decorator application or cache-dict assignment, not prose
                r"^\s*@lru_cache|^\s*@functools\.cache|^\s*@cache\b|^\s*_shadow_cache\s*=",
                str(_SHADOW_SRC),
            ],
            capture_output=True,
            text=True,
        )
        # grep returns exit code 1 when no matches found — that's the expected outcome.
        matches = result.stdout.strip()
        assert matches == "", (
            f"Found caching decorator/assignment in photophore.shadow (SHADOW-06 violation):\n{matches}"
        )

    def test_no_async_def_in_shadow(self) -> None:
        """D-11 gate: zero async def in photophore.shadow (sync-only Phase 2 APIs)."""
        result = subprocess.run(
            [
                "grep",
                "-rn",
                "--include=*.py",
                "-E",
                r"async def",
                str(_SHADOW_SRC),
            ],
            capture_output=True,
            text=True,
        )
        matches = result.stdout.strip()
        assert matches == "", (
            f"Found async def in photophore.shadow (D-11 violation):\n{matches}"
        )

    def test_no_aiosqlite_import_in_shadow(self) -> None:
        """D-11 gate: zero aiosqlite imports in photophore.shadow."""
        result = subprocess.run(
            [
                "grep",
                "-rn",
                "--include=*.py",
                "-E",
                r"import aiosqlite",
                str(_SHADOW_SRC),
            ],
            capture_output=True,
            text=True,
        )
        matches = result.stdout.strip()
        assert matches == "", (
            f"Found aiosqlite import in photophore.shadow (D-11 violation):\n{matches}"
        )

    def test_no_http_imports_in_shadow(self) -> None:
        """Network-isolation contract: zero HTTP client imports in photophore.shadow."""
        result = subprocess.run(
            [
                "grep",
                "-rn",
                "--include=*.py",
                "-E",
                r"import requests|import httpx|import aiohttp|from httpx",
                str(_SHADOW_SRC),
            ],
            capture_output=True,
            text=True,
        )
        matches = result.stdout.strip()
        assert matches == "", (
            f"Found HTTP imports in photophore.shadow (network-isolation violation):\n{matches}"
        )


class TestNoCachingBehavioral:
    def test_100_identical_calls_produce_100_distinct_ids(self) -> None:
        """Behavioral confirmation: 100 identical-input calls produce 100 distinct shadow_ids."""
        content = b"identical content for caching test"
        content_type = ContentType.DOCUMENT

        ids = [
            generate(content, content_type, relevance=0.5).shadow.shadow_id
            for _ in range(100)
        ]

        assert len(set(ids)) == 100, (
            f"Only {len(set(ids))} distinct shadow_ids from 100 identical-input calls. "
            f"Caching may be present (SHADOW-06 violation)."
        )
