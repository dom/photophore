"""Structured exit codes for the photophore CLI (D-14).

Exit code contract:
  0  success
  1  generic (click default; used for ChannelStateError)
  2  config error (rules file missing/malformed, channel record corrupt)
  3  audit chain integrity failure (chain broken — privacy-critical incident)
  4  classifier error (Plan 02-02)
  5  keystore error (keystore unavailable, channel not found)

Phase 3 reserves exit code 6 for dispatch errors.

These ClickException subclasses are raised by CLI subcommands; click calls sys.exit()
with the exit_code after formatting the error message to stderr.
"""
from __future__ import annotations

import click

__all__ = [
    "ConfigError",
    "AuditIntegrityError",
    "ClassifierError",
    "KeystoreError",
]


class ConfigError(click.ClickException):
    """Exit code 2 — config error (rules file missing/malformed)."""
    exit_code = 2


class AuditIntegrityError(click.ClickException):
    """Exit code 3 — audit chain integrity failure.

    Privacy-critical incident: the chain was tampered or corrupted.
    Callers must print the diagnostic JSON to stdout BEFORE raising this,
    so that CI pipelines see both the exit code AND the diagnostic.
    """
    exit_code = 3


class ClassifierError(click.ClickException):
    """Exit code 4 — classifier error (content unreadable, encoding failure, etc.)."""

    exit_code = 4


class KeystoreError(click.ClickException):
    """Exit code 5 — keystore unavailable or channel not found."""

    exit_code = 5
