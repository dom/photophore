"""photophore CLI — single entry point with structured exit codes (D-13, D-14).

Root group: photophore
Sub-groups: channel | audit | classify (Plan 02-02) | policy (Plan 02-03)

Usage:
  photophore [--json] [--data-dir DIR] channel new|open|list|show|suspend|close|set-ceiling
  photophore [--json] [--data-dir DIR] audit query|export|verify

--json: Machine-readable output mode.
  - audit query/export: JSON Lines (one object per line, D-12)
  - all other commands: single JSON document (D-12)

--data-dir: Directory for audit.db and channels.db. Defaults to
  $XDG_DATA_HOME/photophore or ~/.local/share/photophore.
"""
from __future__ import annotations

import os
from pathlib import Path

import click

from ._errors import AuditIntegrityError, ClassifierError, ConfigError, KeystoreError
from .audit_cmds import audit
from .channel_cmds import channel
from .classify_cmds import classify_cmd as classify
from .dispatch_cmds import dispatch_command
from .policy_cmds import policy

__all__ = ["photophore"]

_DEFAULT_DATA_DIR = (
    Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "photophore"
)


@click.group()
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Machine-readable JSON output (D-12).",
)
@click.option(
    "--data-dir",
    "data_dir",
    default=str(_DEFAULT_DATA_DIR),
    envvar="PHOTOPHORE_DATA_DIR",
    show_default=True,
    help="Directory for audit.db and channels.db.",
)
@click.version_option(package_name="photophore")
@click.pass_context
def photophore(ctx: click.Context, output_json: bool, data_dir: str) -> None:
    """Photophore privacy policy engine.

    Manages channels, audit log, content classification, and policy authoring.
    """
    ctx.ensure_object(dict)
    data_path = Path(data_dir)
    ctx.obj["json"] = output_json
    ctx.obj["audit_db"] = str(data_path / "audit.db")
    ctx.obj["channels_db"] = str(data_path / "channels.db")
    ctx.obj["data_dir"] = str(data_path)


photophore.add_command(audit)
photophore.add_command(channel)
photophore.add_command(classify, name="classify")
photophore.add_command(policy)
photophore.add_command(dispatch_command, name="dispatch")
