"""AuditLog: the append-only, cryptographically chained audit store.

This is the primary entry point for the photophore.audit module.

Key design decisions:
- D-01: single denormalized 'entries' table + indexed metadata columns
- D-02: _query_rows() → raw dicts (streaming/export path); query() → typed AuditEntry list
- D-03: entry_hash = blake3(canonicalize(entry minus entry_hash))
- AUDIT-01: append-only via SQLite triggers (raises sqlite3.IntegrityError on DELETE/UPDATE)
- AUDIT-02: algo_version="blake3-v1" on every entry; verifier dispatches via _HASH_ALGO_REGISTRY
- AUDIT-03: prev_hash = previous entry's entry_hash; chain head prev_hash = ""
- AUDIT-05: filtered queries via indexed columns + JSON1 expressions for shadow_id/tier
- AUDIT-06: export() yields raw dicts (JSON Lines per line)
- AUDIT-07: AnchorTarget Protocol side-effect after each append
- AUDIT-08: verify_entry_hash() on every row in query(); verify_chain() walks full chain
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..core import KNOWN_EVENT_TYPES
from ..errors import AuditChainBrokenError, AuditWriteError
from ._anchor import AnchorTarget, HeadAnchor, NullAnchor
from ._chain import ALGO_VERSION_DEFAULT, compute_entry_hash, verify_entry_hash
from ._schema import connect, init
from ._types import AuditEntry, from_dict

__all__ = ["AuditLog"]


def _assert_no_sensitive(payload: dict[str, Any], path: str = "") -> None:
    """Recursively walk an audit payload; raise AuditWriteError on any Sensitive[T] value.

    CONF-06 / D-09 runtime guard: audit log is a permanent, append-only
    record. Privacy-sensitive bytes MUST NEVER be persisted into the audit
    payload — if a Sensitive[T] wrapper is found anywhere in the dict tree,
    raise AuditWriteError(code=AUDIT_SENSITIVE_LEAK) instead of writing.

    This is paired with the SensitiveFilter in photophore.logging (catches
    Sensitive values in log records) and the ast_lint_no_print.py (catches
    `print(` calls in library code) for defense-in-depth (see threat model
    T-04-03 in 04-01-PLAN.md).
    """
    # Import lazily to avoid a hard dependency loop between audit and
    # thermocline.sensitive at module-load time. thermocline-py is in our
    # dependencies; the import only fires at audit-write time.
    from thermocline.sensitive import Sensitive

    for k, v in payload.items():
        leaf_path = f"{path}.{k}" if path else str(k)
        if isinstance(v, Sensitive):
            raise AuditWriteError(
                f"Sensitive[T] value in audit payload field {leaf_path!r}; "
                f"audit log must not store privacy-sensitive content",
                code="AUDIT_SENSITIVE_LEAK",
            )
        if isinstance(v, dict):
            _assert_no_sensitive(v, leaf_path)
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, Sensitive):
                    raise AuditWriteError(
                        f"Sensitive[T] value in audit payload at {leaf_path}[{i}]; "
                        f"audit log must not store privacy-sensitive content",
                        code="AUDIT_SENSITIVE_LEAK",
                    )
                if isinstance(item, dict):
                    _assert_no_sensitive(item, f"{leaf_path}[{i}]")


class AuditLog:
    """Append-only, cryptographically chained audit log backed by SQLite.

    The log lives at a single file path (audit.db). Do NOT use the same file
    as channels.db or any other database — D-04 three-store model.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        anchor: AnchorTarget | None = None,
        head_anchor: HeadAnchor | None = None,
    ) -> None:
        self._path = str(path)
        self._conn = connect(self._path)
        init(self._conn)
        # Serializes the read-prev-hash -> INSERT -> head-anchor sequence in
        # append(). sqlite releases the GIL during C-level calls, so without
        # this two threads can read the same head hash and both commit,
        # forking the chain (two entries sharing one prev_hash).
        self._append_lock = threading.Lock()
        self._anchor: AnchorTarget = anchor if anchor is not None else NullAnchor()
        # Out-of-band head record for tail-truncation detection (see
        # _anchor.HeadAnchor). None = bare Ring-1 chain: tail truncation is
        # then NOT detectable; that residual is documented on the Protocol
        # and pinned by tests/at_negative/test_at_a6_audit_log_tamper.py.
        self._head_anchor: HeadAnchor | None = head_anchor

    @property
    def path(self) -> str:
        """Absolute path to the audit.db file."""
        return self._path

    def _last_entry_hash(self) -> str:
        """Return the entry_hash of the most recent entry, or '' for an empty log."""
        cur = self._conn.execute(
            "SELECT entry_hash FROM entries ORDER BY rowid DESC LIMIT 1"
        )
        row = cur.fetchone()
        return str(row[0]) if row else ""  # "" = chain head sentinel (AUDIT-03)

    def append(
        self,
        *,
        event_type: str,
        channel_id: str | None = None,
        envelope_id: str | None = None,
        payload: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> AuditEntry:
        """Append a new entry to the chain. Returns the committed AuditEntry.

        AUDIT-03: prev_hash = previous entry's entry_hash (or "" for chain head).
        AUDIT-02: algo_version="blake3-v1" on every entry.
        AUDIT-07: self._anchor.anchor(entry) called after every successful append.

        Raises AuditWriteError on:
        - unknown event_type (programmer error, not a runtime config error)
        - sqlite3.IntegrityError from append-only triggers (AUDIT-01 violation)
        """
        if event_type not in KNOWN_EVENT_TYPES:
            raise AuditWriteError(
                f"unknown event_type {event_type!r}; "
                f"add it to KNOWN_EVENT_TYPES in photophore.core",
                code="AUDIT_WRITE_FAILED",
            )
        # CONF-06 / D-09 runtime guard: audit payload MUST NOT carry
        # Sensitive[T] values. Reject the write at the boundary; the caller
        # is responsible for stripping or hashing sensitive fields before
        # passing them to append().
        if payload:
            _assert_no_sensitive(payload)
        ts = timestamp or (
            datetime.now(tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        # MED 7: the SELECT-then-INSERT below is a read-then-write race.
        # sqlite releases the GIL inside C calls, so without serialization two
        # threads can read the same head hash and both commit, forking the
        # chain. The lock also keeps the head-anchor update ordered with its
        # entry so concurrent appends cannot leave the anchor pointing at a
        # non-head entry.
        with self._append_lock:
            prev_hash = self._last_entry_hash()
            entry_id = str(uuid.uuid4())
            # Build the entry dict EXCLUDING entry_hash (D-03 domain rule).
            entry_minus_hash: dict[str, Any] = {
                "id": entry_id,
                "algo_version": ALGO_VERSION_DEFAULT,
                "prev_hash": prev_hash,
                "event_type": event_type,
                "channel_id": channel_id,
                "envelope_id": envelope_id,
                "timestamp": ts,
                "payload": payload or {},
            }
            entry_hash = compute_entry_hash(entry_minus_hash)
            entry = AuditEntry(entry_hash=entry_hash, **entry_minus_hash)
            try:
                self._conn.execute(
                    "INSERT INTO entries "
                    "(id, algo_version, prev_hash, entry_hash, "
                    "event_type, channel_id, envelope_id, timestamp, payload) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    entry.to_row(),
                )
            except sqlite3.IntegrityError as exc:
                raise AuditWriteError(
                    f"audit log rejected write (append-only violation or constraint): {exc}",
                    code="AUDIT_WRITE_FAILED",
                ) from exc
            # Head anchor: persist the new head hash + entry count out-of-band so
            # verify_chain() can detect tail truncation. Failure to update the
            # anchor is surfaced (fail closed): the entry IS committed (append-only,
            # no rollback), but the caller must know the anchor is now stale;
            # verify_chain() will report the mismatch until the anchor catches up.
            if self._head_anchor is not None:
                count = int(
                    self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
                )
                try:
                    self._head_anchor.set(entry.entry_hash, count)
                except Exception as exc:  # noqa: BLE001 any backend failure
                    raise AuditWriteError(
                        f"audit entry committed but head anchor update failed: {exc}",
                        code="AUDIT_HEAD_ANCHOR_FAILED",
                    ) from exc
        # AUDIT-07: anchor side-effect (NullAnchor.anchor returns None — no-op default).
        self._anchor.anchor(entry)
        return entry

    def _query_rows(
        self,
        *,
        channel_id: str | None = None,
        envelope_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        event_type: str | None = None,
        shadow_id: str | None = None,
        tier: str | None = None,
        receipt_status: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Streaming raw-dict iterator over entries (D-02 export path).

        All JSON1-based filters (shadow_id, tier, receipt_status) are verified
        against SQLite 3.53.0. JSON1 is available on macOS stdlib SQLite
        (3.38+) and standard Linux builds.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if channel_id is not None:
            clauses.append("channel_id = ?")
            params.append(channel_id)
        if envelope_id is not None:
            clauses.append("envelope_id = ?")
            params.append(envelope_id)
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(until)
        if shadow_id is not None:
            # JSON1: shadow_ids is a JSON array in payload
            clauses.append(
                "EXISTS ("
                "  SELECT 1 FROM json_each(json_extract(payload, '$.shadow_ids'))"
                "  WHERE value = ?"
                ")"
            )
            params.append(shadow_id)
        if tier is not None:
            # JSON1: tiers is a JSON array in payload
            clauses.append(
                "EXISTS ("
                "  SELECT 1 FROM json_each(json_extract(payload, '$.tiers'))"
                "  WHERE value = ?"
                ")"
            )
            params.append(tier)
        if receipt_status is not None:
            clauses.append("json_extract(payload, '$.receipt_status') = ?")
            params.append(receipt_status)

        sql = (
            "SELECT id, algo_version, prev_hash, entry_hash, event_type, "
            "channel_id, envelope_id, timestamp, payload "
            "FROM entries"
        )
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp ASC, id ASC"

        for row in self._conn.execute(sql, params):
            yield {
                "id": row[0],
                "algo_version": row[1],
                "prev_hash": row[2],
                "entry_hash": row[3],
                "event_type": row[4],
                "channel_id": row[5],
                "envelope_id": row[6],
                "timestamp": row[7],
                "payload": json.loads(row[8]),
            }

    def query(self, **filters: Any) -> list[AuditEntry]:
        """Return a typed list of AuditEntry matching the given filters.

        AUDIT-08: verifies every returned entry's hash on read. Raises
        AuditChainBrokenError on any hash mismatch.
        """
        rows = list(self._query_rows(**filters))
        for row in rows:
            if not verify_entry_hash(row):
                raise AuditChainBrokenError(
                    f"audit chain integrity check failed at entry {row['id']!r}",
                    code="AUDIT_CHAIN_BROKEN",
                )
        return [from_dict(r) for r in rows]

    def verify_chain(self) -> tuple[bool, str | None]:
        """Walk the entire chain and verify hash integrity end-to-end.

        Returns:
            (True, head_hash)   — all entries are intact; head_hash is the
                                  entry_hash of the most recent entry (or "").
            (False, broken_at)  — chain broken; broken_at is the id of the
                                  first invalid entry.

        Checks all of:
        - per-entry hash: verify_entry_hash(row) recomputes blake3(canonicalize(row minus hash))
        - prev_hash chain: each entry's prev_hash must equal the prior entry's entry_hash
        - head anchor (when configured): the walked head hash + entry count
          must match the out-of-band record updated on every append. This is
          what makes TAIL truncation detectable; without a head anchor a
          truncated chain still verifies (Ring-1 residual, see
          _anchor.HeadAnchor).
        """
        prev = ""
        last_hash = ""
        walked = 0
        for row in self._query_rows():
            if row["prev_hash"] != prev:
                return False, str(row["id"])
            if not verify_entry_hash(row):
                return False, str(row["id"])
            prev = str(row["entry_hash"])
            last_hash = str(row["entry_hash"])
            walked += 1
        if self._head_anchor is not None:
            expected = self._head_anchor.get()
            if expected is not None:
                expected_head, expected_count = expected
                if expected_head != last_hash or expected_count != walked:
                    return False, (
                        f"head-anchor mismatch: expected head {expected_head!r} "
                        f"over {expected_count} entries, walked {last_hash!r} "
                        f"over {walked} (possible tail truncation)"
                    )
        return True, last_hash if last_hash else None

    def export(self) -> Iterator[dict[str, Any]]:
        """JSON Lines export (AUDIT-06): yields one raw dict per entry.

        Each dict includes the algo_version field per AUDIT-06 contract.
        CLI pipes this through emit_json_lines() for the --json mode.
        """
        yield from self._query_rows()
