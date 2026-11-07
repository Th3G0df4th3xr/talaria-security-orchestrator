"""Tamper-evident hash chaining for persisted audit events."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_details(details: dict[str, Any]) -> str:
    """Serialize event details deterministically before storing and hashing."""
    return json.dumps(details, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def audit_entry_hash(
    event_id: int,
    event: str,
    details: str,
    created_at: str,
    previous_hash: str,
) -> str:
    """Compute a SHA-256 digest over one event and its predecessor."""
    payload = json.dumps(
        {
            "created_at": created_at,
            "details": details,
            "event": event,
            "id": event_id,
            "previous_hash": previous_hash,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def backfill_audit_chain(connection: Any) -> None:
    """Chain existing events in ID order while preserving their stored values."""
    previous_hash = GENESIS_HASH
    rows = connection.execute(
        "SELECT id, event, details, created_at FROM audit_events ORDER BY id"
    ).fetchall()
    for row in rows:
        entry_hash = audit_entry_hash(
            row["id"], row["event"], row["details"], row["created_at"], previous_hash
        )
        connection.execute(
            "UPDATE audit_events SET previous_hash = ?, entry_hash = ? WHERE id = ?",
            (previous_hash, entry_hash, row["id"]),
        )
        previous_hash = entry_hash


def verify_audit_chain(connection: Any) -> bool:
    """Return false when a row, chain link, or event order has been altered."""
    try:
        rows: Iterable = connection.execute(
            """SELECT id, event, details, created_at, previous_hash, entry_hash
               FROM audit_events ORDER BY id"""
        ).fetchall()
        previous_hash = GENESIS_HASH
        for row in rows:
            if row["previous_hash"] != previous_hash:
                return False
            expected_hash = audit_entry_hash(
                row["id"], row["event"], row["details"], row["created_at"], previous_hash
            )
            if row["entry_hash"] != expected_hash:
                return False
            previous_hash = expected_hash
        return True
    except Exception:
        return False
