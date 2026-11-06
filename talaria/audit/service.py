"""Audit service facade over the existing database audit method."""
from __future__ import annotations

from typing import Any

from talaria.database import Database


class AuditService:
    def __init__(self, database: Database):
        self.database = database

    def record(self, event: str, details: dict[str, Any]) -> None:
        self.database.audit(event, details)

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        return self.database.execute(
            """
            SELECT id, event, details, created_at
            FROM audit_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
