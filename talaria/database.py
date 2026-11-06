import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from talaria.migrations import migrate_to_v2


class Database:
    """SQLite database manager for TALARIA."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        """Create a database connection with required safety settings."""
        connection = sqlite3.connect(
            self.path,
            timeout=10.0,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Provide an atomic transaction and always close its connection."""
        connection = self.connect()

        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        """Initialize legacy tables and apply the current schema migration."""
        with closing(self.connect()) as db:
            with db:
                db.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS repositories (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        path TEXT NOT NULL UNIQUE,
                        registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        repository_id INTEGER NOT NULL
                            REFERENCES repositories(id),
                        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        completed_at TEXT,
                        finding_count INTEGER NOT NULL DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fingerprint TEXT NOT NULL UNIQUE,
                        repository_id INTEGER NOT NULL
                            REFERENCES repositories(id),
                        scan_id INTEGER NOT NULL
                            REFERENCES scans(id),
                        payload TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event TEXT NOT NULL,
                        details TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )

        migrate_to_v2(self.path)

    def insert(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> int:
        """Execute an INSERT and return its generated ID."""
        with self.transaction() as db:
            cursor = db.execute(sql, params)
            return cursor.lastrowid

    def execute(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        """Execute SQL and return rows when the statement produces results."""
        with closing(self.connect()) as db:
            with db:
                cursor = db.execute(sql, params)

                if cursor.description:
                    return [dict(row) for row in cursor.fetchall()]

                return []

    def audit(
        self,
        event: str,
        details: dict[str, Any],
    ) -> None:
        """Persist a structured audit event."""
        self.insert(
            "INSERT INTO audit_events(event, details) VALUES (?, ?)",
            (event, json.dumps(details, sort_keys=True)),
        )
