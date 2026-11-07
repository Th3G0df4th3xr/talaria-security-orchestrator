"""Copy a verified current-version SQLite database into PostgreSQL."""

import re
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from talaria.database import CURRENT_SCHEMA_VERSION, Database
from talaria.database_backup import DatabaseBackupError, copy_database

_TRANSFER_TABLES = (
    "organizations",
    "users",
    "repositories",
    "github_repositories",
    "github_check_runs",
    "scans",
    "findings",
    "finding_occurrences",
    "refresh_sessions",
    "organization_memberships",
    "webhook_deliveries",
    "approval_records",
    "github_events",
    "audit_events",
    "investigations",
)
_IDENTITY_TABLES = (
    "repositories",
    "scans",
    "findings",
    "finding_occurrences",
    "audit_events",
)
_TRANSFER_BATCH_SIZE = 500


class DatabaseTransferError(RuntimeError):
    """Raised when an SQLite-to-PostgreSQL copy cannot be completed safely."""


def transfer_sqlite_to_postgres(source: Path, target: Database) -> dict:
    """Copy data atomically; read-only source and non-empty target are rejected."""
    source = Path(source).expanduser().resolve()
    if not source.is_file():
        raise DatabaseTransferError("Source SQLite database does not exist")
    if not target.is_postgres:
        raise DatabaseTransferError("Target database must be PostgreSQL")
    healthy, version = Database.readiness(target.path)
    if not healthy or version != CURRENT_SCHEMA_VERSION:
        raise DatabaseTransferError("Target PostgreSQL schema is not initialized and ready")

    try:
        with tempfile.TemporaryDirectory(prefix="talaria-import-") as snapshot_directory:
            snapshot = Path(snapshot_directory) / "source.db"
            copy_database(source, snapshot)
            return _transfer_snapshot_to_postgres(snapshot, target)
    except DatabaseTransferError:
        raise
    except (DatabaseBackupError, OSError, sqlite3.Error) as exc:
        raise DatabaseTransferError(
            "Cannot create a verified SQLite import snapshot"
        ) from exc


def _transfer_snapshot_to_postgres(source: Path, target: Database) -> dict:
    """Transfer an immutable private snapshot in one PostgreSQL transaction."""
    uri = f"{source.as_uri()}?mode=ro"
    try:
        source_connection = sqlite3.connect(uri, uri=True, timeout=10.0)
        source_connection.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        raise DatabaseTransferError("Cannot open source SQLite snapshot read-only") from exc

    counts = {}
    try:
        with closing(source_connection):
            # Pin one read snapshot before validation so every copied table is
            # the same state whose schema, integrity, and audit chain were checked.
            source_connection.execute("BEGIN")
            healthy, version = Database.readiness_connection(source_connection)
            if not healthy or version != CURRENT_SCHEMA_VERSION:
                raise DatabaseTransferError(
                    "Source must pass current schema integrity checks"
                )
            with target.transaction() as connection:
                for table in _TRANSFER_TABLES:
                    # Table identifiers come only from this fixed allowlist.
                    existing = connection.execute(
                        f"SELECT COUNT(*) AS count FROM {table}"  # noqa: S608
                    ).fetchone()["count"]
                    if existing:
                        raise DatabaseTransferError(
                            "Target application tables must be empty before transfer"
                        )

                for table in _TRANSFER_TABLES:
                    # The read table name is selected from _TRANSFER_TABLES.
                    cursor = source_connection.execute(
                        f"SELECT * FROM {table}"  # noqa: S608
                    )
                    columns = [
                        item[1]
                        for item in source_connection.execute(
                            f"PRAGMA table_info({table})"
                        )
                    ]
                    invalid_column = any(
                        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) is None
                        for item in columns
                    )
                    if invalid_column:
                        raise DatabaseTransferError(
                            f"Unexpected source column name in {table}"
                        )
                    target_columns = {
                        item["column_name"]
                        for item in connection.execute(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema = 'public' AND table_name = ?",
                            (table,),
                        ).fetchall()
                    }
                    if set(columns) != target_columns:
                        raise DatabaseTransferError(
                            f"Source and target schemas differ for {table}"
                        )
                    fields = ", ".join(f'"{item}"' for item in columns)
                    placeholders = ", ".join("?" for _ in columns)
                    counts[table] = 0
                    while rows := cursor.fetchmany(_TRANSFER_BATCH_SIZE):
                        # Table is allowlisted; columns are validated against target schema.
                        connection.executemany(
                            f"INSERT INTO {table} ({fields}) VALUES ({placeholders})",  # noqa: S608
                            [tuple(row[column] for column in columns) for row in rows],
                        )
                        counts[table] += len(rows)

                for table in _IDENTITY_TABLES:
                    # Identity table names are a fixed subset of _TRANSFER_TABLES.
                    connection.execute(  # noqa: S608
                        "SELECT setval(pg_get_serial_sequence(?, 'id'), "  # noqa: S608
                        f"COALESCE((SELECT MAX(id) FROM {table}), 1), "  # noqa: S608
                        f"EXISTS (SELECT 1 FROM {table}))",
                        (table,),
                    )  # noqa: S608

                for table, expected in counts.items():
                    actual = connection.execute(
                        f"SELECT COUNT(*) AS count FROM {table}"  # noqa: S608
                    ).fetchone()["count"]
                    if actual != expected:
                        raise DatabaseTransferError(
                            f"Transferred row count verification failed for {table}"
                        )
                target.audit_in_transaction(
                    connection,
                    "database.sqlite_imported",
                    {"schema_version": CURRENT_SCHEMA_VERSION, "source_type": "sqlite"},
                )
    except DatabaseTransferError:
        raise
    except Exception as exc:
        raise DatabaseTransferError(
            f"SQLite-to-PostgreSQL transfer failed ({type(exc).__name__})"
        ) from exc

    return {
        "source": str(source),
        "schema_version": CURRENT_SCHEMA_VERSION,
        "rows_by_table": counts,
        "target_audit_event": "database.sqlite_imported",
    }
