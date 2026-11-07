import hashlib
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from talaria.audit.chain import (
    GENESIS_HASH,
    audit_entry_hash,
    backfill_audit_chain,
    canonical_details,
    verify_audit_chain,
)
from talaria.migrations import (
    SQLITE_MIGRATIONS,
    verify_migration_history,
)
from talaria.postgres_schema import (
    POSTGRES_MIGRATIONS,
    POSTGRES_REQUIRED_TABLES,
    POSTGRES_SCHEMA,
)
from talaria.security.secrets import SecretFileError, read_secret_file

CURRENT_SCHEMA_VERSION = 17


class _PostgresConnection:
    """Small DB-API adapter for existing qmark SQL and dict-style rows."""

    def __init__(self, connection):
        self.connection = connection

    @property
    def in_transaction(self) -> bool:
        return self.connection.info.transaction_status != 0

    def execute(self, sql: str, params=()):
        return self.connection.execute(sql.replace("?", "%s"), params)

    def executemany(self, sql: str, params):
        cursor = self.connection.cursor()
        cursor.executemany(sql.replace("?", "%s"), params)
        return cursor

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()


def _is_postgres_url(value: Path | str) -> bool:
    return isinstance(value, str) and value.startswith(("postgresql://", "postgres://"))


def _postgres_schema_checksum() -> str:
    return hashlib.sha256(POSTGRES_SCHEMA.encode("utf-8")).hexdigest()


def _postgres_migration_checksums() -> dict[int, str]:
    return {
        version: hashlib.sha256(statement.encode("utf-8")).hexdigest()
        for version, statement in POSTGRES_MIGRATIONS.items()
    }


def postgres_connection_parameters(database_url: str) -> dict[str, str]:
    """Parse a PostgreSQL URL and require TLS or an explicitly trusted host."""
    if not _is_postgres_url(database_url):
        raise ValueError("A PostgreSQL database URL is required")
    try:
        from psycopg import Error as PsycopgError
        from psycopg.conninfo import conninfo_to_dict

        parameters = conninfo_to_dict(database_url)
    except (PsycopgError, ValueError):
        raise ValueError("Invalid PostgreSQL database URL") from None

    sslmode = parameters.get("sslmode", os.getenv("PGSSLMODE", "prefer"))
    if sslmode in {"require", "verify-ca", "verify-full"}:
        return parameters

    trusted_hosts = {
        host.strip().casefold()
        for host in os.getenv("TALARIA_DATABASE_TRUSTED_HOSTS", "").split(",")
        if host.strip()
    }
    configured_host = parameters.get("host", "")
    hosts = [host.strip().casefold() for host in configured_host.split(",")]
    has_routing_override = any(
        parameters.get(option)
        for option in ("hostaddr", "service", "servicefile")
    ) or any(
        os.getenv(variable)
        for variable in ("PGHOST", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE")
    )
    if (
        sslmode == "disable"
        and hosts
        and all(hosts)
        and set(hosts) <= trusted_hosts
        and not has_routing_override
    ):
        return parameters
    raise ValueError(
        "PostgreSQL connections require sslmode=require, verify-ca, or verify-full; "
        "plaintext is allowed only for an explicitly trusted host"
    )


class Database:
    """SQLite or PostgreSQL database manager for TALARIA."""

    def __init__(self, path: Path | str, *, initialize: bool = True):
        self.path = str(path) if _is_postgres_url(path) else Path(path)
        self.is_postgres = _is_postgres_url(path)
        self._create_if_missing = initialize
        if initialize:
            if self.is_postgres:
                self.initialize()
                return
            existed = self.path.exists()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not existed:
                try:
                    descriptor = os.open(
                        self.path,
                        os.O_CREAT | os.O_EXCL | os.O_RDWR,
                        0o600,
                    )
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
            self.initialize()
            if not existed:
                self.path.chmod(0o600)

    def connect(self):
        """Create a database connection with required safety settings."""
        if self.is_postgres:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL support requires the psycopg package"
                ) from exc
            try:
                parameters = postgres_connection_parameters(self.path)
            except ValueError as exc:
                raise RuntimeError("PostgreSQL transport configuration is invalid") from exc
            password_file = os.getenv("TALARIA_POSTGRES_PASSWORD_FILE")
            if password_file:
                try:
                    parameters["password"] = read_secret_file(
                        password_file, label="PostgreSQL password"
                    )
                except SecretFileError as exc:
                    raise RuntimeError("Cannot read PostgreSQL password secret") from exc
            parameters.setdefault("connect_timeout", 10)
            connection = psycopg.connect(**parameters, row_factory=dict_row)
            return _PostgresConnection(connection)
        if self._create_if_missing:
            connection = sqlite3.connect(self.path, timeout=10.0)
        else:
            connection = sqlite3.connect(
                f"{self.path.as_uri()}?mode=rw", uri=True, timeout=10.0
            )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        """Provide an atomic transaction and always close its connection."""
        connection = self.connect()

        try:
            connection.execute("BEGIN" if self.is_postgres else "BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        """Initialize legacy tables and apply the current schema migration."""
        if self.is_postgres:
            self._initialize_postgres()
            return
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version > CURRENT_SCHEMA_VERSION:
                    raise RuntimeError(
                        f"Database schema version {version} is newer than this release "
                        f"(supported through v{CURRENT_SCHEMA_VERSION})"
                    )
                tables = {
                    row[0]
                    for row in db.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                legacy_tables = {"repositories", "scans", "findings", "audit_events"}
                if tables and not legacy_tables.issubset(tables):
                    raise RuntimeError(
                        "Partial SQLite schema; refusing to modify an unmanaged database"
                    )
                if not tables:
                    _create_legacy_sqlite_schema(db)
                db.commit()
            except Exception:
                db.rollback()
                raise

        for migration in SQLITE_MIGRATIONS.values():
            migration(self.path)
        with closing(self.connect()) as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version != CURRENT_SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database migration stopped at v{version}; "
                    f"expected v{CURRENT_SCHEMA_VERSION}"
                )
            if not verify_migration_history(db):
                raise RuntimeError(
                    "Database migration checksums are not recognized by this release"
                )
    def _initialize_postgres(self) -> None:
        """Create or validate the complete current PostgreSQL schema."""
        with closing(self.connect()) as db:
            with db.connection:
                db.execute("SELECT pg_advisory_xact_lock(1145131090)")
                state = db.execute(
                    "SELECT to_regclass('public.schema_migrations') AS table_name"
                ).fetchone()
                if state["table_name"] is not None:
                    rows = db.execute(
                        "SELECT version, checksum FROM schema_migrations ORDER BY version"
                    ).fetchall()
                    expected_checksums = {
                        11: _postgres_schema_checksum(),
                        **_postgres_migration_checksums(),
                    }
                    applied_versions = [row["version"] for row in rows]
                    expected_versions = list(
                        range(11, (applied_versions[-1] if applied_versions else 10) + 1)
                    )
                    if not applied_versions or applied_versions != expected_versions or any(
                        version not in expected_checksums
                        or row["checksum"] != expected_checksums[version]
                        for row in rows
                        for version in (row["version"],)
                    ):
                        raise RuntimeError(
                            "PostgreSQL schema differs from this release; use a reviewed migration"
                        )
                else:
                    existing_tables = db.execute(
                        "SELECT COUNT(*) AS count FROM information_schema.tables "
                        "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
                    ).fetchone()["count"]
                    if existing_tables:
                        raise RuntimeError(
                            "Refusing to initialize TALARIA in a non-empty "
                            "unmanaged PostgreSQL schema"
                        )
                    for statement in POSTGRES_SCHEMA.split(";"):
                        if statement.strip():
                            db.execute(statement)
                    db.execute(
                        "INSERT INTO schema_migrations(version, checksum) VALUES (?, ?) "
                        "ON CONFLICT(version) DO NOTHING",
                        (11, _postgres_schema_checksum()),
                    )
                    applied_versions = [11]
                expected_checksums = {
                    11: _postgres_schema_checksum(),
                    **_postgres_migration_checksums(),
                }
                for version in range(applied_versions[-1] + 1, CURRENT_SCHEMA_VERSION + 1):
                    migration = POSTGRES_MIGRATIONS.get(version)
                    if migration is None:
                        raise RuntimeError(
                            f"PostgreSQL migration v{version} is not available"
                        )
                    for statement in migration.split(";"):
                        if statement.strip():
                            db.execute(statement)
                    if version == 14:
                        backfill_audit_chain(db)
                        db.execute(
                            "ALTER TABLE audit_events "
                            "ALTER COLUMN previous_hash SET NOT NULL"
                        )
                        db.execute(
                            "ALTER TABLE audit_events "
                            "ALTER COLUMN entry_hash SET NOT NULL"
                        )
                    db.execute(
                        "INSERT INTO schema_migrations(version, checksum) VALUES (?, ?)",
                        (version, expected_checksums[version]),
                    )
        healthy, version = self.readiness(self.path)
        if not healthy or version != CURRENT_SCHEMA_VERSION:
            raise RuntimeError("PostgreSQL database failed readiness after initialization")

    @staticmethod
    def readiness(path: Path | str) -> tuple[bool, int | None]:
        """Check an existing database without creating it or running migrations."""
        if _is_postgres_url(path):
            try:
                database = Database(path, initialize=False)
                with closing(database.connect()) as connection:
                    rows = connection.execute(
                        "SELECT version, checksum FROM schema_migrations ORDER BY version"
                    ).fetchall()
                    tables = {
                        row["table_name"]
                        for row in connection.execute(
                            "SELECT table_name FROM information_schema.tables "
                            "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
                        ).fetchall()
                    }
                    audit_chain_valid = verify_audit_chain(connection)
                versions = [row["version"] for row in rows]
                version = versions[-1] if versions else None
                expected_checksums = {
                    11: _postgres_schema_checksum(),
                    **_postgres_migration_checksums(),
                }
                return (
                    versions == list(range(11, CURRENT_SCHEMA_VERSION + 1))
                    and all(
                        row["checksum"] == expected_checksums.get(row["version"])
                        for row in rows
                    )
                    and POSTGRES_REQUIRED_TABLES <= tables
                    and audit_chain_valid,
                    version,
                )
            except Exception:
                return False, None
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            return False, None
        uri = f"{resolved.as_uri()}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=1.0)
            connection.row_factory = sqlite3.Row
            try:
                return Database.readiness_connection(connection)
            finally:
                connection.close()
        except sqlite3.Error:
            return False, None

    @staticmethod
    def readiness_connection(connection: sqlite3.Connection) -> tuple[bool, int | None]:
        """Check an existing SQLite connection without changing its transaction."""
        check = connection.execute("PRAGMA quick_check").fetchone()
        version = connection.execute("PRAGMA user_version").fetchone()
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchone()
        migrations_match = verify_migration_history(connection)
        audit_chain_valid = verify_audit_chain(connection)
        current_version = version[0] if version else None
        healthy = (
            check is not None
            and check[0] == "ok"
            and current_version == CURRENT_SCHEMA_VERSION
            and foreign_key_errors is None
            and migrations_match
            and audit_chain_valid
        )
        return healthy, current_version

    @staticmethod
    def postgres_schema_version(database_url: str) -> int | None:
        """Read applied PostgreSQL version without initializing or migrating."""
        database = Database(database_url, initialize=False)
        with closing(database.connect()) as connection:
            state = connection.execute(
                "SELECT to_regclass('public.schema_migrations') AS table_name"
            ).fetchone()
            if state["table_name"] is None:
                return None
            row = connection.execute(
                "SELECT MAX(version) AS version FROM schema_migrations"
            ).fetchone()
            return row["version"]

    def insert(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> int:
        """Execute an INSERT and return its generated ID."""
        with self.transaction() as db:
            if self.is_postgres and "RETURNING" not in sql.upper():
                sql = sql.rstrip().rstrip(";") + " RETURNING id"
            cursor = db.execute(sql, params)
            if self.is_postgres:
                row = cursor.fetchone()
                return row["id"] if row else 0
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
        """Persist a structured event as the next hash-chained audit entry."""
        with self.transaction() as connection:
            self.audit_in_transaction(connection, event, details)

    def audit_in_transaction(
        self,
        connection: Any,
        event: str,
        details: dict[str, Any],
    ) -> int:
        """Append a chained audit row inside a caller-owned transaction."""
        if not isinstance(event, str) or not event:
            raise ValueError("Audit event name cannot be empty")
        if not isinstance(details, dict):
            raise ValueError("Audit event details must be an object")
        if self.is_postgres:
            connection.execute("SELECT pg_advisory_xact_lock(1145131091)")

        previous = connection.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous is not None else GENESIS_HASH
        if previous_hash is None:
            raise RuntimeError("Audit chain has an unverified predecessor")

        created_at = datetime.now(UTC).isoformat()
        details_json = canonical_details(details)
        if self.is_postgres:
            event_id = connection.execute(
                "SELECT nextval(pg_get_serial_sequence('audit_events', 'id')) AS id"
            ).fetchone()["id"]
        else:
            event_id = connection.execute(
                "SELECT COALESCE(MAX(id), 0) + 1 AS id FROM audit_events"
            ).fetchone()["id"]
        entry_hash = audit_entry_hash(
            event_id, event, details_json, created_at, previous_hash
        )
        connection.execute(
            """INSERT INTO audit_events
                   (id, event, details, created_at, previous_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (event_id, event, details_json, created_at, previous_hash, entry_hash),
        )
        return event_id

    def allow_shared_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: float,
        *,
        prune_stale: bool = False,
    ) -> bool:
        """Atomically enforce a shared GCRA quota using the configured database."""
        if not isinstance(key, str) or not key:
            raise ValueError("Rate-limit key cannot be empty")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("Rate-limit capacity must be a positive integer")
        if window_seconds <= 0:
            raise ValueError("Rate-limit window must be positive")

        interval = window_seconds / limit
        tolerance = (limit - 1) * interval
        key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
        with self.transaction() as connection:
            if self.is_postgres:
                now = float(
                    connection.execute(
                        "SELECT EXTRACT(EPOCH FROM clock_timestamp()) AS now"
                    ).fetchone()["now"]
                )
            else:
                now = time.time()
            if prune_stale:
                connection.execute(
                    "DELETE FROM request_rate_limits WHERE last_seen < ?",
                    (now - 86_400,),
                )
            cursor = connection.execute(
                """INSERT INTO request_rate_limits
                       (key_hash, theoretical_arrival, last_seen)
                   VALUES (?, ?, ?)
                   ON CONFLICT(key_hash) DO UPDATE SET
                       theoretical_arrival =
                           CASE
                               WHEN request_rate_limits.theoretical_arrival > ?
                               THEN request_rate_limits.theoretical_arrival
                               ELSE ?
                           END + ?,
                       last_seen = ?
                   WHERE ? >= request_rate_limits.theoretical_arrival - ?
                   RETURNING key_hash""",
                (
                    key_hash,
                    now + interval,
                    now,
                    now,
                    now,
                    interval,
                    now,
                    now,
                    tolerance,
                ),
            )
            return cursor.fetchone() is not None


def _create_legacy_sqlite_schema(connection: sqlite3.Connection) -> None:
    """Create the SQLite baseline inside the caller's transaction."""
    connection.execute(
        """CREATE TABLE repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            path TEXT NOT NULL UNIQUE,
            registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    connection.execute(
        """CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository_id INTEGER NOT NULL REFERENCES repositories(id),
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            finding_count INTEGER NOT NULL DEFAULT 0
        )"""
    )
    connection.execute(
        """CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            repository_id INTEGER NOT NULL REFERENCES repositories(id),
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            payload TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
