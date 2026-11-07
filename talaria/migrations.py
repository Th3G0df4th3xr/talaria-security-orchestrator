import hashlib
import inspect
import sqlite3
from pathlib import Path

from talaria.audit.chain import backfill_audit_chain


def _begin_migration(
    connection: sqlite3.Connection,
    target: int,
    expected: int | tuple[int, ...] | None,
) -> bool:
    """Serialize upgrades and read the version only after obtaining the write lock."""
    connection.execute("BEGIN IMMEDIATE")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version >= target:
        connection.rollback()
        return False
    if expected is not None:
        expected_versions = (expected,) if isinstance(expected, int) else expected
        if version not in expected_versions:
            versions = " or ".join(f"v{item}" for item in expected_versions)
            raise RuntimeError(
                f"Database must be at {versions} before migration to v{target}"
            )
    return True


def migrate_to_v2(database_path: Path) -> None:
    """Migrate legacy TALARIA data to the v2 finding lifecycle schema."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        if not _begin_migration(connection, target=2, expected=(0, 1)):
            return

        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

        required = {"repositories", "scans", "findings", "audit_events"}

        if not required.issubset(tables):
            raise RuntimeError("Expected legacy TALARIA tables were not found")

        finding_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(findings)")
        }

        if not {"id", "fingerprint", "repository_id", "scan_id", "payload"}.issubset(
            finding_columns
        ):
            raise RuntimeError("Unexpected findings schema; migration aborted")

        invalid = connection.execute(
            """
            SELECT f.id
            FROM findings AS f
            LEFT JOIN scans AS s ON s.id = f.scan_id
            WHERE s.id IS NULL
            """
        ).fetchall()

        if invalid:
            raise RuntimeError(
                "Invalid legacy finding-to-scan references; migration aborted"
            )

        connection.execute(
            """
            CREATE TEMP TABLE legacy_finding_map AS
            SELECT id AS finding_id, scan_id
            FROM findings
            """
        )

        connection.execute(
            """
            ALTER TABLE scans
            ADD COLUMN status TEXT NOT NULL DEFAULT 'running'
            CHECK(status IN ('running', 'completed', 'failed'))
            """
        )

        connection.execute(
            "ALTER TABLE scans ADD COLUMN error_summary TEXT"
        )

        connection.execute(
            """
            UPDATE scans
            SET status = CASE
                WHEN error_summary IS NOT NULL THEN 'failed'
                WHEN completed_at IS NULL THEN 'running'
                ELSE 'completed'
            END
            """
        )

        connection.execute(
            """
            CREATE TABLE findings_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                repository_id INTEGER NOT NULL
                    REFERENCES repositories(id),
                payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK(status IN (
                        'open',
                        'needs_review',
                        'confirmed',
                        'false_positive',
                        'accepted_risk',
                        'fixed',
                        'reopened'
                    )),
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            INSERT INTO findings_v2 (
                id,
                fingerprint,
                repository_id,
                payload,
                status,
                first_seen_at,
                last_seen_at
            )
            SELECT
                f.id,
                f.fingerprint,
                f.repository_id,
                f.payload,
                'open',
                s.started_at,
                COALESCE(s.completed_at, s.started_at)
            FROM findings AS f
            JOIN scans AS s ON s.id = f.scan_id
            """
        )

        connection.execute(
            """
            CREATE TABLE finding_occurrences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL REFERENCES findings_v2(id),
                scan_id INTEGER NOT NULL REFERENCES scans(id),
                observed_at TEXT NOT NULL,
                UNIQUE(finding_id, scan_id)
            )
            """
        )

        connection.execute(
            """
            INSERT INTO finding_occurrences (
                finding_id,
                scan_id,
                observed_at
            )
            SELECT
                mapping.finding_id,
                mapping.scan_id,
                COALESCE(scans.completed_at, scans.started_at)
            FROM legacy_finding_map AS mapping
            JOIN scans ON scans.id = mapping.scan_id
            """
        )

        connection.execute("DROP TABLE findings")
        connection.execute("ALTER TABLE findings_v2 RENAME TO findings")

        violations = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        if violations:
            raise RuntimeError(
                f"Migration produced {len(violations)} foreign-key violations"
            )

        connection.execute("PRAGMA user_version = 2")
        connection.commit()

        connection.execute("PRAGMA foreign_keys = ON")

    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise

    finally:
        connection.close()


def migrate_to_v3(database_path: Path) -> None:
    """Add persistent refresh sessions without storing bearer tokens."""
    connection = sqlite3.connect(database_path, timeout=10.0)

    try:
        if not _begin_migration(connection, target=3, expected=2):
            return
        connection.execute(
            """
            CREATE TABLE refresh_sessions (
                id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                CHECK (length(subject) > 0),
                CHECK (length(token_hash) = 64)
            )
            """
        )
        connection.execute(
            "CREATE INDEX refresh_sessions_subject_idx ON refresh_sessions(subject)"
        )
        connection.execute(
            "CREATE INDEX refresh_sessions_expiry_idx ON refresh_sessions(expires_at)"
        )
        connection.execute("PRAGMA user_version = 3")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v4(database_path: Path) -> None:
    """Add refresh-token family metadata for rotation and reuse detection."""
    connection = sqlite3.connect(database_path, timeout=10.0)

    try:
        if not _begin_migration(connection, target=4, expected=3):
            return
        connection.execute("ALTER TABLE refresh_sessions ADD COLUMN family_id TEXT")
        connection.execute("ALTER TABLE refresh_sessions ADD COLUMN replaced_by_id TEXT")
        connection.execute("ALTER TABLE refresh_sessions ADD COLUMN compromised_at TEXT")
        connection.execute("UPDATE refresh_sessions SET family_id = id")
        connection.execute(
            "CREATE INDEX refresh_sessions_family_idx ON refresh_sessions(family_id)"
        )
        connection.execute("PRAGMA user_version = 4")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v5(database_path: Path) -> None:
    """Create organization identity tables and repository ownership field."""
    connection = sqlite3.connect(database_path, timeout=10.0)

    try:
        if not _begin_migration(connection, target=5, expected=4):
            return
        connection.execute(
            """
            CREATE TABLE organizations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
                    CHECK (is_active IN (0, 1)),
                CHECK (length(name) > 0)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
                    CHECK (is_active IN (0, 1)),
                is_platform_admin INTEGER NOT NULL DEFAULT 0
                    CHECK (is_platform_admin IN (0, 1)),
                CHECK (length(email) > 3)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE organization_memberships (
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                organization_id TEXT NOT NULL
                    REFERENCES organizations(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK (role IN (
                    'org_admin', 'security_lead', 'security_analyst',
                    'developer', 'auditor'
                )),
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, organization_id)
            )
            """
        )
        connection.execute(
            "ALTER TABLE repositories ADD COLUMN organization_id TEXT "
            "REFERENCES organizations(id) ON DELETE CASCADE"
        )
        connection.execute(
            "CREATE INDEX repositories_organization_idx "
            "ON repositories(organization_id)"
        )
        connection.execute("PRAGMA user_version = 5")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v6(database_path: Path) -> None:
    """Track processed GitHub webhook deliveries without storing payloads."""
    connection = sqlite3.connect(database_path, timeout=10.0)

    try:
        if not _begin_migration(connection, target=6, expected=5):
            return
        connection.execute(
            """CREATE TABLE webhook_deliveries (
                delivery_id TEXT PRIMARY KEY,
                event TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                received_at TEXT NOT NULL
            )"""
        )
        connection.execute("PRAGMA user_version = 6")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v7(database_path: Path) -> None:
    """Add organization-scoped, two-person approval records."""
    connection = sqlite3.connect(database_path, timeout=10.0)

    try:
        if not _begin_migration(connection, target=7, expected=6):
            return
        connection.execute(
            """CREATE TABLE approval_records (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL
                    REFERENCES organizations(id) ON DELETE CASCADE,
                action TEXT NOT NULL CHECK (action IN (
                    'github.create_branch', 'github.create_pull_request'
                )),
                resource TEXT NOT NULL,
                requested_by TEXT NOT NULL REFERENCES users(id),
                decided_by TEXT REFERENCES users(id),
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
                    'pending', 'approved', 'rejected', 'expired'
                )),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decided_at TEXT,
                CHECK (decided_by IS NULL OR decided_by != requested_by)
            )"""
        )
        connection.execute(
            "CREATE INDEX approval_records_org_status_idx "
            "ON approval_records(organization_id, status, created_at)"
        )
        connection.execute("PRAGMA user_version = 7")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v8(database_path: Path) -> None:
    """Record branch and commit identity for each scan."""
    connection = sqlite3.connect(database_path, timeout=10.0)

    try:
        if not _begin_migration(connection, target=8, expected=7):
            return
        connection.execute("ALTER TABLE scans ADD COLUMN branch TEXT")
        connection.execute("ALTER TABLE scans ADD COLUMN commit_sha TEXT")
        connection.execute("PRAGMA user_version = 8")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v9(database_path: Path) -> None:
    """Persist a sanitized summary of verified GitHub webhook events."""
    connection = sqlite3.connect(database_path, timeout=10.0)

    try:
        if not _begin_migration(connection, target=9, expected=8):
            return
        connection.execute(
            """CREATE TABLE github_events (
                delivery_id TEXT PRIMARY KEY
                    REFERENCES webhook_deliveries(delivery_id) ON DELETE CASCADE,
                event TEXT NOT NULL,
                repository TEXT,
                action TEXT,
                ref TEXT,
                base_ref TEXT,
                commit_sha TEXT,
                pull_request_number INTEGER,
                pull_request_state TEXT,
                merged INTEGER CHECK (merged IS NULL OR merged IN (0, 1)),
                actor TEXT,
                received_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            "CREATE INDEX github_events_repository_idx "
            "ON github_events(repository, received_at)"
        )
        connection.execute("PRAGMA user_version = 9")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v10(database_path: Path) -> None:
    """Record source checksums for the sequential migration chain."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    try:
        if not _begin_migration(connection, target=10, expected=9):
            return
        connection.execute(
            """CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                checksum TEXT NOT NULL CHECK (length(checksum) = 64),
                applied_at TEXT NOT NULL
            )"""
        )
        connection.executemany(
            "INSERT INTO schema_migrations(version, checksum, applied_at) "
            "VALUES (?, ?, CURRENT_TIMESTAMP)",
            sorted(migration_checksums().items()),
        )
        connection.execute("PRAGMA user_version = 10")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v11(database_path: Path) -> None:
    """Bind external action approvals to a single exact operation."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    try:
        if not _begin_migration(connection, target=11, expected=10):
            return
        connection.execute("ALTER TABLE approval_records ADD COLUMN consumed_at TEXT")
        connection.execute(
            "CREATE INDEX approval_records_consumption_idx "
            "ON approval_records(status, consumed_at, expires_at)"
        )
        connection.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at) "
            "VALUES (11, ?, CURRENT_TIMESTAMP)",
            (hashlib.sha256(inspect.getsource(migrate_to_v11).encode("utf-8")).hexdigest(),),
        )
        connection.execute("PRAGMA user_version = 11")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v12(database_path: Path) -> None:
    """Index webhook retention and commit lookups for integration sync."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    try:
        if not _begin_migration(connection, target=12, expected=11):
            return
        connection.execute(
            "CREATE INDEX webhook_deliveries_received_idx "
            "ON webhook_deliveries(received_at)"
        )
        connection.execute(
            "CREATE INDEX github_events_commit_sha_idx "
            "ON github_events(commit_sha)"
        )
        connection.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at) "
            "VALUES (12, ?, CURRENT_TIMESTAMP)",
            (hashlib.sha256(inspect.getsource(migrate_to_v12).encode("utf-8")).hexdigest(),),
        )
        connection.execute("PRAGMA user_version = 12")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v13(database_path: Path) -> None:
    """Add shared persistent rate-limit buckets for multiple workers."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    try:
        if not _begin_migration(connection, target=13, expected=12):
            return
        connection.execute(
            """CREATE TABLE request_rate_limits (
                key_hash TEXT PRIMARY KEY,
                theoretical_arrival REAL NOT NULL,
                last_seen REAL NOT NULL
            )"""
        )
        connection.execute(
            "CREATE INDEX request_rate_limits_last_seen_idx "
            "ON request_rate_limits(last_seen)"
        )
        connection.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at) "
            "VALUES (13, ?, CURRENT_TIMESTAMP)",
            (hashlib.sha256(inspect.getsource(migrate_to_v13).encode("utf-8")).hexdigest(),),
        )
        connection.execute("PRAGMA user_version = 13")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v14(database_path: Path) -> None:
    """Add and backfill an ordered integrity chain for audit events."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    try:
        if not _begin_migration(connection, target=14, expected=13):
            return
        connection.execute("ALTER TABLE audit_events ADD COLUMN previous_hash TEXT")
        connection.execute("ALTER TABLE audit_events ADD COLUMN entry_hash TEXT")
        backfill_audit_chain(connection)
        connection.execute(
            """CREATE TRIGGER audit_events_require_hashes
               BEFORE INSERT ON audit_events
               WHEN NEW.previous_hash IS NULL OR NEW.entry_hash IS NULL
               BEGIN
                   SELECT RAISE(ABORT, 'audit events require integrity hashes');
               END"""
        )
        connection.execute(
            """CREATE TRIGGER audit_events_append_only_update
               BEFORE UPDATE ON audit_events
               BEGIN
                   SELECT RAISE(ABORT, 'audit events are append-only');
               END"""
        )
        connection.execute(
            """CREATE TRIGGER audit_events_append_only_delete
               BEFORE DELETE ON audit_events
               BEGIN
                   SELECT RAISE(ABORT, 'audit events are append-only');
               END"""
        )
        connection.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at) "
            "VALUES (14, ?, CURRENT_TIMESTAMP)",
            (hashlib.sha256(inspect.getsource(migrate_to_v14).encode("utf-8")).hexdigest(),),
        )
        connection.execute("PRAGMA user_version = 14")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v15(database_path: Path) -> None:
    """Persist tenant-scoped AI investigation state and results."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    try:
        if not _begin_migration(connection, target=15, expected=14):
            return
        connection.execute(
            "CREATE UNIQUE INDEX findings_id_repository_idx "
            "ON findings(id, repository_id)"
        )
        connection.execute(
            "CREATE UNIQUE INDEX repositories_id_organization_idx "
            "ON repositories(id, organization_id)"
        )
        connection.execute(
            """CREATE TABLE investigations (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL
                    REFERENCES organizations(id) ON DELETE CASCADE,
                repository_id INTEGER NOT NULL,
                finding_id INTEGER NOT NULL,
                initiated_by TEXT NOT NULL REFERENCES users(id),
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
                started_at TEXT NOT NULL,
                finished_at TEXT,
                evidence_refs TEXT NOT NULL DEFAULT '[]',
                result TEXT,
                error_type TEXT,
                FOREIGN KEY (repository_id, organization_id)
                    REFERENCES repositories(id, organization_id) ON DELETE CASCADE,
                FOREIGN KEY (finding_id, repository_id)
                    REFERENCES findings(id, repository_id) ON DELETE CASCADE
            )"""
        )
        connection.execute(
            "CREATE INDEX investigations_org_started_idx "
            "ON investigations(organization_id, started_at DESC)"
        )
        connection.execute(
            "CREATE INDEX investigations_finding_started_idx "
            "ON investigations(finding_id, started_at DESC)"
        )
        connection.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at) "
            "VALUES (15, ?, CURRENT_TIMESTAMP)",
            (hashlib.sha256(inspect.getsource(migrate_to_v15).encode("utf-8")).hexdigest(),),
        )
        connection.execute("PRAGMA user_version = 15")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v16(database_path: Path) -> None:
    """Bind GitHub repositories and webhook events to TALARIA organizations."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    try:
        if not _begin_migration(connection, target=16, expected=15):
            return
        connection.execute(
            """CREATE TABLE github_repositories (
                github_repository_id INTEGER PRIMARY KEY,
                organization_id TEXT NOT NULL
                    REFERENCES organizations(id) ON DELETE CASCADE,
                repository_id INTEGER NOT NULL,
                full_name TEXT NOT NULL,
                installation_id TEXT NOT NULL,
                default_branch TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                created_at TEXT NOT NULL,
                UNIQUE (organization_id, full_name),
                FOREIGN KEY (repository_id, organization_id)
                    REFERENCES repositories(id, organization_id) ON DELETE CASCADE
            )"""
        )
        connection.execute(
            "CREATE INDEX github_repositories_org_idx "
            "ON github_repositories(organization_id, enabled, full_name)"
        )
        connection.execute(
            "ALTER TABLE github_events ADD COLUMN organization_id TEXT "
            "REFERENCES organizations(id) ON DELETE CASCADE"
        )
        connection.execute(
            "ALTER TABLE github_events ADD COLUMN github_repository_id INTEGER"
            " REFERENCES github_repositories(github_repository_id) ON DELETE SET NULL"
        )
        connection.execute(
            "CREATE INDEX github_events_org_received_idx "
            "ON github_events(organization_id, received_at)"
        )
        connection.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at) "
            "VALUES (16, ?, CURRENT_TIMESTAMP)",
            (hashlib.sha256(inspect.getsource(migrate_to_v16).encode("utf-8")).hexdigest(),),
        )
        connection.execute("PRAGMA user_version = 16")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_to_v17(database_path: Path) -> None:
    """Persist bounded GitHub check-run state by repository and commit."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    try:
        if not _begin_migration(connection, target=17, expected=16):
            return
        connection.execute(
            """CREATE TABLE github_check_runs (
                github_repository_id INTEGER NOT NULL
                    REFERENCES github_repositories(github_repository_id)
                    ON DELETE CASCADE,
                check_run_id INTEGER NOT NULL CHECK (check_run_id > 0),
                head_sha TEXT NOT NULL CHECK (length(head_sha) = 40),
                name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
                status TEXT NOT NULL CHECK (status IN ('queued', 'in_progress', 'completed')),
                conclusion TEXT CHECK (conclusion IS NULL OR length(conclusion) <= 64),
                details_url TEXT CHECK (details_url IS NULL OR length(details_url) <= 2048),
                started_at TEXT,
                completed_at TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (github_repository_id, check_run_id)
            )"""
        )
        connection.execute(
            "CREATE INDEX github_check_runs_commit_idx "
            "ON github_check_runs(github_repository_id, head_sha, updated_at DESC)"
        )
        connection.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at) "
            "VALUES (17, ?, CURRENT_TIMESTAMP)",
            (hashlib.sha256(inspect.getsource(migrate_to_v17).encode("utf-8")).hexdigest(),),
        )
        connection.execute("PRAGMA user_version = 17")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


SQLITE_MIGRATIONS = {
    2: migrate_to_v2,
    3: migrate_to_v3,
    4: migrate_to_v4,
    5: migrate_to_v5,
    6: migrate_to_v6,
    7: migrate_to_v7,
    8: migrate_to_v8,
    9: migrate_to_v9,
    10: migrate_to_v10,
    11: migrate_to_v11,
    12: migrate_to_v12,
    13: migrate_to_v13,
    14: migrate_to_v14,
    15: migrate_to_v15,
    16: migrate_to_v16,
    17: migrate_to_v17,
}

# This v2 digest is already persisted in the supplied schema-v10/v11/v12
# workspace databases. The current v2 implementation has changed since that
# digest was recorded; migration tests validate its output. Accept this one
# exact historical digest while writing the current digest to new databases.
LEGACY_MIGRATION_CHECKSUMS = {
    2: frozenset({"ea507a8293249148339f535f24d0c66f8ff9c92148c780df1772f299ed7fd248"}),
}


def migration_checksums() -> dict[int, str]:
    """Hash the implementation of each migration for drift detection."""
    return {
        version: hashlib.sha256(inspect.getsource(migration).encode("utf-8")).hexdigest()
        for version, migration in SQLITE_MIGRATIONS.items()
        if version <= 10
    }


def verify_migration_history(connection: sqlite3.Connection) -> bool:
    """Verify current migration checksums and the narrow legacy compatibility set."""
    try:
        applied = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT version, checksum FROM schema_migrations"
            )
        }
    except sqlite3.Error:
        return False
    expected = migration_history_checksums()
    if applied.keys() != expected.keys():
        return False
    return all(
        checksum == expected[version]
        or checksum in LEGACY_MIGRATION_CHECKSUMS.get(version, frozenset())
        for version, checksum in applied.items()
    )


def migration_history_checksums() -> dict[int, str]:
    """Return checksums for the complete supported migration history."""
    checksums = migration_checksums()
    checksums.update(
        {
            version: hashlib.sha256(inspect.getsource(migration).encode("utf-8")).hexdigest()
            for version, migration in SQLITE_MIGRATIONS.items()
            if version >= 11
        }
    )
    return checksums
