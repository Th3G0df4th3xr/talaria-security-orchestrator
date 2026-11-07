import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from talaria.database import Database
from talaria.migrations import (
    SQLITE_MIGRATIONS,
    migrate_to_v2,
    migrate_to_v3,
    migrate_to_v4,
    migrate_to_v5,
    migrate_to_v6,
    migrate_to_v7,
    migrate_to_v8,
    migrate_to_v9,
    migrate_to_v10,
    migrate_to_v11,
    migrate_to_v12,
    migrate_to_v13,
    migrate_to_v14,
    migrate_to_v15,
    migrate_to_v16,
    migrate_to_v17,
)

pytestmark = [pytest.mark.acceptance, pytest.mark.database]


def create_legacy_database(path, invalid_scan_reference=False):
    connection = sqlite3.connect(path)

    connection.executescript(
        """
        CREATE TABLE repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            path TEXT NOT NULL UNIQUE,
            registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository_id INTEGER NOT NULL REFERENCES repositories(id),
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            finding_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            repository_id INTEGER NOT NULL REFERENCES repositories(id),
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            payload TEXT NOT NULL
        );

        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        INSERT INTO repositories(name, path)
        VALUES ('sample', '/tmp/sample');

        INSERT INTO scans(repository_id, completed_at, finding_count)
        VALUES (1, '2026-11-05T10:00:00', 1);

        INSERT INTO findings(
            fingerprint, repository_id, scan_id, payload
        )
        VALUES (
            'test-fingerprint',
            1,
            0,
            '{"rule_id": "python-eval"}'
        );

        INSERT INTO audit_events(event, details)
        VALUES ('scan.completed', '{"scan_id": 1}');
        """
    )

    if not invalid_scan_reference:
        connection.execute(
            "UPDATE findings SET scan_id = 1 WHERE id = 1"
        )

    connection.commit()
    connection.close()

def test_migration_preserves_legacy_data(tmp_path):
    path = tmp_path / "legacy.db"
    create_legacy_database(path)

    migrate_to_v2(path)

    connection = sqlite3.connect(path)

    assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
    assert connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    assert connection.execute(
        "SELECT COUNT(*) FROM finding_occurrences"
    ).fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    connection.close()


def test_migration_is_idempotent(tmp_path):
    path = tmp_path / "legacy.db"
    create_legacy_database(path)

    migrate_to_v2(path)
    migrate_to_v2(path)

    connection = sqlite3.connect(path)

    assert connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    assert connection.execute(
        "SELECT COUNT(*) FROM finding_occurrences"
    ).fetchone()[0] == 1

    connection.close()


def test_migration_rejects_invalid_scan_reference(tmp_path):
    path = tmp_path / "invalid.db"
    create_legacy_database(path, invalid_scan_reference=True)

    with pytest.raises(RuntimeError, match="Invalid legacy finding-to-scan"):
        migrate_to_v2(path)

    connection = sqlite3.connect(path)

    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    assert "scan_id" in {
        row[1] for row in connection.execute("PRAGMA table_info(findings)")
    }

    connection.close()


def test_initialization_preserves_legacy_database_with_orphan_findings(tmp_path):
    path = tmp_path / "legacy-orphans.db"
    create_legacy_database(path, invalid_scan_reference=True)
    connection = sqlite3.connect(path)
    before = {
        table: connection.execute(f'SELECT * FROM "{table}" ORDER BY id').fetchall()
        for table in ("repositories", "scans", "findings", "audit_events")
    }
    connection.close()

    with pytest.raises(RuntimeError, match="Invalid legacy finding-to-scan"):
        Database(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    after = {
        table: connection.execute(f'SELECT * FROM "{table}" ORDER BY id').fetchall()
        for table in ("repositories", "scans", "findings", "audit_events")
    }
    assert after == before
    connection.close()


def test_v3_migration_adds_refresh_sessions_and_is_idempotent(tmp_path):
    path = tmp_path / "legacy.db"
    create_legacy_database(path)
    migrate_to_v2(path)

    migrate_to_v3(path)
    migrate_to_v3(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(refresh_sessions)")
    }
    assert {
        "id",
        "subject",
        "token_hash",
        "created_at",
        "expires_at",
        "revoked_at",
    } <= columns
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    connection.close()


def test_v3_migration_requires_v2(tmp_path):
    path = tmp_path / "legacy.db"
    create_legacy_database(path)

    with pytest.raises(RuntimeError, match="at v2"):
        migrate_to_v3(path)


def test_v4_migration_adds_refresh_families_and_is_idempotent(tmp_path):
    path = tmp_path / "sessions-v3.db"
    create_legacy_database(path)
    migrate_to_v2(path)
    migrate_to_v3(path)
    connection = sqlite3.connect(path)
    connection.execute(
        """
        INSERT INTO refresh_sessions
            (id, subject, token_hash, created_at, expires_at)
        VALUES ('session-1', 'user-1', ?, '2026-01-01T00:00:00+00:00',
                '2027-01-01T00:00:00+00:00')
        """,
        ("a" * 64,),
    )
    connection.commit()
    connection.close()

    migrate_to_v4(path)
    migrate_to_v4(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
    assert connection.execute(
        "SELECT family_id, replaced_by_id, compromised_at "
        "FROM refresh_sessions WHERE id = 'session-1'"
    ).fetchone() == ("session-1", None, None)
    connection.close()


def test_v5_and_v6_migrations_create_tenant_and_webhook_tables(tmp_path):
    path = tmp_path / "legacy.db"
    create_legacy_database(path)
    migrate_to_v2(path)
    migrate_to_v3(path)
    migrate_to_v4(path)
    migrate_to_v5(path)
    migrate_to_v6(path)
    migrate_to_v6(path)
    migrate_to_v7(path)
    migrate_to_v7(path)
    migrate_to_v8(path)
    migrate_to_v8(path)
    migrate_to_v9(path)
    migrate_to_v9(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 9
    table_names = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    assert {
        "users",
        "organizations",
        "organization_memberships",
        "webhook_deliveries",
        "approval_records",
        "github_events",
    } <= table_names
    assert "organization_id" in {
        row[1] for row in connection.execute("PRAGMA table_info(repositories)")
    }
    assert {"branch", "commit_sha"} <= {
        row[1] for row in connection.execute("PRAGMA table_info(scans)")
    }
    connection.close()


def test_concurrent_initializers_serialize_migrations(tmp_path):
    path = tmp_path / "concurrent.db"
    create_legacy_database(path)
    migrate_to_v2(path)

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: Database(path), range(4)))

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 17
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    connection.close()


def test_concurrent_initializers_serialize_empty_schema_bootstrap(tmp_path):
    path = tmp_path / "concurrent-empty.db"
    barrier = Barrier(8)

    def initialize(_):
        barrier.wait(timeout=5)
        return Database(path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(initialize, range(8)))

    healthy, version = Database.readiness(path)
    assert healthy
    assert version == 17


def test_empty_schema_bootstrap_rolls_back_as_one_transaction(tmp_path, monkeypatch):
    import talaria.database as database_module

    path = tmp_path / "failed-bootstrap.db"

    def create_partial_schema(connection):
        connection.execute(
            "CREATE TABLE repositories(id INTEGER PRIMARY KEY, name TEXT)"
        )
        raise RuntimeError("injected baseline creation failure")

    monkeypatch.setattr(
        database_module, "_create_legacy_sqlite_schema", create_partial_schema
    )

    with pytest.raises(RuntimeError, match="injected baseline creation failure"):
        Database(path)

    connection = sqlite3.connect(path)
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall() == []
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    connection.close()


@pytest.mark.parametrize("source_version", range(18))
def test_every_supported_schema_version_upgrades_to_latest(tmp_path, source_version):
    path = tmp_path / f"legacy-v{source_version}.db"
    create_legacy_database(path)
    connection = sqlite3.connect(path)
    if source_version == 1:
        connection.execute("PRAGMA user_version = 1")
    connection.close()

    migration_steps = (
        migrate_to_v2,
        migrate_to_v3,
        migrate_to_v4,
        migrate_to_v5,
        migrate_to_v6,
        migrate_to_v7,
        migrate_to_v8,
        migrate_to_v9,
        migrate_to_v10,
        migrate_to_v11,
        migrate_to_v12,
        migrate_to_v13,
        migrate_to_v14,
        migrate_to_v15,
        migrate_to_v16,
        migrate_to_v17,
    )
    for version, migration in enumerate(migration_steps, start=2):
        if version <= source_version:
            migration(path)

    database = Database(path)
    Database(path)

    assert Database.readiness(path) == (True, 17)
    assert database.execute("SELECT fingerprint FROM findings") == [
        {"fingerprint": "test-fingerprint"}
    ]
    assert database.execute("SELECT COUNT(*) AS count FROM audit_events")[0]["count"] == 1
    assert database.execute("SELECT payload FROM findings") == [
        {"payload": '{"rule_id": "python-eval"}'}
    ]
    assert database.execute(
        "SELECT COUNT(*) AS count FROM finding_occurrences"
    )[0]["count"] == 1
    assert [row["version"] for row in database.execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    )] == list(range(2, 18))


def test_v14_backfills_and_protects_audit_chain(tmp_path):
    path = tmp_path / "audit-chain.db"
    create_legacy_database(path)
    legacy_connection = sqlite3.connect(path)
    original_audit = legacy_connection.execute(
        "SELECT id, event, details, created_at FROM audit_events ORDER BY id"
    ).fetchall()
    legacy_connection.close()
    Database(path)
    database = Database(path, initialize=False)

    assert database.readiness(path) == (True, 17)
    assert [
        tuple(row.values())
        for row in database.execute(
            "SELECT id, event, details, created_at FROM audit_events ORDER BY id"
        )
    ] == original_audit
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        database.execute("UPDATE audit_events SET event = 'tampered' WHERE id = 1")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        database.execute("DELETE FROM audit_events WHERE id = 1")
    with pytest.raises(sqlite3.IntegrityError, match="require integrity hashes"):
        database.execute(
            "INSERT INTO audit_events(event, details) VALUES (?, ?)",
            ("unhashed", "{}"),
        )

    database.audit("new.event", {"b": 2, "a": 1})
    assert database.readiness(path) == (True, 17)
    rows = database.execute(
        "SELECT previous_hash, entry_hash, details FROM audit_events ORDER BY id"
    )
    assert rows[1]["previous_hash"] == rows[0]["entry_hash"]
    assert rows[1]["details"] == '{"a":1,"b":2}'

    connection = sqlite3.connect(path)
    connection.execute("DROP TRIGGER audit_events_append_only_update")
    connection.execute("UPDATE audit_events SET event = 'tampered' WHERE id = 1")
    connection.commit()
    connection.close()
    assert database.readiness(path) == (False, 17)


def test_failed_migration_rolls_back_schema_and_version(tmp_path):
    path = tmp_path / "failed-v3.db"
    create_legacy_database(path)
    migrate_to_v2(path)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE refresh_sessions (id TEXT PRIMARY KEY)")
    connection.commit()
    connection.close()

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        migrate_to_v3(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='refresh_sessions'"
    ).fetchone() == ("refresh_sessions",)
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    connection.close()


def test_failed_v13_migration_preserves_prior_version_and_checksum_history(tmp_path):
    path = tmp_path / "failed-v13.db"
    create_legacy_database(path)
    for version, migration in SQLITE_MIGRATIONS.items():
        if version <= 12:
            migration(path)
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE request_rate_limits (key_hash TEXT PRIMARY KEY)"
    )
    connection.commit()
    before_history = connection.execute(
        "SELECT version, checksum FROM schema_migrations ORDER BY version"
    ).fetchall()
    connection.close()

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        migrate_to_v13(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 12
    assert connection.execute(
        "SELECT version, checksum FROM schema_migrations ORDER BY version"
    ).fetchall() == before_history
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' "
        "AND name = 'request_rate_limits_last_seen_idx'"
    ).fetchone() is None
    connection.close()


def test_failed_v14_migration_preserves_prior_version_and_checksum_history(tmp_path):
    path = tmp_path / "failed-v14.db"
    create_legacy_database(path)
    for version, migration in SQLITE_MIGRATIONS.items():
        if version <= 13:
            migration(path)
    connection = sqlite3.connect(path)
    connection.execute("ALTER TABLE audit_events ADD COLUMN previous_hash TEXT")
    connection.commit()
    before_history = connection.execute(
        "SELECT version, checksum FROM schema_migrations ORDER BY version"
    ).fetchall()
    connection.close()
    with pytest.raises(sqlite3.OperationalError, match="duplicate column name"):
        migrate_to_v14(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 13
    assert connection.execute(
        "SELECT version, checksum FROM schema_migrations ORDER BY version"
    ).fetchall() == before_history
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' "
        "AND name LIKE 'audit_events_%'"
    ).fetchall() == []
    connection.close()


def test_failed_v15_migration_rolls_back_indexes_and_version(tmp_path):
    path = tmp_path / "failed-v15.db"
    create_legacy_database(path)
    for version, migration in SQLITE_MIGRATIONS.items():
        if version <= 14:
            migration(path)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE investigations (id TEXT PRIMARY KEY)")
    before_history = connection.execute(
        "SELECT version, checksum FROM schema_migrations ORDER BY version"
    ).fetchall()
    connection.commit()
    connection.close()

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        migrate_to_v15(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 14
    assert connection.execute(
        "SELECT version, checksum FROM schema_migrations ORDER BY version"
    ).fetchall() == before_history
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' "
        "AND name IN ('findings_id_repository_idx', "
        "'repositories_id_organization_idx')"
    ).fetchall() == []
    connection.close()


def test_v16_adds_organization_bound_github_repository_schema(tmp_path):
    path = tmp_path / "github-tenant-schema.db"
    database = Database(path)
    columns = {
        row["name"]
        for row in database.execute("PRAGMA table_info(github_events)")
    }
    assert {"organization_id", "github_repository_id"} <= columns
    assert database.execute(
        "SELECT version FROM schema_migrations WHERE version = 16"
    ) == [{"version": 16}]
    assert Database.readiness(path) == (True, 17)


def test_failed_v16_migration_rolls_back_tables_columns_and_version(tmp_path):
    path = tmp_path / "failed-v16.db"
    create_legacy_database(path)
    for version, migration in SQLITE_MIGRATIONS.items():
        if version <= 15:
            migration(path)
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE INDEX github_events_org_received_idx ON github_events(received_at)"
    )
    connection.commit()
    connection.close()

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        migrate_to_v16(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 15
    assert connection.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = 16"
    ).fetchone()[0] == 0
    assert "organization_id" not in {
        row[1] for row in connection.execute("PRAGMA table_info(github_events)")
    }
    assert connection.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' "
        "AND name = 'github_repositories'"
    ).fetchone()[0] == 0
    assert connection.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' "
        "AND name = 'github_repositories_org_idx'"
    ).fetchone()[0] == 0
    connection.close()


def test_v17_adds_persisted_github_check_run_schema(tmp_path):
    database = Database(tmp_path / "github-check-runs.db")
    columns = {
        row["name"] for row in database.execute("PRAGMA table_info(github_check_runs)")
    }
    assert {
        "github_repository_id", "check_run_id", "head_sha", "name", "status",
        "conclusion", "details_url", "started_at", "completed_at", "updated_at",
    } <= columns
    assert database.execute(
        "SELECT version FROM schema_migrations WHERE version = 17"
    ) == [{"version": 17}]
    assert Database.readiness(database.path) == (True, 17)


def test_failed_v17_migration_rolls_back_table_index_and_version(tmp_path):
    path = tmp_path / "failed-v17.db"
    create_legacy_database(path)
    for version, migration in SQLITE_MIGRATIONS.items():
        if version <= 16:
            migration(path)
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE INDEX github_check_runs_commit_idx "
        "ON github_events(repository, received_at)"
    )
    connection.commit()
    connection.close()

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        migrate_to_v17(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 16
    assert connection.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = 17"
    ).fetchone()[0] == 0
    assert connection.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' "
        "AND name = 'github_check_runs'"
    ).fetchone()[0] == 0
    connection.close()

def test_future_schema_version_is_rejected_without_mutation(tmp_path):
    path = tmp_path / "future-schema.db"
    Database(path)
    connection = sqlite3.connect(path)
    tables_before = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    connection.execute("PRAGMA user_version = 18")
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="newer than this release"):
        Database(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 18
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall() == tables_before
    connection.close()


def test_unknown_legacy_schema_version_is_rejected_without_mutation(tmp_path):
    path = tmp_path / "unknown-schema.db"
    create_legacy_database(path)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = -1")
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="v0 or v1"):
        Database(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == -1
    assert connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    connection.close()


def test_partial_legacy_schema_is_rejected_without_modification(tmp_path):
    path = tmp_path / "partial-schema.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE repositories (id INTEGER PRIMARY KEY)")
    connection.commit()
    before = connection.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    connection.close()

    with pytest.raises(RuntimeError, match="Partial SQLite schema"):
        Database(path)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    assert connection.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall() == before
    connection.close()


def test_sqlite_migration_registry_is_contiguous_from_legacy_baseline():
    assert list(SQLITE_MIGRATIONS) == list(range(2, 18))


def test_initialization_rejects_migration_checksum_drift(tmp_path):
    path = tmp_path / "checksum-drift.db"
    database = Database(path)
    database.execute(
        "UPDATE schema_migrations SET checksum = ? WHERE version = 7",
        ("0" * 64,),
    )

    with pytest.raises(RuntimeError, match="checksums are not recognized"):
        Database(path)

    assert Database.readiness(path) == (False, 17)


def test_known_persisted_v2_checksum_remains_compatible(tmp_path):
    path = tmp_path / "legacy-checksum.db"
    database = Database(path)
    database.execute(
        "UPDATE schema_migrations SET checksum = ? WHERE version = 2",
        ("ea507a8293249148339f535f24d0c66f8ff9c92148c780df1772f299ed7fd248",),
    )

    assert Database.readiness(path) == (True, 17)
    Database(path)
