import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from talaria.auth.service import AuthService
from talaria.database import CURRENT_SCHEMA_VERSION, Database

pytestmark = pytest.mark.database


def test_database_initializes(isolated_db):
    path = isolated_db / "db.sqlite"
    db = Database(path)
    assert db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    assert path.stat().st_mode & 0o077 == 0


def test_foreign_keys_enabled_on_every_connection(isolated_db):
    db = Database(isolated_db / "db.sqlite")

    result = db.execute("PRAGMA foreign_keys")

    assert result[0]["foreign_keys"] == 1


def test_transaction_rolls_back_on_error(isolated_db):
    db = Database(isolated_db / "db.sqlite")

    with pytest.raises(RuntimeError):
        with db.transaction() as connection:
            connection.execute(
                "INSERT INTO repositories(name, path) VALUES (?, ?)",
                ("rollback-test", "/tmp/rollback-test"),
            )
            raise RuntimeError("Simulated failure")

    rows = db.execute(
        "SELECT * FROM repositories WHERE name = ?",
        ("rollback-test",),
    )

    assert rows == []


def test_transaction_closes_connection(isolated_db):
    db = Database(isolated_db / "db.sqlite")

    with db.transaction() as connection:
        connection.execute(
            "INSERT INTO repositories(name, path) VALUES (?, ?)",
            ("closure-test", "/tmp/closure-test"),
        )

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_current_schema_rejects_duplicate_findings_and_occurrences(isolated_db):
    database = Database(isolated_db / "constraints.db")
    repository_id = database.insert(
        "INSERT INTO repositories(name, path) VALUES (?, ?)",
        ("constraints", "/tmp/constraints"),
    )
    scan_id = database.insert(
        "INSERT INTO scans(repository_id, completed_at) VALUES (?, ?)",
        (repository_id, "2026-11-07T00:00:00+00:00"),
    )
    finding_id = database.insert(
        """INSERT INTO findings
           (fingerprint, repository_id, payload, first_seen_at, last_seen_at)
           VALUES (?, ?, ?, ?, ?)""",
        (
            "unique-fingerprint",
            repository_id,
            "{}",
            "2026-11-07T00:00:00+00:00",
            "2026-11-07T00:00:00+00:00",
        ),
    )
    occurrence = (finding_id, scan_id, "2026-11-07T00:00:00+00:00")
    database.insert(
        "INSERT INTO finding_occurrences(finding_id, scan_id, observed_at) "
        "VALUES (?, ?, ?)",
        occurrence,
    )

    with pytest.raises(sqlite3.IntegrityError):
        database.insert(
            """INSERT INTO findings
               (fingerprint, repository_id, payload, first_seen_at, last_seen_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                "unique-fingerprint",
                repository_id,
                "{}",
                "2026-11-07T00:00:00+00:00",
                "2026-11-07T00:00:00+00:00",
            ),
        )

    with pytest.raises(sqlite3.IntegrityError):
        database.insert(
            "INSERT INTO finding_occurrences(finding_id, scan_id, observed_at) "
            "VALUES (?, ?, ?)",
            occurrence,
        )

    with pytest.raises(sqlite3.IntegrityError):
        database.insert(
            "INSERT INTO finding_occurrences(finding_id, scan_id, observed_at) "
            "VALUES (?, ?, ?)",
            (9999, scan_id, "2026-11-07T00:00:00+00:00"),
        )


def test_readiness_requires_current_schema_and_does_not_migrate(isolated_db):
    path = isolated_db / "legacy.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE repositories(id INTEGER PRIMARY KEY);"
        "PRAGMA user_version = 0;"
    )
    connection.close()
    assert Database.readiness(path) == (False, 0)

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall() == [("repositories",)]
    connection.close()


def test_readiness_connection_pins_a_read_only_snapshot(isolated_db):
    path = isolated_db / "readiness-snapshot.db"
    database = Database(path)
    with sqlite3.connect(path) as setup:
        setup.execute("PRAGMA journal_mode = WAL")
    source = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    source.execute("BEGIN")

    assert Database.readiness_connection(source) == (True, CURRENT_SCHEMA_VERSION)

    Database(path, initialize=False).insert(
        "INSERT INTO repositories(name, path) VALUES (?, ?)",
        ("concurrent", "/tmp/concurrent"),
    )
    assert source.execute("SELECT COUNT(*) FROM repositories").fetchone()[0] == 0
    assert database.execute("SELECT COUNT(*) AS count FROM repositories")[0]["count"] == 1
    source.close()


def test_concurrent_audit_appends_preserve_hash_chain(isolated_db):
    path = isolated_db / "concurrent-audit.db"
    database = Database(path)

    def append(index):
        Database(path, initialize=False).audit("concurrent.test", {"index": index})

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append, range(40)))

    events = database.execute(
        "SELECT id, previous_hash, entry_hash FROM audit_events ORDER BY id"
    )
    assert len(events) == 40
    assert all(
        events[index]["previous_hash"] == events[index - 1]["entry_hash"]
        for index in range(1, len(events))
    )
    assert Database.readiness(path) == (True, CURRENT_SCHEMA_VERSION)


def test_investigation_foreign_keys_enforce_repository_and_tenant_pairing(isolated_db):
    database = Database(isolated_db / "investigation-tenant.db")
    auth = AuthService(database)
    bootstrap = auth.bootstrap("admin@example.test", "strong-test-password", "Org one")
    other = auth.create_organization("Org two", "admin@example.test")
    repository_id = database.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("repo", "/repo", bootstrap["organization_id"]),
    )
    finding_id = database.insert(
        """INSERT INTO findings
           (fingerprint, repository_id, payload, first_seen_at, last_seen_at)
           VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
        ("f" * 64, repository_id, "{}"),
    )
    record = (
        "investigation-1", other["organization_id"], repository_id, finding_id,
        bootstrap["user_id"], "provider.example", "model", "running",
        "2026-11-07T00:00:00+00:00",
    )

    with pytest.raises(sqlite3.IntegrityError):
        database.insert(
            """INSERT INTO investigations
               (id, organization_id, repository_id, finding_id, initiated_by,
                provider, model, status, started_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            record,
        )


def test_github_repository_foreign_key_enforces_tenant_pairing(isolated_db):
    database = Database(isolated_db / "github-tenant.db")
    auth = AuthService(database)
    bootstrap = auth.bootstrap("admin@example.test", "strong-test-password", "Org one")
    other = auth.create_organization("Org two", "admin@example.test")
    repository_id = database.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("repo", "/repo", bootstrap["organization_id"]),
    )

    with pytest.raises(sqlite3.IntegrityError):
        database.insert(
            """INSERT INTO github_repositories
               (github_repository_id, organization_id, repository_id, full_name,
                installation_id, default_branch, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                1234,
                other["organization_id"],
                repository_id,
                "owner/repo",
                "456",
                "main",
                "2026-11-07T00:00:00+00:00",
            ),
        )


def test_readiness_does_not_create_missing_database(isolated_db):
    path = isolated_db / "missing" / "database.db"

    assert Database.readiness(path) == (False, None)
    assert not path.exists()


def test_non_initializing_database_does_not_create_database(isolated_db):
    path = isolated_db / "missing" / "database.db"

    Database(path, initialize=False)

    assert not path.exists()


def test_non_initializing_connection_does_not_create_database(isolated_db):
    path = isolated_db / "missing" / "database.db"
    database = Database(path, initialize=False)

    with pytest.raises(sqlite3.OperationalError):
        database.connect()

    assert not path.exists()


def test_readiness_rejects_migration_checksum_drift(isolated_db):
    path = isolated_db / "checksum.db"
    database = Database(path)

    assert Database.readiness(path) == (True, CURRENT_SCHEMA_VERSION)
    database.execute(
        "UPDATE schema_migrations SET checksum = ? WHERE version = 2",
        ("0" * 64,),
    )

    assert Database.readiness(path) == (False, CURRENT_SCHEMA_VERSION)


def test_shared_rate_limit_uses_bounded_hashes_and_gcra(monkeypatch, isolated_db):
    import talaria.database as database_module

    path = isolated_db / "shared-rate-limit.db"
    database = Database(path)
    now = [100.0]
    monkeypatch.setattr(database_module.time, "time", lambda: now[0])

    assert database.allow_shared_rate_limit("client:/auth/login", 2, 60)
    independent_handle = Database(path, initialize=False)
    assert independent_handle.allow_shared_rate_limit("client:/auth/login", 2, 60)
    assert not independent_handle.allow_shared_rate_limit("client:/auth/login", 2, 60)

    now[0] += 30
    assert independent_handle.allow_shared_rate_limit("client:/auth/login", 2, 60)
    stored = database.execute(
        "SELECT key_hash FROM request_rate_limits"
    )
    assert stored == [
        {"key_hash": hashlib.sha256(b"client:/auth/login").hexdigest()}
    ]


def test_shared_rate_limit_prunes_stale_client_buckets(isolated_db):
    database = Database(isolated_db / "rate-limit-prune.db")
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO request_rate_limits "
            "(key_hash, theoretical_arrival, last_seen) VALUES (?, ?, ?)",
            ("old-key", 1.0, 1.0),
        )

    assert database.allow_shared_rate_limit(
        "new-client", 2, 60, prune_stale=True
    )
    assert database.execute(
        "SELECT key_hash FROM request_rate_limits ORDER BY key_hash"
    ) == [
        {"key_hash": hashlib.sha256(b"new-client").hexdigest()}
    ]
