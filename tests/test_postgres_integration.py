"""Opt-in tests for a disposable PostgreSQL database."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from urllib.parse import unquote, urlsplit

import pytest

from talaria.auth.service import AuthenticationError, AuthService
from talaria.auth.session_store import RefreshSessionStore, RefreshTokenReuseError
from talaria.database import Database
from talaria.database_transfer import transfer_sqlite_to_postgres

pytestmark = [pytest.mark.integration, pytest.mark.postgres]


@pytest.fixture
def postgres_database():
    url = os.getenv("TALARIA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("TALARIA_TEST_POSTGRES_URL is not configured")
    database_name = unquote(urlsplit(url).path.removeprefix("/"))
    if not database_name.startswith("talaria_test_"):
        pytest.fail("TALARIA_TEST_POSTGRES_URL must name a disposable talaria_test_* database")

    database = Database(url)
    with database.transaction() as connection:
        connection.execute(
            "TRUNCATE TABLE github_check_runs, investigations, request_rate_limits, "
            "approval_records, "
            "github_repositories, github_events, "
            "webhook_deliveries, "
            "organization_memberships, refresh_sessions, finding_occurrences, "
            "findings, scans, repositories, users, organizations, audit_events "
            "RESTART IDENTITY CASCADE"
        )
    yield database


def test_postgres_readiness_checks_current_baseline(postgres_database):
    assert Database.readiness(postgres_database.path) == (True, 17)
    indexes = postgres_database.execute(
        "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' "
        "AND indexname IN ('webhook_deliveries_received_idx', "
        "'github_events_commit_sha_idx', 'request_rate_limits_last_seen_idx')"
    )
    assert {row["indexname"] for row in indexes} == {
        "webhook_deliveries_received_idx",
        "github_events_commit_sha_idx",
        "request_rate_limits_last_seen_idx",
    }


def test_postgres_applies_pending_migrations_from_v11(postgres_database):
    with postgres_database.transaction() as connection:
        connection.execute("DROP INDEX github_events_org_received_idx")
        connection.execute("ALTER TABLE github_events DROP COLUMN github_repository_id")
        connection.execute("ALTER TABLE github_events DROP COLUMN organization_id")
        connection.execute("DELETE FROM schema_migrations WHERE version IN (16, 17)")
        connection.execute("DROP INDEX github_check_runs_commit_idx")
        connection.execute("DROP TABLE github_check_runs")
        connection.execute("DROP TABLE github_repositories")
        connection.execute("DROP INDEX webhook_deliveries_received_idx")
        connection.execute("DROP INDEX github_events_commit_sha_idx")
        connection.execute("DROP INDEX request_rate_limits_last_seen_idx")
        connection.execute("DROP TABLE request_rate_limits")
        connection.execute("DROP TABLE investigations")
        connection.execute("DROP INDEX findings_id_repository_idx")
        connection.execute("DROP INDEX repositories_id_organization_idx")
        connection.execute("DELETE FROM schema_migrations WHERE version = 15")
        connection.execute("ALTER TABLE audit_events DROP COLUMN entry_hash")
        connection.execute("ALTER TABLE audit_events DROP COLUMN previous_hash")
        connection.execute("DELETE FROM schema_migrations WHERE version = 14")
        connection.execute("DELETE FROM schema_migrations WHERE version = 13")
        connection.execute("DELETE FROM schema_migrations WHERE version = 12")

    Database(postgres_database.path, initialize=True)

    assert Database.readiness(postgres_database.path) == (True, 17)
    assert postgres_database.execute(
        "SELECT COUNT(*) AS count FROM pg_indexes WHERE schemaname = 'public' "
        "AND indexname IN ('webhook_deliveries_received_idx', "
        "'github_events_commit_sha_idx', 'request_rate_limits_last_seen_idx')"
    )[0]["count"] == 3
    assert postgres_database.execute(
        "SELECT to_regclass('public.request_rate_limits') AS table_name"
    )[0]["table_name"] == "request_rate_limits"
    assert postgres_database.execute(
        "SELECT to_regclass('public.investigations') AS table_name"
    )[0]["table_name"] == "investigations"


def test_sqlite_transfer_preserves_ai_investigation_history(postgres_database, tmp_path):
    source = Database(tmp_path / "transfer-source.db")
    now = "2026-11-07T00:00:00+00:00"
    with source.transaction() as connection:
        connection.execute(
            "INSERT INTO organizations(id, name, created_at) VALUES ('org-1', 'Org', ?)",
            (now,),
        )
        connection.execute(
            "INSERT INTO users(id, email, password_hash, created_at) "
            "VALUES ('user-1', 'user@example.test', 'test-hash', ?)",
            (now,),
        )
        connection.execute(
            "INSERT INTO organization_memberships "
            "(user_id, organization_id, role, created_at) "
            "VALUES ('user-1', 'org-1', 'org_admin', ?)",
            (now,),
        )
        connection.execute(
            "INSERT INTO repositories(name, path, organization_id) "
            "VALUES ('repo', '/repo', 'org-1')"
        )
        connection.execute(
            """INSERT INTO github_repositories
               (github_repository_id, organization_id, repository_id, full_name,
                installation_id, default_branch, created_at)
               VALUES (1234, 'org-1', 1, 'owner/repo', '456', 'main', ?)""",
            (now,),
        )
        connection.execute(
            "INSERT INTO webhook_deliveries(delivery_id, event, body_sha256, received_at) "
            "VALUES ('delivery-1', 'pull_request', ?, ?)",
            ("a" * 64, now),
        )
        connection.execute(
            """INSERT INTO github_events
               (delivery_id, event, repository, received_at, organization_id,
                github_repository_id)
               VALUES ('delivery-1', 'pull_request', 'owner/repo', ?, 'org-1', 1234)""",
            (now,),
        )
        connection.execute(
            "INSERT INTO scans(repository_id, started_at, completed_at, finding_count, status) "
            "VALUES (1, ?, ?, 1, 'completed')",
            (now, now),
        )
        connection.execute(
            "INSERT INTO findings "
            "(fingerprint, repository_id, payload, first_seen_at, last_seen_at) "
            "VALUES ('fingerprint-1', 1, '{\"rule\":\"test\"}', ?, ?)",
            (now, now),
        )
        connection.execute(
            "INSERT INTO investigations "
            "(id, organization_id, repository_id, finding_id, initiated_by, provider, "
            "model, status, started_at, finished_at, evidence_refs, result) "
            "VALUES ('investigation-1', 'org-1', 1, 1, 'user-1', 'test-provider', "
            "'test-model', 'completed', ?, ?, '[\"source:app.py:1\"]', "
            "'{\"triage\":\"manual_review\"}')",
            (now, now),
        )

    result = transfer_sqlite_to_postgres(source.path, postgres_database)

    assert result["rows_by_table"]["investigations"] == 1
    assert result["rows_by_table"]["github_repositories"] == 1
    assert result["rows_by_table"]["github_events"] == 1
    assert postgres_database.execute(
        "SELECT id, evidence_refs, result FROM investigations"
    ) == [
        {
            "id": "investigation-1",
            "evidence_refs": '["source:app.py:1"]',
            "result": '{"triage":"manual_review"}',
        }
    ]
    assert postgres_database.execute(
        "SELECT organization_id, github_repository_id FROM github_events"
    ) == [{"organization_id": "org-1", "github_repository_id": 1234}]


@pytest.mark.concurrency
def test_postgres_shared_rate_limit_is_atomic_across_threads(postgres_database):
    def request(_):
        return postgres_database.allow_shared_rate_limit(
            "postgres-concurrency:/auth/login", 5, 60
        )

    with ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(request, range(12)))

    assert sum(results) == 5


@pytest.mark.concurrency
def test_postgres_bootstrap_allows_only_one_concurrent_admin(postgres_database):
    service = AuthService(postgres_database)

    def bootstrap(index):
        try:
            return service.bootstrap(
                f"admin{index}@example.test",
                "correct horse battery staple",
                f"Organization {index}",
            )
        except AuthenticationError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(bootstrap, (1, 2)))

    assert sum(result is not None for result in results) == 1
    assert postgres_database.execute("SELECT COUNT(*) AS count FROM users")[0]["count"] == 1
    assert (
        postgres_database.execute("SELECT COUNT(*) AS count FROM organizations")[0]["count"]
        == 1
    )


@pytest.mark.concurrency
def test_postgres_concurrent_refresh_reuse_revokes_the_rotated_family(
    postgres_database,
):
    original, _ = RefreshSessionStore(postgres_database).create("user-1")
    barrier = Barrier(2)

    def rotate():
        store = RefreshSessionStore(postgres_database)
        barrier.wait()
        try:
            return store.rotate(original)
        except RefreshTokenReuseError:
            return "reused"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: rotate(), range(2)))

    rotations = [result for result in results if result != "reused"]
    assert len(rotations) == 1
    assert results.count("reused") == 1
    replacement, _ = rotations[0]
    assert RefreshSessionStore(postgres_database).get_active(replacement) is None
    rows = postgres_database.execute(
        "SELECT compromised_at FROM refresh_sessions ORDER BY created_at, id"
    )
    assert len(rows) == 2
    assert all(row["compromised_at"] is not None for row in rows)
