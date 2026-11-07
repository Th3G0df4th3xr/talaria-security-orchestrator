import re
import sqlite3

import psycopg
import pytest

from talaria.config import database_path
from talaria.database import Database, _is_postgres_url, _PostgresConnection
from talaria.database_transfer import (
    _TRANSFER_TABLES,
    DatabaseTransferError,
    transfer_sqlite_to_postgres,
)
from talaria.postgres_schema import (
    POSTGRES_MIGRATIONS,
    POSTGRES_REQUIRED_TABLES,
    POSTGRES_SCHEMA,
)

pytestmark = pytest.mark.database


def _split_top_level_commas(value):
    parts = []
    depth = 0
    start = 0
    for index, character in enumerate(value):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return parts


def _postgres_declared_columns():
    tables = {}
    schemas = [POSTGRES_SCHEMA, *POSTGRES_MIGRATIONS.values()]
    for schema in schemas:
        for match in re.finditer(
            r"CREATE TABLE(?: IF NOT EXISTS)?\s+(\w+)\s*\((.*?)\);",
            schema,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            columns = set()
            for clause in _split_top_level_commas(match.group(2)):
                first_word = clause.split(None, 1)[0].strip('"') if clause else ""
                if first_word.upper() not in {
                    "CHECK",
                    "CONSTRAINT",
                    "FOREIGN",
                    "PRIMARY",
                    "UNIQUE",
                }:
                    columns.add(first_word)
            tables[match.group(1)] = columns

    for schema in schemas:
        for match in re.finditer(
            r"ALTER TABLE\s+(\w+)\s+ADD COLUMN(?: IF NOT EXISTS)?\s+(\w+)",
            schema,
            flags=re.IGNORECASE,
        ):
            tables.setdefault(match.group(1), set()).add(match.group(2))

    return tables


class FakeCursor:
    def __init__(self):
        self.sql = None
        self.params = None


class FakeDriverConnection:
    def __init__(self):
        self.cursor = FakeCursor()

    def execute(self, sql, params=()):
        self.cursor.sql = sql
        self.cursor.params = params
        return self.cursor

    def executemany(self, sql, params):
        self.cursor.sql = sql
        self.cursor.params = params
        return self.cursor

    def close(self):
        return None


def test_database_config_prefers_postgres_url(monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE_URL", "postgresql://talaria@db/talaria")
    monkeypatch.setenv("TALARIA_DATABASE", ".talaria/local.db")

    assert database_path() == "postgresql://talaria@db/talaria"


def test_postgres_adapter_translates_qmark_placeholders():
    raw_connection = FakeDriverConnection()
    adapter = _PostgresConnection(raw_connection)

    adapter.execute("SELECT * FROM findings WHERE id = ? AND status = ?", (4, "open"))

    assert raw_connection.cursor.sql == (
        "SELECT * FROM findings WHERE id = %s AND status = %s"
    )
    assert raw_connection.cursor.params == (4, "open")


def test_postgres_password_is_loaded_from_secret_file(tmp_path, monkeypatch):
    secret_file = tmp_path / "postgres-password"
    secret_file.write_text("db-secret-value\n", encoding="utf-8")
    secret_file.chmod(0o600)
    monkeypatch.setenv("TALARIA_POSTGRES_PASSWORD_FILE", str(secret_file))
    captured = {}

    def connect(**parameters):
        captured.update(parameters)
        return FakeDriverConnection()

    monkeypatch.setattr(psycopg, "connect", connect)
    connection = Database(
        "postgresql://talaria@db/talaria?sslmode=require", initialize=False
    ).connect()
    connection.close()

    assert captured["password"] == "db-secret-value"


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql://talaria@remote.example/talaria",
        "postgresql://talaria@remote.example/talaria?sslmode=prefer",
        "postgresql://talaria@remote.example/talaria?sslmode=disable",
    ],
)
def test_postgres_connection_rejects_unencrypted_remote_transport(
    database_url, monkeypatch
):
    monkeypatch.delenv("TALARIA_DATABASE_TRUSTED_HOSTS", raising=False)
    monkeypatch.delenv("PGSSLMODE", raising=False)
    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda **_kwargs: pytest.fail("insecure PostgreSQL transport must be rejected"),
    )

    with pytest.raises(RuntimeError, match="transport configuration is invalid"):
        Database(database_url, initialize=False).connect()


def test_postgres_connection_allows_plaintext_for_explicit_trusted_host(monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE_TRUSTED_HOSTS", "postgres")
    for variable in ("PGHOST", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE"):
        monkeypatch.delenv(variable, raising=False)
    captured = {}

    def connect(**parameters):
        captured.update(parameters)
        return FakeDriverConnection()

    monkeypatch.setattr(psycopg, "connect", connect)
    connection = Database(
        "postgresql://talaria@postgres/talaria?sslmode=disable", initialize=False
    ).connect()

    assert captured["host"] == "postgres"
    connection.close()


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql:///talaria?sslmode=disable",
        "postgresql://talaria@postgres/talaria?service=remote&sslmode=disable",
        "postgresql://talaria@postgres/talaria?hostaddr=203.0.113.8&sslmode=disable",
    ],
)
def test_trusted_host_plaintext_exception_rejects_conninfo_routing_overrides(
    database_url, monkeypatch
):
    monkeypatch.setenv("TALARIA_DATABASE_TRUSTED_HOSTS", "localhost,postgres")
    for variable in ("PGHOST", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE"):
        monkeypatch.delenv(variable, raising=False)

    with pytest.raises(RuntimeError, match="transport configuration is invalid"):
        Database(database_url, initialize=False).connect()


def test_trusted_host_plaintext_exception_rejects_routing_environment_override(
    monkeypatch,
):
    monkeypatch.setenv("TALARIA_DATABASE_TRUSTED_HOSTS", "postgres")
    monkeypatch.setenv("PGHOSTADDR", "203.0.113.8")

    with pytest.raises(RuntimeError, match="transport configuration is invalid"):
        Database(
            "postgresql://talaria@postgres/talaria?sslmode=disable",
            initialize=False,
        ).connect()


def test_postgres_baseline_contains_all_runtime_tables_and_constraints():
    assert _is_postgres_url("postgresql://talaria@db/talaria")
    assert not _is_postgres_url(".talaria/talaria.db")
    for table in POSTGRES_REQUIRED_TABLES:
        assert table in _postgres_declared_columns()
    assert "consumed_at TEXT" in POSTGRES_SCHEMA
    assert "REFERENCES organizations(id) ON DELETE CASCADE" in POSTGRES_SCHEMA
    assert "REFERENCES users(id)" in POSTGRES_SCHEMA
    assert 17 in POSTGRES_MIGRATIONS


def test_sqlite_transfer_covers_all_persistent_schema_tables():
    non_persistent_tables = {"request_rate_limits", "schema_migrations"}

    assert set(_TRANSFER_TABLES) == POSTGRES_REQUIRED_TABLES - non_persistent_tables
    assert _TRANSFER_TABLES.index("investigations") > _TRANSFER_TABLES.index("findings")
    assert _TRANSFER_TABLES.index("github_repositories") > _TRANSFER_TABLES.index("repositories")
    assert _TRANSFER_TABLES.index("github_events") > _TRANSFER_TABLES.index("github_repositories")


def test_declared_postgres_v17_columns_match_sqlite_v17(tmp_path):
    postgres_columns = _postgres_declared_columns()
    database_path = tmp_path / "sqlite-v17.db"
    Database(database_path)
    connection = sqlite3.connect(database_path)
    try:
        sqlite_columns = {
            table: {
                row[1]
                for row in connection.execute(f'PRAGMA table_info("{table}")')
            }
            for (table,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
    finally:
        connection.close()

    assert POSTGRES_REQUIRED_TABLES <= postgres_columns.keys()
    assert sqlite_columns.keys() == postgres_columns.keys()
    assert sqlite_columns == postgres_columns


def test_sqlite_transfer_rejects_non_postgres_target_before_reading_source(tmp_path):
    source = tmp_path / "uninspected.db"
    source.touch()

    try:
        transfer_sqlite_to_postgres(source, Database(tmp_path / "target.db"))
    except DatabaseTransferError as exc:
        assert "Target database must be PostgreSQL" in str(exc)
    else:
        raise AssertionError("SQLite target should not be accepted")
