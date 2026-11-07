import subprocess
from pathlib import Path

import pytest

from talaria.database import CURRENT_SCHEMA_VERSION, Database
from talaria.database_postgres_backup import (
    PostgresBackupError,
    backup_postgres_database,
    restore_postgres_database,
)


def test_postgres_backup_publishes_verified_private_archive(tmp_path, monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        passfile = kwargs["env"].get("PGPASSFILE")
        assert passfile is not None
        assert Path(passfile).stat().st_mode & 0o777 == 0o600
        assert "visible-secret" in Path(passfile).read_text(encoding="utf-8")
        if command[0] == "pg_dump":
            output = next(
                item.removeprefix("--file=")
                for item in command
                if item.startswith("--file=")
            )
            with open(output, "wb") as archive:
                archive.write(b"custom archive bytes")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", run)
    destination = tmp_path / "talaria.dump"

    result = backup_postgres_database(
        "postgresql://talaria:visible-secret@db.example/talaria?sslmode=require",
        destination,
    )

    assert result["format"] == "postgres-custom"
    assert destination.read_bytes() == b"custom archive bytes"
    assert destination.stat().st_mode & 0o777 == 0o600
    assert all("visible-secret" not in " ".join(command) for command in commands)
    assert commands[0][0] == "pg_dump"
    assert commands[1][:2] == ["pg_restore", "--list"]


def test_postgres_backup_refuses_overwrite(tmp_path):
    destination = tmp_path / "existing.dump"
    destination.write_bytes(b"keep")

    with pytest.raises(PostgresBackupError, match="already exists"):
        backup_postgres_database(
            "postgresql://talaria@db/talaria?sslmode=require", destination
        )

    assert destination.read_bytes() == b"keep"


@pytest.mark.parametrize("operation", ["backup", "restore"])
def test_malformed_postgres_url_returns_safe_backup_error(tmp_path, operation):
    archive = tmp_path / "archive.dump"
    archive.write_bytes(b"archive")

    with pytest.raises(PostgresBackupError, match="Invalid PostgreSQL database URL"):
        if operation == "backup":
            backup_postgres_database("postgresql://%zz", tmp_path / "output.dump")
        else:
            restore_postgres_database(archive, "postgresql://%zz")

    assert not (tmp_path / "output.dump").exists()


def test_postgres_backup_reports_unusable_destination_directory(tmp_path):
    blocked_parent = tmp_path / "not-a-directory"
    blocked_parent.write_text("preserve", encoding="utf-8")

    with pytest.raises(PostgresBackupError, match="Cannot prepare.*destination"):
        backup_postgres_database(
            "postgresql://talaria@db.example/talaria?sslmode=require",
            blocked_parent / "backup.dump",
        )

    assert blocked_parent.read_text(encoding="utf-8") == "preserve"
    assert not list(tmp_path.glob(".backup.dump.*.dump"))


def test_postgres_restore_refuses_active_database_as_target(tmp_path):
    archive = tmp_path / "backup.dump"
    archive.write_bytes(b"archive")
    active = "postgresql://talaria@db.example/talaria?sslmode=require"

    with pytest.raises(PostgresBackupError, match="differ from the active"):
        restore_postgres_database(archive, active, active)


def test_postgres_restore_uses_one_transaction_and_checks_readiness(
    tmp_path, monkeypatch
):
    archive = tmp_path / "backup.dump"
    archive.write_bytes(b"archive")
    commands = []

    class FakeCursor:
        def __init__(self, row):
            self.row = row

        def fetchone(self):
            return self.row

    class FakeConnection:
        def execute(self, sql):
            if "to_regclass" in sql:
                return FakeCursor({"table_name": None})
            return FakeCursor({"count": 0})

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(Database, "connect", lambda self: FakeConnection())
    monkeypatch.setattr(
        Database, "readiness", lambda *_args: (True, CURRENT_SCHEMA_VERSION)
    )
    monkeypatch.setattr(subprocess, "run", run)

    result = restore_postgres_database(
        archive,
        "postgresql://talaria@restore-db/talaria_restore?sslmode=require",
        "postgresql://talaria@source-db/talaria?sslmode=require",
    )

    assert result["schema_version"] == CURRENT_SCHEMA_VERSION
    assert "--single-transaction" in commands[1]
    assert "--exit-on-error" in commands[1]
    assert "--clean" not in commands[1]


@pytest.mark.parametrize("existing_object_query", ["public objects", "custom schema"])
def test_postgres_restore_refuses_nonempty_target_before_running_pg_restore(
    tmp_path, monkeypatch, existing_object_query
):
    archive = tmp_path / "backup.dump"
    archive.write_bytes(b"archive")

    class FakeCursor:
        def __init__(self, row):
            self.row = row

        def fetchone(self):
            return self.row

    class FakeConnection:
        def execute(self, sql):
            if "to_regclass" in sql:
                return FakeCursor({"table_name": None})
            if "nspname NOT IN" in sql:
                count = int(existing_object_query == "custom schema")
            elif "pg_class AS c" in sql:
                count = int(existing_object_query == "public objects")
            else:
                count = 0
            return FakeCursor({"count": count})

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    monkeypatch.setattr(Database, "connect", lambda self: FakeConnection())
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("pg_restore must not run"),
    )

    with pytest.raises(PostgresBackupError, match="no user-created schemas"):
        restore_postgres_database(
            archive,
            "postgresql://talaria@restore-db/talaria_restore?sslmode=require",
        )
