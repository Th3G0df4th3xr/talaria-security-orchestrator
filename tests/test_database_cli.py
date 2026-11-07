import json
import sqlite3
import sys
from pathlib import Path

import pytest

from talaria.cli import main
from talaria.database import CURRENT_SCHEMA_VERSION


def _create_v0_database(path):
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
        INSERT INTO repositories(name, path) VALUES ('legacy', '/legacy');
        INSERT INTO scans(repository_id, completed_at) VALUES (1, CURRENT_TIMESTAMP);
        INSERT INTO findings(fingerprint, repository_id, scan_id, payload)
            VALUES ('kept', 1, 1, '{"preserved":true}');
        """
    )
    connection.commit()
    connection.close()


def test_upgrade_command_backs_up_before_migrating(tmp_path, monkeypatch, capsys):
    path = tmp_path / "talaria.db"
    _create_v0_database(path)
    monkeypatch.setenv("TALARIA_DATABASE", str(path))
    monkeypatch.setattr(sys, "argv", ["talaria", "upgrade-db"])

    main()

    output = json.loads(capsys.readouterr().out)
    backup_path = output["backup"]["destination"]
    assert output["schema_version"] == CURRENT_SCHEMA_VERSION
    assert Path(backup_path).is_file()
    upgraded = sqlite3.connect(path)
    backup = sqlite3.connect(backup_path)
    assert upgraded.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
    assert backup.execute("PRAGMA user_version").fetchone()[0] == 0
    assert upgraded.execute("SELECT payload FROM findings").fetchone()[0] == (
        '{"preserved":true}'
    )
    assert backup.execute("SELECT payload FROM findings").fetchone()[0] == (
        '{"preserved":true}'
    )
    upgraded.close()
    backup.close()


def test_upgrade_copy_command_migrates_new_file_and_preserves_source(
    tmp_path, monkeypatch, capsys
):
    source = tmp_path / "legacy.db"
    destination = tmp_path / "upgraded.db"
    _create_v0_database(source)
    original = sqlite3.connect(source)
    original_finding = original.execute(
        "SELECT id, fingerprint, repository_id, scan_id, payload FROM findings"
    ).fetchall()
    original.close()
    monkeypatch.setenv("TALARIA_DATABASE", str(source))
    monkeypatch.setattr(
        sys, "argv", ["talaria", "upgrade-db", "--copy-to", str(destination)]
    )

    main()

    result = json.loads(capsys.readouterr().out)
    assert result["source_schema_version"] == 0
    assert result["schema_version"] == CURRENT_SCHEMA_VERSION
    source_connection = sqlite3.connect(source)
    destination_connection = sqlite3.connect(destination)
    assert source_connection.execute("PRAGMA user_version").fetchone()[0] == 0
    assert source_connection.execute(
        "SELECT id, fingerprint, repository_id, scan_id, payload FROM findings"
    ).fetchall() == original_finding
    assert destination_connection.execute("PRAGMA user_version").fetchone()[0] == (
        CURRENT_SCHEMA_VERSION
    )
    assert destination_connection.execute(
        "SELECT fingerprint, payload FROM findings"
    ).fetchall() == [("kept", '{"preserved":true}')]
    assert destination.stat().st_mode & 0o077 == 0
    source_connection.close()
    destination_connection.close()


def test_upgrade_copy_failure_does_not_publish_or_change_source(
    tmp_path, monkeypatch
):
    source = tmp_path / "broken.db"
    destination = tmp_path / "upgraded.db"
    _create_v0_database(source)
    connection = sqlite3.connect(source)
    connection.execute("UPDATE findings SET scan_id = 0")
    connection.commit()
    connection.close()
    monkeypatch.setenv("TALARIA_DATABASE", str(source))
    monkeypatch.setattr(
        sys, "argv", ["talaria", "upgrade-db", "--copy-to", str(destination)]
    )

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2
    connection = sqlite3.connect(source)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    assert connection.execute("SELECT scan_id FROM findings").fetchone()[0] == 0
    connection.close()
    assert not destination.exists()
    assert not list(tmp_path.glob(".upgraded.db.*.upgrade"))


def test_upgrade_copy_reports_unusable_destination_directory(
    tmp_path, monkeypatch, capsys
):
    source = tmp_path / "legacy.db"
    blocked_parent = tmp_path / "not-a-directory"
    blocked_parent.write_text("preserve", encoding="utf-8")
    _create_v0_database(source)
    monkeypatch.setenv("TALARIA_DATABASE", str(source))
    monkeypatch.setattr(
        sys,
        "argv",
        ["talaria", "upgrade-db", "--copy-to", str(blocked_parent / "out.db")],
    )

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2
    assert "Cannot create destination directory" in capsys.readouterr().err
    assert blocked_parent.read_text(encoding="utf-8") == "preserve"


def test_upgrade_failure_keeps_legacy_database_and_backup(tmp_path, monkeypatch):
    path = tmp_path / "broken.db"
    _create_v0_database(path)
    connection = sqlite3.connect(path)
    connection.execute("UPDATE findings SET scan_id = 0")
    connection.commit()
    connection.close()
    monkeypatch.setenv("TALARIA_DATABASE", str(path))
    monkeypatch.setattr(sys, "argv", ["talaria", "upgrade-db"])

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2
    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    assert connection.execute("SELECT scan_id FROM findings").fetchone()[0] == 0
    connection.close()
    assert len(list(tmp_path.glob("broken.db.pre-migration-*.bak"))) == 1


def test_postgres_upgrade_requires_and_creates_backup_before_migration(
    tmp_path, monkeypatch, capsys
):
    from talaria import cli

    url = "postgresql://talaria@database/talaria"
    destination = tmp_path / "pre-upgrade.dump"
    actions = []

    class FakeDatabase:
        @staticmethod
        def postgres_schema_version(_url):
            actions.append("read-version")
            return 11

        def __init__(self, _url, *, initialize):
            assert initialize is True
            actions.append("initialize")
            self.path = url

    def backup(_url, path):
        actions.append("backup")
        assert path == destination
        return {"destination": str(path), "format": "postgres-custom"}

    monkeypatch.setattr(cli, "database_path", lambda: url)
    monkeypatch.setattr(cli, "Database", FakeDatabase)
    monkeypatch.setattr(cli, "backup_postgres_database", backup)
    monkeypatch.setattr(
        sys,
        "argv",
        ["talaria", "upgrade-db", "--backup-output", str(destination)],
    )

    main()

    result = json.loads(capsys.readouterr().out)
    assert actions == ["read-version", "backup", "initialize"]
    assert result["schema_version"] == CURRENT_SCHEMA_VERSION
    assert result["backup"]["destination"] == str(destination)


def test_postgres_upgrade_refuses_existing_schema_without_backup(
    monkeypatch,
):
    from talaria import cli

    url = "postgresql://talaria@database/talaria"
    monkeypatch.setattr(cli, "database_path", lambda: url)
    monkeypatch.setattr(cli.Database, "postgres_schema_version", lambda _url: 11)
    monkeypatch.setattr(sys, "argv", ["talaria", "upgrade-db"])

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2
