import os
import sqlite3
import stat

import pytest

from talaria.database_backup import (
    DatabaseBackupError,
    backup_database,
    copy_database,
    publish_file_no_overwrite,
)


def test_durable_publication_syncs_file_and_directory_without_overwrite(
    tmp_path, monkeypatch
):
    temporary = tmp_path / ".prepared"
    destination = tmp_path / "published"
    temporary.write_bytes(b"complete backup")
    sync_targets = []
    real_fsync = os.fsync

    def record_fsync(descriptor):
        sync_targets.append(stat.S_ISDIR(os.fstat(descriptor).st_mode))
        return real_fsync(descriptor)

    monkeypatch.setattr("talaria.database_backup.os.fsync", record_fsync)

    publish_file_no_overwrite(temporary, destination)

    assert sync_targets == [False, True]
    assert destination.read_bytes() == b"complete backup"
    assert not temporary.exists()

    duplicate = tmp_path / ".duplicate"
    duplicate.write_bytes(b"must not replace")
    with pytest.raises(FileExistsError):
        publish_file_no_overwrite(duplicate, destination)

    assert destination.read_bytes() == b"complete backup"


def test_durable_publication_removes_visible_destination_when_directory_sync_fails(
    tmp_path, monkeypatch
):
    temporary = tmp_path / ".prepared"
    destination = tmp_path / "published"
    temporary.write_bytes(b"complete backup")
    real_fsync = os.fsync

    def fail_directory_fsync(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("directory sync failed")
        return real_fsync(descriptor)

    monkeypatch.setattr("talaria.database_backup.os.fsync", fail_directory_fsync)

    with pytest.raises(OSError, match="directory sync failed"):
        publish_file_no_overwrite(temporary, destination)

    assert not destination.exists()
    assert temporary.read_bytes() == b"complete backup"


def test_backup_is_consistent_verified_and_source_is_unchanged(tmp_path):
    source = tmp_path / "source.db"
    destination = tmp_path / "backup.db"
    connection = sqlite3.connect(source)
    connection.executescript(
        "CREATE TABLE repositories(id INTEGER PRIMARY KEY);"
        "CREATE TABLE scans(id INTEGER PRIMARY KEY);"
        "CREATE TABLE findings(id INTEGER PRIMARY KEY);"
        "CREATE TABLE audit_events(id INTEGER PRIMARY KEY);"
        "CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT);"
        "INSERT INTO records(value) VALUES ('preserve me'); PRAGMA user_version=4;"
    )
    connection.close()

    result = backup_database(source, destination)

    assert result["schema_version"] == 4
    original = sqlite3.connect(source)
    backup = sqlite3.connect(destination)
    assert original.execute("SELECT * FROM records").fetchall() == [(1, "preserve me")]
    assert backup.execute("SELECT * FROM records").fetchall() == [(1, "preserve me")]
    assert original.execute("PRAGMA user_version").fetchone()[0] == 4
    assert backup.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert destination.stat().st_mode & 0o077 == 0
    original.close()
    backup.close()


def test_copy_refuses_to_overwrite_destination(tmp_path):
    source = tmp_path / "source.db"
    destination = tmp_path / "backup.db"
    sqlite3.connect(source).close()
    destination.write_bytes(b"keep")

    with pytest.raises(DatabaseBackupError, match="refusing to overwrite"):
        copy_database(source, destination)

    assert destination.read_bytes() == b"keep"


def test_copy_refuses_same_file(tmp_path):
    source = tmp_path / "source.db"
    sqlite3.connect(source).close()

    with pytest.raises(DatabaseBackupError, match="different files"):
        copy_database(source, source)


def test_copy_rejects_non_talaria_database_without_publishing(tmp_path):
    source = tmp_path / "empty.db"
    destination = tmp_path / "backup.db"
    sqlite3.connect(source).close()

    with pytest.raises(DatabaseBackupError, match="not a TALARIA database"):
        copy_database(source, destination)

    assert not destination.exists()


def test_copy_reports_unusable_destination_directory_without_changing_source(
    tmp_path,
):
    source = tmp_path / "source.db"
    blocked_parent = tmp_path / "not-a-directory"
    connection = sqlite3.connect(source)
    connection.executescript(
        "CREATE TABLE repositories(id INTEGER PRIMARY KEY);"
        "CREATE TABLE scans(id INTEGER PRIMARY KEY);"
        "CREATE TABLE findings(id INTEGER PRIMARY KEY);"
        "CREATE TABLE audit_events(id INTEGER PRIMARY KEY);"
    )
    connection.close()
    blocked_parent.write_text("preserve", encoding="utf-8")
    original = source.read_bytes()

    with pytest.raises(DatabaseBackupError, match="Cannot prepare database copy"):
        copy_database(source, blocked_parent / "backup.db")

    assert source.read_bytes() == original
    assert blocked_parent.read_text(encoding="utf-8") == "preserve"
    assert not list(tmp_path.glob(".backup.db.*.backup"))
