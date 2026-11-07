import sqlite3

import pytest

from talaria.database import CURRENT_SCHEMA_VERSION
from talaria.database_recovery import DatabaseRecoveryError, recover_legacy_database

pytestmark = [pytest.mark.acceptance, pytest.mark.database]


def _create_broken_legacy_database(path):
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
        INSERT INTO repositories(id, name, path) VALUES (1, 'legacy', '/repo');
        INSERT INTO scans(id, repository_id, started_at, completed_at, finding_count)
            VALUES (1, 1, '2025-01-01T00:00:00', '2025-01-01T00:01:00', 0);
        INSERT INTO scans(id, repository_id, started_at, completed_at, finding_count)
            VALUES (2, 1, '2026-01-01T00:00:00', '2026-01-01T00:01:00', 1);
        INSERT INTO scans(id, repository_id, started_at, completed_at, finding_count)
            VALUES (3, 1, '2026-02-01T00:00:00', '2026-02-01T00:01:00', 0);
        INSERT INTO findings(id, fingerprint, repository_id, scan_id, payload)
            VALUES (10, 'orphan-one', 1, 0, '{"evidence":"one"}');
        INSERT INTO findings(id, fingerprint, repository_id, scan_id, payload)
            VALUES (11, 'orphan-two', 1, 0, '{"evidence":"two"}');
        INSERT INTO findings(id, fingerprint, repository_id, scan_id, payload)
            VALUES (12, 'valid', 1, 2, '{"evidence":"valid"}');
        INSERT INTO audit_events(event, details)
            VALUES ('legacy.event', '{"kept":true}');
        """
    )
    connection.commit()
    connection.close()


def test_recovery_copies_repairs_and_migrates_without_changing_source(tmp_path):
    source = tmp_path / "legacy.db"
    destination = tmp_path / "recovered.db"
    _create_broken_legacy_database(source)
    source_db = sqlite3.connect(source)
    original_scans = source_db.execute(
        "SELECT id, repository_id, started_at, completed_at, finding_count "
        "FROM scans ORDER BY id"
    ).fetchall()
    original_audit = source_db.execute(
        "SELECT id, event, details, created_at FROM audit_events ORDER BY id"
    ).fetchall()
    source_db.close()

    result = recover_legacy_database(source, destination)

    assert result["schema_version"] == CURRENT_SCHEMA_VERSION
    assert result["recovered_findings"] == 2
    source_db = sqlite3.connect(source)
    assert source_db.execute("PRAGMA user_version").fetchone()[0] == 0
    assert source_db.execute(
        "SELECT id, scan_id FROM findings ORDER BY id"
    ).fetchall() == [(10, 0), (11, 0), (12, 2)]
    assert source_db.execute(
        "SELECT id, repository_id, started_at, completed_at, finding_count "
        "FROM scans ORDER BY id"
    ).fetchall() == original_scans
    assert source_db.execute(
        "SELECT id, event, details, created_at FROM audit_events ORDER BY id"
    ).fetchall() == original_audit
    source_db.close()

    recovered = sqlite3.connect(destination)
    assert recovered.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
    assert recovered.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert recovered.execute("PRAGMA foreign_key_check").fetchall() == []
    assert recovered.execute(
        "SELECT id, payload FROM findings ORDER BY id"
    ).fetchall() == [
        (10, '{"evidence":"one"}'),
        (11, '{"evidence":"two"}'),
        (12, '{"evidence":"valid"}'),
    ]
    assert recovered.execute(
        "SELECT finding_id, scan_id FROM finding_occurrences ORDER BY finding_id"
    ).fetchall() == [(10, 4), (11, 4), (12, 2)]
    assert recovered.execute(
        "SELECT id, repository_id, started_at, completed_at, finding_count "
        "FROM scans WHERE id <= 3 ORDER BY id"
    ).fetchall() == original_scans
    assert recovered.execute(
        "SELECT id, event, details, created_at FROM audit_events "
        "WHERE id <= 1 ORDER BY id"
    ).fetchall() == original_audit
    assert recovered.execute(
        "SELECT COUNT(*) FROM finding_occurrences"
    ).fetchone()[0] == 3
    recovery_scans = recovered.execute(
        "SELECT status, error_summary FROM scans WHERE status = 'failed'"
    ).fetchall()
    assert len(recovery_scans) == 1
    assert "missing scan IDs: 0" in recovery_scans[0][1]
    assert recovered.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event = 'legacy.event'"
    ).fetchone()[0] == 1
    assert recovered.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event = 'database.legacy_recovery'"
    ).fetchone()[0] == 1
    recovered.close()


def test_recovery_refuses_to_overwrite_destination(tmp_path):
    source = tmp_path / "legacy.db"
    destination = tmp_path / "recovered.db"
    _create_broken_legacy_database(source)
    destination.write_bytes(b"keep")

    with pytest.raises(DatabaseRecoveryError, match="refusing to overwrite"):
        recover_legacy_database(source, destination)

    assert destination.read_bytes() == b"keep"


def test_recovery_refuses_same_source_and_destination(tmp_path):
    source = tmp_path / "legacy.db"
    _create_broken_legacy_database(source)

    with pytest.raises(DatabaseRecoveryError, match="different files"):
        recover_legacy_database(source, source)


def test_recovery_rejects_missing_repository_without_publishing_output(tmp_path):
    source = tmp_path / "invalid.db"
    destination = tmp_path / "recovered.db"
    connection = sqlite3.connect(source)
    connection.executescript(
        """
        CREATE TABLE repositories(id INTEGER PRIMARY KEY, name TEXT, path TEXT);
        CREATE TABLE scans(
            id INTEGER PRIMARY KEY, repository_id INTEGER, started_at TEXT,
            completed_at TEXT, finding_count INTEGER
        );
        CREATE TABLE findings(
            id INTEGER PRIMARY KEY, fingerprint TEXT, repository_id INTEGER,
            scan_id INTEGER, payload TEXT
        );
        CREATE TABLE audit_events(id INTEGER PRIMARY KEY, event TEXT, details TEXT);
        INSERT INTO findings VALUES (1, 'orphan', 999, 0, '{}');
        """
    )
    connection.close()

    with pytest.raises(DatabaseRecoveryError, match="no repository"):
        recover_legacy_database(source, destination)

    assert not destination.exists()


def test_recovery_reports_unusable_destination_directory_without_changing_source(
    tmp_path,
):
    source = tmp_path / "legacy.db"
    blocked_parent = tmp_path / "not-a-directory"
    _create_broken_legacy_database(source)
    blocked_parent.write_text("preserve", encoding="utf-8")
    original = source.read_bytes()

    with pytest.raises(DatabaseRecoveryError, match="Cannot create destination directory"):
        recover_legacy_database(source, blocked_parent / "recovered.db")

    assert source.read_bytes() == original
    assert blocked_parent.read_text(encoding="utf-8") == "preserve"
    assert not list(tmp_path.glob(".recovered.db.*.recovery"))
