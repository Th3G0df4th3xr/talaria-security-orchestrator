import sqlite3

import pytest

from talaria.migrations import migrate_to_v2


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
