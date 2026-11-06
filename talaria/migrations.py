import sqlite3
from pathlib import Path


def migrate_to_v2(database_path: Path) -> None:
    """Migrate legacy TALARIA data to the v2 finding lifecycle schema."""
    connection = sqlite3.connect(database_path, timeout=10.0)
    connection.row_factory = sqlite3.Row

    try:
        version = connection.execute("PRAGMA user_version").fetchone()[0]

        if version >= 2:
            return

        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN IMMEDIATE")

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
