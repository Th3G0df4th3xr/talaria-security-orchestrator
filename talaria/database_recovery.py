"""Copy and repair legacy SQLite databases without changing the source."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

from talaria.database import CURRENT_SCHEMA_VERSION, Database
from talaria.database_backup import copy_database, publish_file_no_overwrite


class DatabaseRecoveryError(RuntimeError):
    """Raised when a legacy database cannot be safely recovered."""


def recover_legacy_database(source: Path, destination: Path) -> dict[str, int | str]:
    """Recover a legacy database into a new file and migrate the copy to current.

    Orphaned findings are linked to explicit synthetic failed scans. The source is
    opened read-only, and the destination is created atomically without replacing
    an existing path.
    """
    temporary: Path | None = None
    try:
        source = Path(source).expanduser().resolve()
        destination = Path(destination).expanduser().resolve()
        if source == destination:
            raise DatabaseRecoveryError("Source and destination must be different files")
        if not source.is_file():
            raise DatabaseRecoveryError("Source database does not exist")
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise DatabaseRecoveryError("Cannot create destination directory") from exc
        if destination.exists():
            raise DatabaseRecoveryError(
                "Destination already exists; refusing to overwrite"
            )

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".recovery",
            dir=destination.parent,
        )
        temporary = Path(temporary_name)
        os.close(descriptor)
        temporary.unlink()

        copy_database(source, temporary)
        orphan_count, recovery_scans = _repair_orphaned_findings(temporary)
        Database(temporary)
        Database(temporary, initialize=False).audit(
            "database.legacy_recovery", {"recovered_findings": orphan_count}
        )
        if recovery_scans:
            with Database(temporary, initialize=False).transaction() as connection:
                for scan_id, finding_count, missing_scan_ids in recovery_scans:
                    connection.execute(
                        """UPDATE scans SET status = 'failed', error_summary = ?
                           WHERE id = ?""",
                        (
                            "Recovery record: original scan was missing; "
                            f"linked {finding_count} historical finding(s); "
                            f"missing scan IDs: {', '.join(map(str, missing_scan_ids))}",
                            scan_id,
                        ),
                    )
        healthy, version = Database.readiness(temporary)
        if not healthy or version != CURRENT_SCHEMA_VERSION:
            raise DatabaseRecoveryError("Recovered database failed integrity checks")

        # A hard link provides atomic no-overwrite publication on the same filesystem.
        publish_file_no_overwrite(temporary, destination)
        return {
            "destination": str(destination),
            "schema_version": CURRENT_SCHEMA_VERSION,
            "recovered_findings": orphan_count,
        }
    except DatabaseRecoveryError:
        raise
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
        raise DatabaseRecoveryError(f"Database recovery failed: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
            Path(f"{temporary}-journal").unlink(missing_ok=True)
            Path(f"{temporary}-wal").unlink(missing_ok=True)
            Path(f"{temporary}-shm").unlink(missing_ok=True)


def _repair_orphaned_findings(
    database_path: Path,
) -> tuple[int, list[tuple[int, int, tuple[int, ...]]]]:
    connection = sqlite3.connect(database_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not {"repositories", "scans", "findings", "audit_events"} <= tables:
            raise DatabaseRecoveryError("Source does not have the expected legacy schema")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != 0:
            raise DatabaseRecoveryError("Recovery is limited to schema version 0 databases")

        orphaned = connection.execute(
            """SELECT f.id, f.repository_id, f.scan_id
               FROM findings f LEFT JOIN scans s ON s.id = f.scan_id
               WHERE s.id IS NULL ORDER BY f.id"""
        ).fetchall()
        missing_repositories = connection.execute(
            """SELECT f.id FROM findings f
               LEFT JOIN repositories r ON r.id = f.repository_id
               WHERE r.id IS NULL LIMIT 1"""
        ).fetchone()
        if missing_repositories:
            raise DatabaseRecoveryError(
                "An orphaned finding also has no repository; manual review is required"
            )

        grouped: dict[int, list[sqlite3.Row]] = {}
        recovery_scans: list[tuple[int, int, tuple[int, ...]]] = []
        for row in orphaned:
            grouped.setdefault(row["repository_id"], []).append(row)

        with connection:
            for repository_id, findings in grouped.items():
                cursor = connection.execute(
                    """INSERT INTO scans(repository_id, completed_at, finding_count)
                       VALUES (?, CURRENT_TIMESTAMP, ?)""",
                    (repository_id, len(findings)),
                )
                scan_id = cursor.lastrowid
                missing_scan_ids = tuple(sorted({row["scan_id"] for row in findings}))
                recovery_scans.append((scan_id, len(findings), missing_scan_ids))
                for finding in findings:
                    connection.execute(
                        "UPDATE findings SET scan_id = ? WHERE id = ?",
                        (scan_id, finding["id"]),
                    )
        return len(orphaned), recovery_scans
    finally:
        connection.close()
