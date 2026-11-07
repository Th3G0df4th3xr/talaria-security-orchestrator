"""Upgrade a SQLite copy and publish it only after readiness succeeds."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

from talaria.database import CURRENT_SCHEMA_VERSION, Database
from talaria.database_backup import (
    DatabaseBackupError,
    copy_database,
    publish_file_no_overwrite,
)


class DatabaseUpgradeError(RuntimeError):
    """Raised when an upgraded copy cannot be safely produced."""


def upgrade_database_copy(source: Path, destination: Path) -> dict[str, int | str]:
    """Migrate a verified SQLite snapshot without changing its source file."""
    source = Path(source).expanduser().resolve()
    destination = Path(destination).expanduser().resolve()
    if source == destination:
        raise DatabaseUpgradeError("Source and destination must be different files")
    if not source.is_file():
        raise DatabaseUpgradeError("Source database does not exist")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DatabaseUpgradeError("Cannot create destination directory") from exc
    if destination.exists():
        raise DatabaseUpgradeError("Destination already exists; refusing to overwrite")

    temporary_name = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".upgrade", dir=destination.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        temporary.unlink()
    except OSError as exc:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
        raise DatabaseUpgradeError("Cannot create temporary upgrade file") from exc
    try:
        copied = copy_database(source, temporary)
        source_version = copied["schema_version"]
        Database(temporary)
        healthy, version = Database.readiness(temporary)
        if not healthy or version != CURRENT_SCHEMA_VERSION:
            raise DatabaseUpgradeError("Upgraded database copy failed readiness checks")
        publish_file_no_overwrite(temporary, destination)
        return {
            "source": str(source),
            "destination": str(destination),
            "source_schema_version": source_version,
            "schema_version": version,
        }
    except DatabaseUpgradeError:
        raise
    except (DatabaseBackupError, OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
        raise DatabaseUpgradeError(f"Database copy upgrade failed: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)
        Path(f"{temporary}-journal").unlink(missing_ok=True)
        Path(f"{temporary}-wal").unlink(missing_ok=True)
        Path(f"{temporary}-shm").unlink(missing_ok=True)
