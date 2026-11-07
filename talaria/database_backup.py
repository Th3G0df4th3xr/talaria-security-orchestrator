"""Consistent SQLite backup and copy operations with no-overwrite publication."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path


class DatabaseBackupError(RuntimeError):
    """Raised when a database copy cannot be safely created or verified."""


def publish_file_no_overwrite(temporary: Path, destination: Path) -> None:
    """Durably publish a prepared file atomically without replacing a path."""
    temporary = Path(temporary)
    destination = Path(destination)
    file_fd = os.open(temporary, os.O_RDONLY)
    try:
        os.fsync(file_fd)
    finally:
        os.close(file_fd)

    directory_fd = os.open(
        destination.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.link(temporary, destination)
        try:
            # The directory sync commits the atomically published destination.
            os.fsync(directory_fd)
        except OSError as sync_error:
            try:
                os.unlink(destination)
            except OSError as rollback_error:
                raise DatabaseBackupError(
                    "Cannot synchronize the published database; its destination "
                    "may still exist"
                ) from rollback_error
            try:
                os.fsync(directory_fd)
            except OSError:
                # Report failure; the destination is absent now, but its rollback
                # could not be confirmed durable across a sudden power loss.
                pass
            raise sync_error
    finally:
        os.close(directory_fd)
    temporary.unlink()


def copy_database(source: Path, destination: Path) -> dict[str, int | str]:
    """Create a consistent verified database copy without changing the source."""
    source = Path(source).expanduser().resolve()
    destination = Path(destination).expanduser().resolve()
    if source == destination:
        raise DatabaseBackupError("Source and destination must be different files")
    if not source.is_file():
        raise DatabaseBackupError("Source database does not exist")
    temporary: Path | None = None
    descriptor: int | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise DatabaseBackupError(
                "Destination already exists; refusing to overwrite"
            )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".backup", dir=destination.parent
        )
        temporary = Path(temporary_name)
        os.close(descriptor)
        descriptor = None
    except DatabaseBackupError:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise DatabaseBackupError("Cannot prepare database copy destination") from exc
    try:
        source_connection = sqlite3.connect(
            f"{source.as_uri()}?mode=ro", uri=True, timeout=10.0
        )
        destination_connection = sqlite3.connect(temporary, timeout=10.0)
        try:
            source_connection.backup(destination_connection)
        finally:
            destination_connection.close()
            source_connection.close()

        check = sqlite3.connect(f"{temporary.as_uri()}?mode=ro", uri=True)
        try:
            integrity = check.execute("PRAGMA quick_check").fetchone()
            version = check.execute("PRAGMA user_version").fetchone()
            tables = {
                row[0]
                for row in check.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        finally:
            check.close()
        if integrity is None or integrity[0] != "ok" or version is None:
            raise DatabaseBackupError("Database copy failed integrity verification")
        if not {"repositories", "scans", "findings", "audit_events"} <= tables:
            raise DatabaseBackupError("Source is not a TALARIA database")

        temporary.chmod(0o600)
        publish_file_no_overwrite(temporary, destination)
        return {"destination": str(destination), "schema_version": version[0]}
    except DatabaseBackupError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise DatabaseBackupError(f"Database copy failed: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
            Path(f"{temporary}-journal").unlink(missing_ok=True)
            Path(f"{temporary}-wal").unlink(missing_ok=True)
            Path(f"{temporary}-shm").unlink(missing_ok=True)


def backup_database(source: Path, destination: Path) -> dict[str, int | str]:
    """Alias with backup terminology for operator-facing use."""
    return copy_database(source, destination)
