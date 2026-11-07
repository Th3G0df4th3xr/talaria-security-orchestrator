import argparse
import getpass
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import psycopg

from talaria.auth.service import AuthenticationError, AuthService
from talaria.config import database_path
from talaria.database import CURRENT_SCHEMA_VERSION, Database
from talaria.database_backup import DatabaseBackupError, backup_database, copy_database
from talaria.database_postgres_backup import (
    PostgresBackupError,
    backup_postgres_database,
    restore_postgres_database,
)
from talaria.database_recovery import DatabaseRecoveryError, recover_legacy_database
from talaria.database_transfer import DatabaseTransferError, transfer_sqlite_to_postgres
from talaria.database_upgrade import upgrade_database_copy
from talaria.repositories.service import RepositoryError, RepositoryService
from talaria.scanning.service import ScanService


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="talaria", description="Local-first security orchestration MVP"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    bootstrap = sub.add_parser(
        "bootstrap-admin", help="Create the initial platform administrator"
    )
    bootstrap.add_argument("--email", required=True)
    bootstrap.add_argument("--organization", required=True)
    register = sub.add_parser("register", help="Register a local Git repository")
    register.add_argument("path")
    scan = sub.add_parser("scan", help="Scan a registered/authorized local Git repository")
    scan.add_argument("path")
    scan.add_argument("--profile", default="baseline")
    scan.add_argument("--json-out")
    backup = sub.add_parser("backup-db", help="Create and verify a consistent SQLite backup")
    backup.add_argument("--source")
    backup.add_argument("--output", required=True)
    restore = sub.add_parser(
        "restore-db", help="Restore SQLite or PostgreSQL backup data to a new target"
    )
    restore.add_argument("--source", required=True)
    restore.add_argument("--output")
    restore.add_argument("--target-url")
    upgrade = sub.add_parser(
        "upgrade-db",
        help="Back up/apply database migrations or initialize an empty PostgreSQL schema",
    )
    upgrade.add_argument(
        "--backup-output",
        help="Required custom-format backup path when upgrading an existing PostgreSQL schema",
    )
    upgrade.add_argument(
        "--copy-to",
        help="Upgrade a copy of the configured SQLite database to this new path",
    )
    recover = sub.add_parser(
        "recover-legacy-db",
        help="Recover a schema-v0 SQLite database into a new migrated file",
    )
    recover.add_argument("--source", required=True)
    recover.add_argument("--output", required=True)
    transfer = sub.add_parser(
        "import-sqlite-db",
        help="Copy a verified current-version SQLite database into an empty PostgreSQL database",
    )
    transfer.add_argument("--source", required=True)
    args = parser.parse_args()
    if args.command == "import-sqlite-db":
        target_url = database_path()
        if not isinstance(target_url, str) or not target_url.startswith(
            ("postgresql://", "postgres://")
        ):
            parser.exit(2, "talaria: error: TALARIA_DATABASE_URL must select PostgreSQL\n")
        try:
            result = transfer_sqlite_to_postgres(
                Path(args.source), Database(target_url, initialize=False)
            )
            print(json.dumps(result, indent=2))
        except DatabaseTransferError as exc:
            parser.exit(2, f"talaria: error: {exc}\n")
        return
    if args.command == "recover-legacy-db":
        try:
            result = recover_legacy_database(Path(args.source), Path(args.output))
            print(json.dumps(result, indent=2))
        except DatabaseRecoveryError as exc:
            parser.exit(2, f"talaria: error: {exc}\n")
        return
    if args.command in {"backup-db", "restore-db"}:
        try:
            if args.command == "restore-db":
                if args.target_url:
                    if args.output:
                        parser.error("--output is only valid for SQLite restore")
                    active_url = database_path()
                    result = restore_postgres_database(
                        Path(args.source),
                        args.target_url,
                        active_url if isinstance(active_url, str) else None,
                    )
                else:
                    if not args.output:
                        parser.error("--output is required for SQLite restore")
                    result = copy_database(Path(args.source), Path(args.output))
            else:
                source_value = args.source if args.source else database_path()
                if isinstance(source_value, str) and source_value.startswith(
                    ("postgresql://", "postgres://")
                ):
                    result = backup_postgres_database(source_value, Path(args.output))
                else:
                    result = backup_database(Path(source_value), Path(args.output))
            print(json.dumps(result, indent=2))
        except DatabaseBackupError as exc:
            parser.exit(2, f"talaria: error: {exc}\n")
        except PostgresBackupError as exc:
            parser.exit(2, f"talaria: error: {exc}\n")
        return

    try:
        if args.command == "upgrade-db":
            path = database_path()
            is_postgres = isinstance(path, str) and path.startswith(
                ("postgresql://", "postgres://")
            )
            if args.copy_to:
                if is_postgres:
                    parser.error("--copy-to is only supported for SQLite databases")
                if args.backup_output:
                    parser.error("--copy-to cannot be combined with --backup-output")
                result = upgrade_database_copy(path, Path(args.copy_to))
                print(json.dumps(result, indent=2))
                return
            if is_postgres:
                version = Database.postgres_schema_version(path)
                if version is not None and version < CURRENT_SCHEMA_VERSION:
                    if not args.backup_output:
                        parser.error(
                            "--backup-output is required before upgrading an "
                            "existing PostgreSQL schema"
                        )
                    backup_result = backup_postgres_database(
                        path, Path(args.backup_output)
                    )
                else:
                    backup_result = None
                db = Database(path, initialize=True)
            elif args.backup_output:
                parser.error("--backup-output is only valid for PostgreSQL upgrades")
            elif path.is_file():
                timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
                backup_path = path.with_name(f"{path.name}.pre-migration-{timestamp}.bak")
                backup_result = backup_database(path, backup_path)
                db = Database(path, initialize=True)
            else:
                backup_result = None
                db = Database(path, initialize=True)
            result = {
                "database": str(db.path),
                "schema_version": CURRENT_SCHEMA_VERSION,
                "backup": backup_result,
            }
            print(json.dumps(result, indent=2))
            return
        else:
            db = Database(database_path(), initialize=False)

        if args.command == "bootstrap-admin":
            password = getpass.getpass("New administrator password: ")
            confirmation = getpass.getpass("Confirm password: ")
            if password != confirmation:
                parser.exit(2, "talaria: error: passwords do not match\n")
            result = AuthService(db).bootstrap(
                args.email, password, args.organization
            )
        elif args.command == "register":
            result = RepositoryService(db).register(args.path)
        else:
            result = ScanService(db).scan(args.path, args.profile)
            if args.json_out:
                target = Path(args.json_out).expanduser()
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2, default=str))
    except (
        RepositoryError,
        AuthenticationError,
        DatabaseBackupError,
        sqlite3.Error,
        psycopg.Error,
        RuntimeError,
        ValueError,
    ) as exc:
        parser.exit(2, f"talaria: error: {exc}\n")


if __name__ == "__main__":
    main()
