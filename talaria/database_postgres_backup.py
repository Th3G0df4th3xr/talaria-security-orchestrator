"""Verified PostgreSQL custom-format backup and empty-database restore helpers."""

from __future__ import annotations

import os
import subprocess
import tempfile
from getpass import getuser
from pathlib import Path

from psycopg.conninfo import make_conninfo

from talaria.database import (
    CURRENT_SCHEMA_VERSION,
    Database,
    postgres_connection_parameters,
)
from talaria.database_backup import publish_file_no_overwrite
from talaria.security.secrets import SecretFileError, read_secret_file


class PostgresBackupError(RuntimeError):
    """Raised when a PostgreSQL dump or restore cannot be verified safely."""


def _connection_parameters(database_url: str) -> dict[str, str]:
    try:
        return postgres_connection_parameters(database_url)
    except ValueError as exc:
        raise PostgresBackupError(str(exc)) from exc


def _pgpass_value(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace(":", "\\:")
        .replace("\r", "")
        .replace("\n", "")
    )


def _credential_file(parameters: dict[str, str]) -> tuple[str | None, Path | None]:
    password_file = os.getenv("TALARIA_POSTGRES_PASSWORD_FILE")
    if password_file:
        try:
            password = read_secret_file(
                password_file, label="PostgreSQL password"
            )
        except SecretFileError as exc:
            raise PostgresBackupError("Cannot read PostgreSQL password secret") from exc
    else:
        password = parameters.get("password", "")
    if not password:
        return None, None

    host = parameters.get("host", "localhost")
    if host.startswith("/"):
        host = "localhost"
    fields = (
        host,
        parameters.get("port", "5432"),
        parameters.get("dbname", "*"),
        parameters.get("user", "*"),
        password,
    )
    descriptor, name = tempfile.mkstemp(prefix="talaria-pgpass-")
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        stream = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor = -1
        with stream:
            stream.write(":".join(_pgpass_value(item) for item in fields) + "\n")
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)
        raise PostgresBackupError("Cannot create temporary PostgreSQL credentials") from exc
    return str(path), path


def _run(
    command: list[str], environment: dict[str, str], *, stdin=None
) -> subprocess.CompletedProcess:
    if not command or command[0] not in {"pg_dump", "pg_restore"}:
        raise PostgresBackupError("Unexpected PostgreSQL client command")
    try:
        # Commands are fixed argv lists; user values are never shell-expanded.
        return subprocess.run(  # noqa: S603
            command,
            input=stdin,
            capture_output=True,
            env=environment,
            timeout=3600,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise PostgresBackupError(
            "PostgreSQL client utilities pg_dump and pg_restore must be installed"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise PostgresBackupError("PostgreSQL backup operation timed out") from exc
    except OSError as exc:
        raise PostgresBackupError("PostgreSQL client utility could not run") from exc


def backup_postgres_database(database_url: str, destination: Path) -> dict:
    """Write a verified custom-format dump atomically without overwriting."""
    parameters = _connection_parameters(database_url)
    temporary: Path | None = None
    descriptor: int | None = None
    try:
        destination = Path(destination).expanduser().resolve()
        if destination.exists():
            raise PostgresBackupError("Backup destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temp_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".dump", dir=destination.parent
        )
        temporary = Path(temp_name)
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        descriptor = None
    except PostgresBackupError:
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
        raise PostgresBackupError("Cannot prepare PostgreSQL backup destination") from exc

    passfile = None
    try:
        passfile_value, passfile = _credential_file(parameters)
        environment = os.environ.copy()
        environment.pop("PGPASSWORD", None)
        if passfile_value:
            environment["PGPASSFILE"] = passfile_value
        safe_conninfo = make_conninfo(
            **{key: value for key, value in parameters.items() if key != "password"}
        )
        result = _run(
            [
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-acl",
                f"--file={temporary}",
                f"--dbname={safe_conninfo}",
            ],
            environment,
        )
        if result.returncode:
            raise PostgresBackupError("pg_dump failed")
        verify = _run(["pg_restore", "--list", str(temporary)], environment)
        if verify.returncode:
            raise PostgresBackupError("PostgreSQL archive verification failed")
        publish_file_no_overwrite(temporary, destination)
        return {"destination": str(destination), "format": "postgres-custom"}
    except PostgresBackupError:
        raise
    except OSError as exc:
        raise PostgresBackupError("PostgreSQL backup could not be published") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if passfile is not None:
            passfile.unlink(missing_ok=True)


def restore_postgres_database(source: Path, target_url: str, active_url: str | None = None) -> dict:
    """Restore an archive atomically into a separate empty PostgreSQL database."""
    source = Path(source).expanduser().resolve()
    if not source.is_file():
        raise PostgresBackupError("PostgreSQL backup file does not exist")
    target_parameters = _connection_parameters(target_url)
    if active_url:
        active_parameters = _connection_parameters(active_url)
        def identity(parameters):
            user = parameters.get("user", getuser())
            return (
                parameters.get("host", "localhost"),
                parameters.get("port", "5432"),
                parameters.get("dbname", user),
                user,
            )

        if identity(target_parameters) == identity(active_parameters):
            raise PostgresBackupError("Restore target must differ from the active database")

    parameters = target_parameters
    database = Database(target_url, initialize=False)
    try:
        with database.connect() as connection:
            state = connection.execute(
                "SELECT to_regclass('public.schema_migrations') AS table_name"
            ).fetchone()
            public_objects = connection.execute(
                "SELECT "
                "(SELECT COUNT(*) FROM pg_class AS c "
                "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public') + "
                "(SELECT COUNT(*) FROM pg_proc AS p "
                "JOIN pg_namespace AS n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'public') + "
                "(SELECT COUNT(*) FROM pg_type AS t "
                "JOIN pg_namespace AS n ON n.oid = t.typnamespace "
                "WHERE n.nspname = 'public' AND t.typtype IN ('d', 'e', 'r', 'm')) "
                "AS count"
            ).fetchone()["count"]
            custom_schemas = connection.execute(
                "SELECT COUNT(*) AS count FROM pg_namespace "
                "WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public') "
                "AND left(nspname, 3) <> 'pg_'"
            ).fetchone()["count"]
        if state["table_name"] is not None or public_objects or custom_schemas:
            raise PostgresBackupError(
                "Restore target database must have no user-created schemas or objects"
            )
    except PostgresBackupError:
        raise
    except Exception as exc:
        raise PostgresBackupError("Cannot verify PostgreSQL restore target") from exc

    passfile = None
    try:
        passfile_value, passfile = _credential_file(parameters)
        environment = os.environ.copy()
        environment.pop("PGPASSWORD", None)
        if passfile_value:
            environment["PGPASSFILE"] = passfile_value
        safe_conninfo = make_conninfo(
            **{key: value for key, value in parameters.items() if key != "password"}
        )
        listing = _run(["pg_restore", "--list", str(source)], environment)
        if listing.returncode:
            raise PostgresBackupError("PostgreSQL archive verification failed")
        result = _run(
            [
                "pg_restore",
                "--exit-on-error",
                "--single-transaction",
                "--no-owner",
                "--no-acl",
                f"--dbname={safe_conninfo}",
                str(source),
            ],
            environment,
        )
        if result.returncode:
            raise PostgresBackupError("PostgreSQL restore failed")
        healthy, version = Database.readiness(target_url)
        if not healthy or version != CURRENT_SCHEMA_VERSION:
            raise PostgresBackupError("Restored PostgreSQL database failed readiness checks")
        return {"source": str(source), "schema_version": version, "target": "ready"}
    finally:
        if passfile is not None:
            passfile.unlink(missing_ok=True)
