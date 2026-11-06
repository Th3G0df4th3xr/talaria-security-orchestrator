import sqlite3

import pytest

from talaria.database import Database


def test_database_initializes(isolated_db):
    db = Database(isolated_db / "db.sqlite")
    assert db.execute("SELECT name FROM sqlite_master WHERE type='table'")


def test_foreign_keys_enabled_on_every_connection(isolated_db):
    db = Database(isolated_db / "db.sqlite")

    result = db.execute("PRAGMA foreign_keys")

    assert result[0]["foreign_keys"] == 1


def test_transaction_rolls_back_on_error(isolated_db):
    db = Database(isolated_db / "db.sqlite")

    with pytest.raises(RuntimeError):
        with db.transaction() as connection:
            connection.execute(
                "INSERT INTO repositories(name, path) VALUES (?, ?)",
                ("rollback-test", "/tmp/rollback-test"),
            )
            raise RuntimeError("Simulated failure")

    rows = db.execute(
        "SELECT * FROM repositories WHERE name = ?",
        ("rollback-test",),
    )

    assert rows == []


def test_transaction_closes_connection(isolated_db):
    db = Database(isolated_db / "db.sqlite")

    with db.transaction() as connection:
        connection.execute(
            "INSERT INTO repositories(name, path) VALUES (?, ?)",
            ("closure-test", "/tmp/closure-test"),
        )

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
