"""Tests for TALARIA refresh-token security."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest

from talaria.auth.session_store import (
    RefreshSessionStore,
    RefreshTokenReuseError,
)
from talaria.auth.sessions import (
    generate_refresh_token,
    hash_refresh_token,
    refresh_token_expiry,
    verify_refresh_token,
)
from talaria.database import Database


def test_refresh_token_generation():
    token = generate_refresh_token()

    assert isinstance(token, str)
    assert len(token) >= 60


def test_refresh_tokens_are_unique():
    first = generate_refresh_token()
    second = generate_refresh_token()

    assert first != second


def test_refresh_token_hashing():
    token = generate_refresh_token()
    digest = hash_refresh_token(token)

    assert len(digest) == 64
    assert digest != token


def test_same_token_produces_same_hash():
    token = generate_refresh_token()

    assert hash_refresh_token(token) == hash_refresh_token(token)


def test_correct_refresh_token_verifies():
    token = generate_refresh_token()
    stored_hash = hash_refresh_token(token)

    assert verify_refresh_token(token, stored_hash) is True


def test_wrong_refresh_token_rejected():
    token = generate_refresh_token()
    stored_hash = hash_refresh_token(token)

    assert verify_refresh_token("wrong-token", stored_hash) is False


def test_empty_refresh_token_rejected():
    with pytest.raises(ValueError):
        hash_refresh_token("")


def test_non_string_refresh_token_rejected():
    with pytest.raises(TypeError):
        hash_refresh_token(None)


def test_refresh_token_expiry_is_in_future():
    expiry = refresh_token_expiry()

    assert expiry.tzinfo is not None
    assert expiry > datetime.now(UTC)


def test_non_positive_refresh_lifetime_rejected():
    with pytest.raises(ValueError):
        refresh_token_expiry(timedelta(seconds=0))


def test_database_session_stores_only_token_hash(tmp_path):
    store = RefreshSessionStore(Database(tmp_path / "talaria.db"))

    token, session = store.create("user-123")

    assert session.subject == "user-123"
    assert store.get_active(token) == session
    stored = store.database.execute(
        "SELECT token_hash FROM refresh_sessions WHERE id = ?", (session.id,)
    )[0]["token_hash"]
    assert stored == hash_refresh_token(token)
    assert token not in stored


def test_database_session_revocation_is_idempotent(tmp_path):
    store = RefreshSessionStore(Database(tmp_path / "talaria.db"))
    token, _ = store.create("user-123")

    assert store.revoke(token) is True
    assert store.revoke(token) is False
    assert store.get_active(token) is None


def test_rotation_invalidates_previous_token_and_preserves_family(tmp_path):
    store = RefreshSessionStore(Database(tmp_path / "talaria.db"))
    original, original_session = store.create("user-123")

    rotated = store.rotate(original)

    assert rotated is not None
    replacement, replacement_session = rotated
    assert store.get_active(original) is None
    assert store.get_active(replacement) == replacement_session
    assert replacement_session.family_id == original_session.family_id
    assert replacement_session.subject == original_session.subject


def test_reuse_of_rotated_token_revokes_entire_family(tmp_path):
    store = RefreshSessionStore(Database(tmp_path / "talaria.db"))
    original, _ = store.create("user-123")
    replacement, _ = store.rotate(original)

    with pytest.raises(RefreshTokenReuseError):
        store.rotate(original)

    assert store.get_active(replacement) is None
    rows = store.database.execute(
        "SELECT compromised_at FROM refresh_sessions WHERE token_hash IN (?, ?)",
        (hash_refresh_token(original), hash_refresh_token(replacement)),
    )
    assert len(rows) == 2
    assert all(row["compromised_at"] is not None for row in rows)


def test_unknown_refresh_token_cannot_be_rotated(tmp_path):
    store = RefreshSessionStore(Database(tmp_path / "talaria.db"))

    assert store.rotate("unknown-token") is None


def test_revoke_subject_revokes_all_active_sessions(tmp_path):
    store = RefreshSessionStore(Database(tmp_path / "talaria.db"))
    first, _ = store.create("user-123")
    second, _ = store.create("user-123")
    other, _ = store.create("user-456")

    assert store.revoke_subject("user-123") == 2
    assert store.get_active(first) is None
    assert store.get_active(second) is None
    assert store.get_active(other) is not None


def test_database_session_rejects_invalid_subject_and_lifetime(tmp_path):
    store = RefreshSessionStore(Database(tmp_path / "talaria.db"))

    with pytest.raises(ValueError):
        store.create(" ")
    with pytest.raises(ValueError):
        store.create("user-123", timedelta(seconds=0))




def test_concurrent_refresh_reuse_revokes_the_rotated_family(tmp_path):
    path = tmp_path / "concurrent-refresh.db"
    original, _ = RefreshSessionStore(Database(path)).create("user-123")
    barrier = Barrier(2)

    def rotate():
        store = RefreshSessionStore(Database(path, initialize=False))
        barrier.wait()
        try:
            return store.rotate(original)
        except RefreshTokenReuseError:
            return "reused"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: rotate(), range(2)))

    rotations = [result for result in results if result != "reused"]
    assert len(rotations) == 1
    assert results.count("reused") == 1
    replacement, _ = rotations[0]
    store = RefreshSessionStore(Database(path, initialize=False))
    assert store.get_active(replacement) is None
    rows = store.database.execute(
        "SELECT compromised_at FROM refresh_sessions ORDER BY created_at, id"
    )
    assert len(rows) == 2
    assert all(row["compromised_at"] is not None for row in rows)
