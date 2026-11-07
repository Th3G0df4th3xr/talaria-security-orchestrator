"""Tests for Argon2id password security."""

import pytest
from argon2 import PasswordHasher

from talaria.auth.passwords import (
    hash_password,
    password_needs_rehash,
    verify_password,
)


def test_password_is_hashed_with_argon2id():
    password_hash = hash_password("Talaria-Secure-Password-2026")

    assert password_hash.startswith("$argon2id$")
    assert password_hash != "Talaria-Secure-Password-2026"


def test_correct_password_verifies():
    password = "Talaria-Secure-Password-2026"
    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


def test_incorrect_password_is_rejected():
    password_hash = hash_password("Correct-Password-123!")

    assert verify_password("Wrong-Password-123!", password_hash) is False


def test_invalid_hash_is_rejected():
    assert verify_password("some-password", "not-a-valid-hash") is False


def test_empty_password_is_rejected():
    with pytest.raises(ValueError):
        hash_password("")


def test_non_string_password_is_rejected():
    with pytest.raises(TypeError):
        hash_password(None)


def test_current_hash_does_not_need_rehash():
    password_hash = hash_password("Talaria-Secure-Password-2026")

    assert password_needs_rehash(password_hash) is False


def test_weak_hash_needs_rehash():
    weak_hasher = PasswordHasher(
        time_cost=1,
        memory_cost=1024,
        parallelism=1,
    )
    weak_hash = weak_hasher.hash("Talaria-Secure-Password-2026")

    assert password_needs_rehash(weak_hash) is True
