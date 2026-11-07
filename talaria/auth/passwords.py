"""Secure password hashing and verification using Argon2id."""

from argon2 import PasswordHasher
from argon2.exceptions import (
    HashingError,
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

# Argon2id with secure default parameters.
_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        raise ValueError("Password cannot be empty.")

    if len(password.encode("utf-8")) > 1024:
        raise ValueError("Password cannot exceed 1024 bytes.")

    try:
        return _password_hasher.hash(password)
    except HashingError as exc:
        raise RuntimeError("Password hashing failed.") from exc


def verify_password(password: str, encoded_hash: str) -> bool:
    """Verify a password against its stored Argon2id hash."""
    if not isinstance(password, str) or not isinstance(encoded_hash, str):
        return False

    try:
        return _password_hasher.verify(encoded_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(encoded_hash: str) -> bool:
    """Check whether a stored hash needs updated Argon2 parameters."""
    if not isinstance(encoded_hash, str):
        return True

    try:
        return _password_hasher.check_needs_rehash(encoded_hash)
    except (VerificationError, InvalidHashError):
        return True
