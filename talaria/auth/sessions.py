"""Secure refresh-token generation and hashing for TALARIA."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

REFRESH_TOKEN_BYTES = 48
REFRESH_TOKEN_LIFETIME = timedelta(days=30)


def generate_refresh_token() -> str:
    """Generate a cryptographically secure opaque refresh token."""
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    """Return a SHA-256 digest suitable for database storage."""
    if not isinstance(token, str):
        raise TypeError("Refresh token must be a string.")

    if not token:
        raise ValueError("Refresh token cannot be empty.")

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_refresh_token(token: str, stored_hash: str) -> bool:
    """Compare a refresh token against its stored digest."""
    import hmac

    if not isinstance(token, str) or not isinstance(stored_hash, str):
        return False

    if not token or not stored_hash:
        return False

    candidate = hash_refresh_token(token)

    return hmac.compare_digest(candidate, stored_hash)


def refresh_token_expiry(
    lifetime: timedelta = REFRESH_TOKEN_LIFETIME,
) -> datetime:
    """Calculate the UTC expiration timestamp for a refresh token."""
    if lifetime.total_seconds() <= 0:
        raise ValueError("Refresh-token lifetime must be positive.")

    return datetime.now(UTC) + lifetime
