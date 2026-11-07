"""JWT access-token creation and validation for TALARIA."""

import os
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from jwt.exceptions import InvalidTokenError

from talaria.security.secrets import SecretFileError, read_secret_file

ALGORITHM = "HS256"
ISSUER = "talaria"
AUDIENCE = "talaria-api"
ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)


class TokenError(ValueError):
    """Raised when a JWT is invalid or cannot be processed."""


def get_jwt_secret() -> str:
    """Load the JWT signing secret from a mounted file or environment."""
    secret = os.getenv("TALARIA_JWT_SECRET")
    secret_file = os.getenv("TALARIA_JWT_SECRET_FILE")
    if secret_file:
        try:
            secret = read_secret_file(
                secret_file, label="JWT signing", allow_empty=True
            )
        except SecretFileError as exc:
            raise TokenError("Cannot read the configured JWT secret file.") from exc

    if not secret or len(secret.encode("utf-8")) < 32:
        raise TokenError(
            "TALARIA_JWT_SECRET must contain at least 32 bytes."
        )

    return secret


def create_access_token(
    subject: str,
    secret: str | None = None,
    expires_in: timedelta = ACCESS_TOKEN_LIFETIME,
) -> str:
    """Create a signed JWT access token."""
    signing_secret = secret or get_jwt_secret()

    if len(signing_secret.encode("utf-8")) < 32:
        raise TokenError("JWT signing secret must contain at least 32 bytes.")

    if not subject or not subject.strip():
        raise TokenError("Token subject cannot be empty.")

    if expires_in.total_seconds() <= 0:
        raise TokenError("Token lifetime must be positive.")

    now = datetime.now(UTC)

    payload = {
        "sub": subject,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "jti": secrets.token_urlsafe(16),
        "type": "access",
    }

    return jwt.encode(payload, signing_secret, algorithm=ALGORITHM)


def decode_access_token(
    token: str,
    secret: str | None = None,
) -> dict:
    """Validate a JWT and return its claims."""
    signing_secret = secret or get_jwt_secret()

    if len(signing_secret.encode("utf-8")) < 32:
        raise TokenError("JWT signing secret must contain at least 32 bytes.")

    try:
        claims = jwt.decode(
            token,
            signing_secret,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": [
                    "sub",
                    "iss",
                    "aud",
                    "iat",
                    "nbf",
                    "exp",
                    "jti",
                    "type",
                ]
            },
        )

        if claims.get("type") != "access":
            raise TokenError("Invalid token type.")

        return claims

    except InvalidTokenError as exc:
        raise TokenError("Invalid or expired access token.") from exc
