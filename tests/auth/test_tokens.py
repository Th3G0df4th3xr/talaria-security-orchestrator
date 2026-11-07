"""Tests for TALARIA JWT access tokens."""

from datetime import timedelta

import pytest

from talaria.auth.tokens import (
    TokenError,
    create_access_token,
    decode_access_token,
    get_jwt_secret,
)

TEST_SECRET = "Talaria-Test-Secret-2026-At-Least-32-Bytes!"


def test_jwt_secret_can_be_loaded_from_a_mounted_file(tmp_path, monkeypatch):
    secret_file = tmp_path / "jwt-secret"
    secret_file.write_text(f"{TEST_SECRET}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    monkeypatch.delenv("TALARIA_JWT_SECRET", raising=False)
    monkeypatch.setenv("TALARIA_JWT_SECRET_FILE", str(secret_file))

    assert get_jwt_secret() == TEST_SECRET


def test_unreadable_jwt_secret_file_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("TALARIA_JWT_SECRET_FILE", str(tmp_path / "missing"))

    with pytest.raises(TokenError, match="secret file"):
        get_jwt_secret()


def test_create_access_token():
    token = create_access_token("user-123", TEST_SECRET)

    assert isinstance(token, str)
    assert len(token) > 50


def test_decode_valid_access_token():
    token = create_access_token("user-123", TEST_SECRET)

    claims = decode_access_token(token, TEST_SECRET)

    assert claims["sub"] == "user-123"
    assert claims["iss"] == "talaria"
    assert claims["aud"] == "talaria-api"
    assert claims["type"] == "access"


def test_token_contains_required_security_claims():
    token = create_access_token("user-123", TEST_SECRET)

    claims = decode_access_token(token, TEST_SECRET)

    assert "iat" in claims
    assert "nbf" in claims
    assert "exp" in claims
    assert "jti" in claims


def test_token_has_unique_jti():
    first = create_access_token("user-123", TEST_SECRET)
    second = create_access_token("user-123", TEST_SECRET)

    first_claims = decode_access_token(first, TEST_SECRET)
    second_claims = decode_access_token(second, TEST_SECRET)

    assert first_claims["jti"] != second_claims["jti"]


def test_wrong_secret_rejected():
    token = create_access_token("user-123", TEST_SECRET)

    with pytest.raises(TokenError):
        decode_access_token(
            token,
            "Another-Secret-That-Is-Definitely-32-Bytes!",
        )


def test_negative_token_lifetime_rejected():
    with pytest.raises(TokenError, match="lifetime must be positive"):
        create_access_token(
            "user-123",
            TEST_SECRET,
            expires_in=timedelta(seconds=-1),
        )


def test_short_secret_rejected():
    with pytest.raises(TokenError):
        create_access_token("user-123", "short-secret")


def test_empty_subject_rejected():
    with pytest.raises(TokenError):
        create_access_token("", TEST_SECRET)


def test_non_positive_lifetime_rejected():
    with pytest.raises(TokenError):
        create_access_token(
            "user-123",
            TEST_SECRET,
            expires_in=timedelta(seconds=0),
        )
