import os
from pathlib import Path

import pytest

from talaria.config import (
    allowed_repository_roots,
    max_file_bytes,
    validate_runtime_configuration,
)


def test_allowed_repository_roots_default_to_current_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TALARIA_ALLOWED_REPOSITORY_ROOTS", raising=False)

    assert allowed_repository_roots() == (Path(tmp_path).resolve(),)


def test_allowed_repository_roots_parse_path_separator_list(monkeypatch, tmp_path):
    one = tmp_path / "one"
    two = tmp_path / "two"
    monkeypatch.setenv(
        "TALARIA_ALLOWED_REPOSITORY_ROOTS",
        f"{one}{os.pathsep}{two}",
    )

    assert allowed_repository_roots() == (one.resolve(), two.resolve())


def test_allowed_repository_roots_reject_empty_configuration(monkeypatch):
    monkeypatch.setenv("TALARIA_ALLOWED_REPOSITORY_ROOTS", "")

    with pytest.raises(ValueError, match="cannot be empty"):
        allowed_repository_roots()


@pytest.mark.parametrize("value", ["not-a-number", "0", "1023", "50000001"])
def test_max_file_bytes_rejects_invalid_or_unsafe_limits(monkeypatch, value):
    monkeypatch.setenv("TALARIA_MAX_FILE_BYTES", value)

    with pytest.raises(ValueError, match="TALARIA_MAX_FILE_BYTES"):
        max_file_bytes()


def test_max_file_bytes_accepts_documented_bounds(monkeypatch):
    monkeypatch.setenv("TALARIA_MAX_FILE_BYTES", "50000000")

    assert max_file_bytes() == 50_000_000


def _minimal_runtime_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("TALARIA_JWT_SECRET", "unit-test-signing-secret-32-bytes-minimum")
    monkeypatch.delenv("TALARIA_JWT_SECRET_FILE", raising=False)
    monkeypatch.setenv("TALARIA_ALLOWED_REPOSITORY_ROOTS", str(tmp_path))
    for name in (
        "TALARIA_DATABASE_URL",
        "TALARIA_DATABASE_TRUSTED_HOSTS",
        "TALARIA_MAX_FILE_BYTES",
        "TALARIA_BOOTSTRAP_TOKEN_FILE",
        "TALARIA_METRICS_TOKEN_FILE",
        "GITHUB_WEBHOOK_SECRET_FILE",
        "TALARIA_AI_ENABLED",
        "TALARIA_AI_SEND_SOURCE",
        "TALARIA_AI_TIMEOUT_SECONDS",
        "TALARIA_LLM_API_KEY",
        "TALARIA_LLM_API_KEY_FILE",
        "TALARIA_LLM_BASE_URL",
        "TALARIA_LLM_MODEL",
        "GITHUB_APP_ID",
        "GITHUB_INSTALLATION_ID",
        "GITHUB_APP_PRIVATE_KEY",
        "GITHUB_APP_PRIVATE_KEY_PATH",
        "PGSSLMODE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_runtime_configuration_accepts_valid_minimal_settings(monkeypatch, tmp_path):
    _minimal_runtime_environment(monkeypatch, tmp_path)

    validate_runtime_configuration()


def test_runtime_configuration_requires_valid_jwt_secret(monkeypatch, tmp_path):
    _minimal_runtime_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("TALARIA_JWT_SECRET", "short")

    with pytest.raises(ValueError, match="JWT signing configuration"):
        validate_runtime_configuration()


def test_runtime_configuration_rejects_nonexistent_repository_root(
    monkeypatch, tmp_path
):
    _minimal_runtime_environment(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "TALARIA_ALLOWED_REPOSITORY_ROOTS", str(tmp_path / "missing-root")
    )

    with pytest.raises(ValueError, match="must be a directory"):
        validate_runtime_configuration()


def test_runtime_configuration_rejects_source_sharing_without_ai(monkeypatch, tmp_path):
    _minimal_runtime_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("TALARIA_AI_SEND_SOURCE", "true")

    with pytest.raises(ValueError, match="requires TALARIA_AI_ENABLED"):
        validate_runtime_configuration()


def test_runtime_configuration_rejects_invalid_ai_boolean(monkeypatch, tmp_path):
    _minimal_runtime_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("TALARIA_AI_ENABLED", "sometimes")

    with pytest.raises(ValueError, match="AI integration configuration"):
        validate_runtime_configuration()


def test_runtime_configuration_rejects_incomplete_enabled_ai(monkeypatch, tmp_path):
    _minimal_runtime_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("TALARIA_AI_ENABLED", "true")

    with pytest.raises(ValueError, match="AI integration configuration"):
        validate_runtime_configuration()


def test_runtime_configuration_rejects_partial_github_app(monkeypatch, tmp_path):
    _minimal_runtime_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("GITHUB_APP_ID", "123")

    with pytest.raises(ValueError, match="must include app, installation, and key"):
        validate_runtime_configuration()


def test_runtime_configuration_rejects_plaintext_remote_postgres(monkeypatch, tmp_path):
    _minimal_runtime_environment(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "TALARIA_DATABASE_URL",
        "postgresql://talaria@database.example/talaria?sslmode=disable",
    )

    with pytest.raises(ValueError, match="PostgreSQL transport configuration"):
        validate_runtime_configuration()


def test_runtime_configuration_accepts_plaintext_for_explicit_trusted_host(
    monkeypatch, tmp_path
):
    _minimal_runtime_environment(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "TALARIA_DATABASE_URL",
        "postgresql://talaria@postgres/talaria?sslmode=disable",
    )
    monkeypatch.setenv("TALARIA_DATABASE_TRUSTED_HOSTS", "postgres")

    validate_runtime_configuration()
