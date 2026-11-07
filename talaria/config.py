import os
from pathlib import Path


def database_path() -> Path | str:
    """Return a local SQLite path or an explicitly configured PostgreSQL URL."""
    database_url = os.getenv("TALARIA_DATABASE_URL")
    if database_url:
        return database_url
    value = os.getenv("TALARIA_DATABASE", ".talaria/talaria.db")
    return Path(value).expanduser().resolve()


def max_file_bytes() -> int:
    try:
        value = int(os.getenv("TALARIA_MAX_FILE_BYTES", "2000000"))
    except ValueError:
        raise ValueError("TALARIA_MAX_FILE_BYTES must be an integer") from None
    if not 1024 <= value <= 50_000_000:
        raise ValueError("TALARIA_MAX_FILE_BYTES must be between 1024 and 50000000")
    return value


def allowed_repository_roots() -> tuple[Path, ...]:
    """Return canonical repository roots permitted to API-triggered scans."""
    configured = os.getenv("TALARIA_ALLOWED_REPOSITORY_ROOTS")
    values = (
        [item.strip() for item in configured.split(os.pathsep) if item.strip()]
        if configured is not None
        else [str(Path.cwd())]
    )
    roots = tuple(Path(value).expanduser().resolve() for value in values)
    if not roots:
        raise ValueError("TALARIA_ALLOWED_REPOSITORY_ROOTS cannot be empty")
    return roots


def validate_runtime_configuration() -> None:
    """Fail startup on invalid security settings or incomplete integrations."""
    from talaria.auth.tokens import TokenError, get_jwt_secret
    from talaria.integrations.base import IntegrationError
    from talaria.integrations.github import GitHubAppClient
    from talaria.integrations.llm import (
        LLMSettings,
        OpenAICompatibleProvider,
    )
    from talaria.security.secrets import SecretFileError, read_secret_file

    max_file_bytes()
    database_url = os.getenv("TALARIA_DATABASE_URL", "")
    if database_url.startswith(("postgresql://", "postgres://")):
        from talaria.database import postgres_connection_parameters

        try:
            postgres_connection_parameters(database_url)
        except ValueError as exc:
            raise ValueError("PostgreSQL transport configuration is invalid") from exc
    roots = allowed_repository_roots()
    if any(not root.is_dir() for root in roots):
        raise ValueError("Every TALARIA_ALLOWED_REPOSITORY_ROOTS entry must be a directory")

    try:
        get_jwt_secret()
    except TokenError as exc:
        raise ValueError("JWT signing configuration is invalid") from exc

    for variable, label in (
        ("TALARIA_BOOTSTRAP_TOKEN_FILE", "bootstrap"),
        ("TALARIA_METRICS_TOKEN_FILE", "metrics"),
        ("GITHUB_WEBHOOK_SECRET_FILE", "GitHub webhook"),
    ):
        secret_path = os.getenv(variable)
        if secret_path:
            try:
                read_secret_file(secret_path, label=label, allow_empty=True)
            except SecretFileError as exc:
                raise ValueError(f"{variable} is invalid") from exc

    try:
        llm_settings = LLMSettings.from_environment()
        if llm_settings.send_source and not llm_settings.enabled:
            raise ValueError("TALARIA_AI_SEND_SOURCE requires TALARIA_AI_ENABLED")
        if llm_settings.enabled:
            OpenAICompatibleProvider(llm_settings)
    except IntegrationError as exc:
        raise ValueError("AI integration configuration is invalid") from exc

    try:
        github = GitHubAppClient()
    except IntegrationError as exc:
        raise ValueError("GitHub App configuration is invalid") from exc
    github_values = (github.app_id, github.installation_id, github.private_key)
    if any(github_values) and not all(github_values):
        raise ValueError("GitHub App configuration must include app, installation, and key")
    if github.app_id and not github.app_id.isdigit():
        raise ValueError("GITHUB_APP_ID must contain only digits")
    if github.installation_id and not github.installation_id.isdigit():
        raise ValueError("GITHUB_INSTALLATION_ID must contain only digits")
