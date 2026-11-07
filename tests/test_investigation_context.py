import hashlib

import pytest

from talaria.investigation.context import (
    ContextError,
    RepositoryContextCollector,
    analyze_python_imports,
)


def test_context_collector_returns_bounded_line_numbered_context(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    source = root / "app.py"
    source.write_text("\n".join(f"line_{i}" for i in range(1, 21)), encoding="utf-8")

    context = RepositoryContextCollector(max_context_lines=5).collect(
        root, "app.py", line=10, radius=2
    )

    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    assert context["id"] == f"source:{digest}:app.py:10"
    assert context["content_sha256"] == digest
    assert context["start_line"] == 8
    assert "10: line_10" in context["content"]
    assert len(context["content"].splitlines()) == 5


def test_context_collector_rejects_path_traversal_and_symlinks(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "secret.py"
    outside.write_text("password = 'never-send'", encoding="utf-8")
    (root / "link.py").symlink_to(outside)
    collector = RepositoryContextCollector()

    with pytest.raises(ContextError):
        collector.collect(root, "../secret.py", 1)
    with pytest.raises(ContextError, match="Symlink"):
        collector.collect(root, "link.py", 1)


def test_context_collector_rejects_symlinked_repository_root(tmp_path):
    real_root = tmp_path / "real-repo"
    real_root.mkdir()
    (real_root / "app.py").write_text("value = 1\n", encoding="utf-8")
    root_link = tmp_path / "repo-link"
    root_link.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(ContextError, match="root.*symlinked"):
        RepositoryContextCollector().collect(root_link, "app.py", 1)


def test_context_collector_enforces_size_and_line_limits(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "large.py").write_text("x" * 500, encoding="utf-8")
    collector = RepositoryContextCollector(max_file_bytes=100)

    with pytest.raises(ContextError, match="size limit"):
        collector.collect(root, "large.py", 1)


def test_context_collector_redacts_credentials_before_returning_context(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    secret = "super-secret-value-do-not-send"
    github_token = "".join(("ghp_", "123456789012345678901234567890123456"))
    slack_token = "".join(("xoxb-", "123456789012-", "abcdefghijklmnop"))
    source = root / "settings.py"
    source.write_text(
        f'api_key = "{secret}"\n'
        '"password": "another-secret-value"\n'
        f"access_token = {github_token}\n"
        'Authorization: Bearer exposed-bearer-credential\n'
        'aws_secret_access_key = "exposed-aws-secret"\n'
        'DATABASE_URL = "postgresql://dbuser:db-secret@database.example/talaria"\n'
        'DATABASE_URL = "postgresql://dbuser:before@after@database.example/talaria"\n'
        'clone_url = "https://x-access-token:github-secret@github.example/org/repo.git"\n'
        f"service_value = {slack_token}\n",
        encoding="utf-8",
    )

    context = RepositoryContextCollector().collect(root, "settings.py", 1)

    assert context["secrets_redacted"] is True
    assert secret not in context["content"]
    assert "another-secret-value" not in context["content"]
    assert "exposed-bearer-credential" not in context["content"]
    assert "exposed-aws-secret" not in context["content"]
    assert "db-secret" not in context["content"]
    assert "before@after" not in context["content"]
    assert "github-secret" not in context["content"]
    assert slack_token not in context["content"]
    assert github_token not in context["content"]
    assert context["content"].count("[REDACTED]") == 7
    assert "[REDACTED TOKEN]" in context["content"]


@pytest.mark.parametrize(
    "relative_path",
    [".env", ".env.production", "secrets/token.txt", "credentials.json", "id_rsa"],
)
def test_context_collector_excludes_secret_files(tmp_path, relative_path):
    root = tmp_path / "repo"
    root.mkdir()
    source = root / relative_path
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("secret-material", encoding="utf-8")

    with pytest.raises(ContextError, match="excluded"):
        RepositoryContextCollector().collect(root, relative_path, 1)


def test_static_import_analysis_never_executes_repository_code():
    result = analyze_python_imports(
        {
            "app.py": "import os.path\nfrom fastapi import FastAPI\n",
            "broken.py": "def invalid(:\n",
        }
    )

    assert result["imports_by_file"]["app.py"] == ["fastapi", "os"]
    assert result["parse_errors"] == ["broken.py"]
    assert result["execution_performed"] is False
