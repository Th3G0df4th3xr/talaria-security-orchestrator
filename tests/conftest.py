import subprocess

import pytest


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "talaria.db"))
    return tmp_path


@pytest.fixture
def git_repo(tmp_path):
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True
    )
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True)
    (repo / "app.py").write_text("value = eval(user_input)\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "initial"], check=True, capture_output=True
    )
    return repo
