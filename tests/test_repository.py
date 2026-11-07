from pathlib import Path

import pytest

from talaria.database import Database
from talaria.repositories.service import RepositoryError, RepositoryService


def test_register_git_repo(isolated_db, git_repo):
    service = RepositoryService(Database(isolated_db / "db.sqlite"))
    first = service.register(str(git_repo))
    second = service.register(str(git_repo))
    assert first["id"] == second["id"]
    assert first["path"] == str(git_repo.resolve())


def test_reject_non_git_directory(isolated_db, tmp_path):
    service = RepositoryService(Database(isolated_db / "db.sqlite"))
    with pytest.raises(RepositoryError):
        service.register(str(tmp_path))


def test_allowed_root_policy_accepts_children_and_rejects_other_repositories(
    tmp_path, git_repo
):
    database = Database(tmp_path / "db.sqlite")
    allowed = RepositoryService(database, (git_repo.parent,))
    assert allowed.register(str(git_repo))["path"] == str(git_repo.resolve())

    denied = RepositoryService(database, (Path(tmp_path / "other-root"),))
    with pytest.raises(RepositoryError, match="outside configured allowed roots"):
        denied.validate(str(git_repo))
