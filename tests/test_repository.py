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
