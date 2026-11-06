from pathlib import Path

from git import InvalidGitRepositoryError, NoSuchPathError, Repo

from talaria.database import Database


class RepositoryError(ValueError):
    pass


class RepositoryService:
    def __init__(self, db: Database):
        self.db = db

    def validate(self, supplied_path: str) -> tuple[Path, str]:
        path = Path(supplied_path).expanduser().resolve()
        if not path.exists() or not path.is_dir():
            raise RepositoryError("Repository path must be an existing directory")
        try:
            repo = Repo(path, search_parent_directories=True)
        except (InvalidGitRepositoryError, NoSuchPathError):
            raise RepositoryError("Path is not inside a Git repository") from None
        root = Path(repo.working_tree_dir).resolve()
        return root, root.name

    def register(self, supplied_path: str) -> dict:
        path, name = self.validate(supplied_path)
        existing = self.db.execute("SELECT * FROM repositories WHERE path = ?", (str(path),))
        if existing:
            return existing[0]
        self.db.execute("INSERT INTO repositories(name, path) VALUES (?, ?)", (name, str(path)))
        row = self.db.execute("SELECT * FROM repositories WHERE path = ?", (str(path),))[0]
        self.db.audit("repository.registered", {"repository_id": row["id"], "path": str(path)})
        return row

    def list(self) -> list[dict]:
        return self.db.execute("SELECT * FROM repositories ORDER BY id")
