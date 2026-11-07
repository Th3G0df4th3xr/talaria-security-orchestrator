from pathlib import Path

from git import InvalidGitRepositoryError, NoSuchPathError, Repo

from talaria.database import Database


class RepositoryError(ValueError):
    pass


class RepositoryService:
    def __init__(self, db: Database, allowed_roots: tuple[Path, ...] | None = None):
        self.db = db
        self.allowed_roots = allowed_roots

    def validate(self, supplied_path: str) -> tuple[Path, str]:
        path = Path(supplied_path).expanduser().resolve()
        if not path.exists() or not path.is_dir():
            raise RepositoryError("Repository path must be an existing directory")
        try:
            repo = Repo(path, search_parent_directories=True)
        except (InvalidGitRepositoryError, NoSuchPathError):
            raise RepositoryError("Path is not inside a Git repository") from None
        root = Path(repo.working_tree_dir).resolve()
        if self.allowed_roots is not None and not any(
            root == allowed or allowed in root.parents for allowed in self.allowed_roots
        ):
            raise RepositoryError("Repository is outside configured allowed roots")
        return root, root.name

    def register(self, supplied_path: str, organization_id: str | None = None) -> dict:
        path, name = self.validate(supplied_path)
        existing = self.db.execute("SELECT * FROM repositories WHERE path = ?", (str(path),))
        if existing:
            owner = existing[0].get("organization_id")
            if organization_id and owner and owner != organization_id:
                raise RepositoryError("Repository is already owned by another organization")
            if organization_id and owner is None:
                self.db.execute(
                    "UPDATE repositories SET organization_id = ? WHERE id = ?",
                    (organization_id, existing[0]["id"]),
                )
                existing[0]["organization_id"] = organization_id
            return existing[0]
        self.db.execute(
            "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
            (name, str(path), organization_id),
        )
        row = self.db.execute("SELECT * FROM repositories WHERE path = ?", (str(path),))[0]
        self.db.audit("repository.registered", {"repository_id": row["id"], "path": str(path)})
        return row

    def list(self, organization_id: str | None = None) -> list[dict]:
        if organization_id is None:
            return self.db.execute("SELECT * FROM repositories ORDER BY id")
        return self.db.execute(
            "SELECT * FROM repositories WHERE organization_id = ? ORDER BY id",
            (organization_id,),
        )
