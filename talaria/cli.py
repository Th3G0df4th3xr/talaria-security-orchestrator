import argparse
import json
from pathlib import Path

from talaria.config import database_path
from talaria.database import Database
from talaria.repositories.service import RepositoryError, RepositoryService
from talaria.scanning.service import ScanService


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="talaria", description="Local-first security orchestration MVP"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("register", help="Register a local Git repository")
    register.add_argument("path")
    scan = sub.add_parser("scan", help="Scan a registered/authorized local Git repository")
    scan.add_argument("path")
    scan.add_argument("--profile", default="baseline")
    scan.add_argument("--json-out")
    args = parser.parse_args()
    db = Database(database_path())
    try:
        if args.command == "register":
            result = RepositoryService(db).register(args.path)
        else:
            result = ScanService(db).scan(args.path, args.profile)
            if args.json_out:
                target = Path(args.json_out).expanduser()
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2, default=str))
    except (RepositoryError, ValueError) as exc:
        parser.exit(2, f"talaria: error: {exc}\n")


if __name__ == "__main__":
    main()
