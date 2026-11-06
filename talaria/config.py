import os
from pathlib import Path


def database_path() -> Path:
    value = os.getenv("TALARIA_DATABASE", ".talaria/talaria.db")
    path = Path(value).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def max_file_bytes() -> int:
    try:
        return max(1024, int(os.getenv("TALARIA_MAX_FILE_BYTES", "2000000")))
    except ValueError:
        return 2_000_000
