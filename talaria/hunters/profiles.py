import re
from pathlib import Path

import yaml

PROFILE_DIR = Path(__file__).parent / "profiles"


def load_profile(name: str = "baseline") -> dict:
    path = (PROFILE_DIR / f"{name}.yaml").resolve()
    if path.parent != PROFILE_DIR.resolve() or not path.is_file():
        raise ValueError(f"Unknown hunter profile: {name}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("checks"), list):
        raise ValueError("Invalid hunter profile structure")
    for check in data["checks"]:
        re.compile(check["pattern"])
    return data
