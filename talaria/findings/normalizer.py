import hashlib


def fingerprint(rule_id: str, relative_path: str, line: int, snippet: str) -> str:
    normalized = " ".join(snippet.strip().split())[:240]
    value = "|".join((rule_id, relative_path, str(line), normalized))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
