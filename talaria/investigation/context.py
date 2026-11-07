"""Bounded, read-only repository context and Python import analysis."""

import ast
import hashlib
import os
import re
from pathlib import Path

from talaria.security.filesystem import SecureFileError, read_regular_file_beneath

ALLOWED_CONTEXT_SUFFIXES = frozenset(
    {
        ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
        ".jsx", ".kt", ".md", ".php", ".py", ".rb", ".rs", ".scala",
        ".sh", ".sql", ".swift", ".toml", ".ts", ".tsx", ".txt", ".xml",
        ".yaml", ".yml",
    }
)
SENSITIVE_PATH_PARTS = frozenset(
    {".aws", ".gnupg", ".ssh", "credentials", "private", "secret", "secrets"}
)
SECRET_ASSIGNMENT = re.compile(
    r"(?i)([\"']?\b(?:api[_-]?key|aws[_-]?access[_-]?key(?:[_-]?id)?|"
    r"aws[_-]?secret[_-]?access[_-]?key|access[_-]?key|client[_-]?secret|"
    r"(?:database|db|connection|redis|mongo|postgres|mysql)[_-]?"
    r"(?:url|uri|dsn|connection[_-]?string)|"
    r"password|passwd|private[_-]?key|(?:secret|signing|encryption)[_-]?key|"
    r"secret|token|authorization)\b[\"']?\s*[:=]\s*)"
    r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"
)
AUTHORIZATION_CREDENTIAL = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(?:bearer|basic)\s+[^\s,;\"']+"
)
URL_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s]+@")
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
KNOWN_TOKEN = re.compile(
    r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|"
    r"npm_[A-Za-z0-9]{20,}|(?:sk|rk)_live_[A-Za-z0-9]{20,}|"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b"
)


def redact_sensitive_text(text: str) -> tuple[str, bool]:
    """Redact recognizable credential material from text sent to or received from AI."""
    redacted = PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", text)
    redacted = AUTHORIZATION_CREDENTIAL.sub(r"\1[REDACTED]", redacted)
    redacted = URL_USERINFO.sub(r"\1[REDACTED]@", redacted)
    redacted = SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", redacted)
    redacted = KNOWN_TOKEN.sub("[REDACTED TOKEN]", redacted)
    return redacted, redacted != text


class ContextError(ValueError):
    """Raised when repository context is outside the allowed budget/root."""


class RepositoryContextCollector:
    def __init__(
        self,
        max_file_bytes: int = 200_000,
        max_context_lines: int = 21,
        max_total_bytes: int = 500_000,
    ):
        if min(max_file_bytes, max_context_lines, max_total_bytes) <= 0:
            raise ValueError("Repository context limits must be positive")
        self.max_file_bytes = max_file_bytes
        self.max_context_lines = max_context_lines
        self.max_total_bytes = max_total_bytes

    def collect(
        self,
        repository_root: str | Path,
        file_path: str,
        line: int,
        radius: int = 5,
    ) -> dict:
        root = Path(os.path.abspath(Path(repository_root).expanduser()))
        try:
            resolved_root = root.resolve(strict=True)
        except OSError as exc:
            raise ContextError("Repository root could not be resolved") from exc
        if resolved_root != root:
            raise ContextError("Repository root must not contain symlinked paths")
        supplied = Path(file_path)
        if (
            supplied.is_absolute()
            or ".." in supplied.parts
            or not file_path
            or line < 1
            or radius < 0
        ):
            raise ContextError("Finding source location is invalid")
        candidate = root / supplied
        if any(part.is_symlink() for part in _parents_between(root, candidate)):
            raise ContextError("Symlinked source files are not accepted")
        resolved = candidate.resolve(strict=True)
        try:
            relative = resolved.relative_to(root)
        except ValueError as exc:
            raise ContextError("Source file is outside the repository") from exc
        if not resolved.is_file():
            raise ContextError("Source location is not a file")
        lower_parts = tuple(part.lower() for part in relative.parts)
        lower_name = relative.name.lower()
        if (
            relative.suffix.lower() not in ALLOWED_CONTEXT_SUFFIXES
            or any(part in SENSITIVE_PATH_PARTS for part in lower_parts)
            or re.fullmatch(r"(?:credentials?|secrets?)(?:\.[a-z0-9_-]+)?", lower_name)
            or lower_name == ".env"
            or lower_name.startswith(".env.")
            or lower_name.endswith((".pem", ".key", ".p12", ".pfx", ".jks"))
            or lower_name in {"id_rsa", "id_ed25519", "authorized_keys"}
        ):
            raise ContextError("Source file is excluded from AI context")
        try:
            raw_bytes = read_regular_file_beneath(
                root, supplied, min(self.max_file_bytes, self.max_total_bytes)
            )
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            text, secrets_redacted = redact_sensitive_text(raw_text)
            lines = text.splitlines()
        except SecureFileError as exc:
            if "size limit" in str(exc):
                raise ContextError("Source file exceeds the context size limit") from exc
            raise ContextError("Source file could not be read") from exc
        except OSError as exc:
            raise ContextError("Source file could not be read") from exc
        if line > len(lines):
            raise ContextError("Finding line is outside the source file")
        start = max(1, line - min(radius, self.max_context_lines // 2))
        end = min(len(lines), start + self.max_context_lines - 1)
        selected = lines[start - 1 : end]
        content = "\n".join(
            f"{number}: {text[:1000]}"
            for number, text in enumerate(selected, start=start)
        )
        if len(content.encode("utf-8")) > self.max_total_bytes:
            raise ContextError("Collected context exceeds the total size limit")
        content_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        return {
            "id": f"source:{content_sha256}:{relative.as_posix()}:{line}",
            "path": relative.as_posix(),
            "line": line,
            "start_line": start,
            "content": content,
            "content_sha256": content_sha256,
            "secrets_redacted": secrets_redacted,
        }


def analyze_python_imports(source_files: dict[str, str]) -> dict:
    """Extract static imports without importing or executing repository code."""
    imports: dict[str, set[str]] = {}
    errors = []
    for path, content in list(source_files.items())[:200]:
        try:
            tree = ast.parse(content[:200_000], filename=path)
        except (SyntaxError, TypeError, ValueError):
            errors.append(path[:500])
            continue
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split(".")[0])
        imports[path[:500]] = names
    return {
        "files_analyzed": len(imports),
        "imports_by_file": {path: sorted(names) for path, names in imports.items()},
        "parse_errors": errors,
        "execution_performed": False,
    }


def _parents_between(root: Path, path: Path) -> list[Path]:
    parents = []
    current = path
    while current != root:
        parents.append(current)
        current = current.parent
        if root not in current.parents and current != root:
            break
    return parents
