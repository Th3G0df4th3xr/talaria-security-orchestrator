import hashlib
import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path

from git import InvalidGitRepositoryError, Repo
from git.exc import BadName

from talaria.config import max_file_bytes
from talaria.database import Database
from talaria.findings.normalizer import fingerprint
from talaria.hunters.profiles import load_profile
from talaria.investigation.engine import investigate
from talaria.notifications.base import NotificationAdapter
from talaria.remediation.advisor import advise
from talaria.repositories.service import RepositoryService
from talaria.scanning.limits import ScanLimits
from talaria.security.filesystem import (
    SecureFileAccessUnavailable,
    SecureFileError,
    read_regular_file_beneath,
)

logger = logging.getLogger(__name__)


EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
}


class ScanLimitExceeded(RuntimeError):
    """Raised when a scan exceeds its configured resource budget."""


class ScanService:
    def __init__(
        self,
        db: Database,
        limits: ScanLimits | None = None,
        notifier: NotificationAdapter | None = None,
        allowed_roots: tuple[Path, ...] | None = None,
    ):
        self.db = db
        self.limits = limits or ScanLimits(max_file_bytes=max_file_bytes())
        self.repositories = RepositoryService(db, allowed_roots)
        self.notifier = notifier

    def scan(
        self,
        supplied_path: str,
        profile_name: str = "baseline",
        organization_id: str | None = None,
    ) -> dict:
        # Validate the profile before creating a scan record.
        profile = load_profile(profile_name)

        repository = self.repositories.register(supplied_path, organization_id)
        root = Path(repository["path"])
        branch, commit_sha = _repository_revision(root)

        scan_id = self.db.insert(
            """
            INSERT INTO scans(repository_id, branch, commit_sha, status)
            VALUES (?, ?, ?, 'running')
            """,
            (repository["id"], branch, commit_sha),
        )

        try:
            found = self._collect_findings(root, profile)

            completed_at = datetime.now(UTC).isoformat()
            serialized_findings = [
                (item, json.dumps(item, sort_keys=True))
                for item in found
            ]

            # Persist findings, occurrences, scan completion and audit
            # atomically. A failure rolls back the entire persistence phase.
            with self.db.transaction() as connection:
                for item, payload in serialized_findings:
                    connection.execute(
                        """
                        INSERT INTO findings (
                            fingerprint,
                            repository_id,
                            payload,
                            status,
                            first_seen_at,
                            last_seen_at
                        )
                        VALUES (?, ?, ?, 'open', ?, ?)
                        ON CONFLICT(fingerprint) DO UPDATE SET
                            payload = excluded.payload,
                            last_seen_at = excluded.last_seen_at
                        """,
                        (
                            item["fingerprint"],
                            repository["id"],
                            payload,
                            completed_at,
                            completed_at,
                        ),
                    )

                    finding = connection.execute(
                        "SELECT id FROM findings WHERE fingerprint = ?",
                        (item["fingerprint"],),
                    ).fetchone()

                    connection.execute(
                        """
                        INSERT INTO finding_occurrences (
                            finding_id,
                            scan_id,
                            observed_at
                        )
                        VALUES (?, ?, ?)
                        ON CONFLICT(finding_id, scan_id) DO NOTHING
                        """,
                        (
                            finding["id"],
                            scan_id,
                            completed_at,
                        ),
                    )

                connection.execute(
                    """
                    UPDATE scans
                    SET status = 'completed',
                        completed_at = ?,
                        finding_count = ?
                    WHERE id = ?
                    """,
                    (
                        completed_at,
                        len({item["fingerprint"] for item in found}),
                        scan_id,
                    ),
                )

                self.db.audit_in_transaction(
                    connection,
                    "scan.completed",
                    {
                        "scan_id": scan_id,
                        "repository_id": repository["id"],
                        "branch": branch,
                        "commit_sha": commit_sha,
                        "finding_count": len(found),
                    },
                )

            self._notify(
                {
                    "event": "scan.completed",
                    "scan_id": scan_id,
                    "repository": root.name,
                    "finding_count": len(found),
                    "status": "completed",
                }
            )

            return {
                "scan_id": scan_id,
                "repository": repository,
                "profile": profile["name"],
                "branch": branch,
                "commit_sha": commit_sha,
                "finding_count": len(found),
                "findings": found,
            }

        except Exception as exc:
            failed_at = datetime.now(UTC).isoformat()

            with self.db.transaction() as connection:
                connection.execute(
                    """
                    UPDATE scans
                    SET status = 'failed',
                        completed_at = ?,
                        error_summary = ?
                    WHERE id = ?
                    """,
                    (
                        failed_at,
                        str(exc)[:500],
                        scan_id,
                    ),
                )

                self.db.audit_in_transaction(
                    connection,
                    "scan.failed",
                    {
                        "scan_id": scan_id,
                        "repository_id": repository["id"],
                        "error_type": type(exc).__name__,
                    },
                )

            self._notify(
                {
                    "event": "scan.failed",
                    "scan_id": scan_id,
                    "repository": root.name,
                    "status": "failed",
                    "error_type": type(exc).__name__,
                }
            )

            raise

    def _notify(self, message: dict) -> None:
        if self.notifier is None:
            return
        try:
            self.notifier.send(message)
        except Exception as exc:
            logger.warning(
                "Notification delivery failed: adapter=%s error_type=%s",
                self.notifier.name,
                type(exc).__name__,
            )

    def _collect_findings(self, root: Path, profile: dict) -> list[dict]:
        found = []
        enabled_checks = [
            check for check in profile["checks"] if check.get("enabled", True)
        ]
        compiled_checks = [
            (check, re.compile(check["pattern"]))
            for check in enabled_checks
        ]
        allowed_extensions = {
            extension
            for check in enabled_checks
            for extension in check.get("extensions", [])
        }

        file_count = 0
        total_bytes = 0

        for current_dir, directories, filenames in os.walk(
            root, topdown=True, followlinks=False
        ):
            current_path = Path(current_dir)
            relative_dir = current_path.relative_to(root)

            directories[:] = [
                name
                for name in directories
                if name not in EXCLUDED
                and not (current_path / name).is_symlink()
                and len((relative_dir / name).parts) <= self.limits.max_depth
            ]

            for filename in filenames:
                file_path = current_path / filename
                relative_path = file_path.relative_to(root)

                if file_path.is_symlink() or file_path.suffix not in allowed_extensions:
                    continue

                if len(relative_path.parts) > self.limits.max_depth:
                    continue

                try:
                    size = file_path.stat().st_size
                except OSError:
                    continue

                if size > self.limits.max_file_bytes:
                    raise ScanLimitExceeded(
                        f"File exceeds max_file_bytes: {relative_path}"
                    )

                file_count += 1
                total_bytes += size

                if file_count > self.limits.max_files:
                    raise ScanLimitExceeded(
                        f"Scan exceeds max_files ({self.limits.max_files})"
                    )

                if total_bytes > self.limits.max_total_bytes:
                    raise ScanLimitExceeded(
                        f"Scan exceeds max_total_bytes ({self.limits.max_total_bytes})"
                    )

                try:
                    raw_content = read_regular_file_beneath(
                        root, relative_path, self.limits.max_file_bytes
                    )
                except SecureFileAccessUnavailable as exc:
                    raise RuntimeError(
                        "Secure repository scanning is unsupported on this platform"
                    ) from exc
                except SecureFileError as exc:
                    if "size limit" in str(exc):
                        raise ScanLimitExceeded(
                            f"File exceeds max_file_bytes: {relative_path}"
                        ) from exc
                    continue
                except OSError:
                    continue
                total_bytes += len(raw_content) - size
                if total_bytes > self.limits.max_total_bytes:
                    raise ScanLimitExceeded(
                        f"Scan exceeds max_total_bytes ({self.limits.max_total_bytes})"
                    )
                content = raw_content.decode("utf-8", errors="replace")
                source_sha256 = hashlib.sha256(raw_content).hexdigest()

                relative = relative_path.as_posix()

                for check, regex in compiled_checks:
                    if file_path.suffix not in check.get("extensions", []):
                        continue

                    for line_number, line in enumerate(
                        content.splitlines(),
                        start=1,
                    ):
                        if not regex.search(line):
                            continue

                        item = {
                            "rule_id": check["id"],
                            "title": check["description"],
                            "severity": check["severity"],
                            "path": relative,
                            "line": line_number,
                            "snippet": line.strip()[:240],
                            "source_sha256": source_sha256,
                        }

                        item["fingerprint"] = fingerprint(
                            item["rule_id"],
                            relative,
                            line_number,
                            line,
                        )
                        item["investigation"] = investigate(item)
                        item["remediation"] = advise(item["rule_id"])

                        found.append(item)

        return found


def _repository_revision(root: Path) -> tuple[str | None, str | None]:
    try:
        repository = Repo(root)
    except InvalidGitRepositoryError:
        return None, None
    try:
        try:
            branch = repository.active_branch.name
        except TypeError:
            branch = None
        try:
            commit_sha = repository.head.commit.hexsha
        except (BadName, ValueError, TypeError):
            commit_sha = None
        return branch, commit_sha
    finally:
        repository.close()
