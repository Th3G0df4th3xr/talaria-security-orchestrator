"""GitHub App authentication, bounded API calls, approvals, and webhooks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request

import jwt

from talaria.auth.approvals import ApprovalRegistry
from talaria.database import Database
from talaria.integrations.base import IntegrationAdapter, IntegrationError
from talaria.remediation.patches import PatchValidationResult
from talaria.security.http import urlopen_no_redirect
from talaria.security.secrets import SecretFileError, read_secret_file

GITHUB_API = "https://api.github.com"
MAX_RESPONSE_BYTES = 2_000_000


class GitHubAppClient:
    """Small GitHub App client; credentials are read from process config."""

    def __init__(
        self,
        app_id: str | None = None,
        private_key: str | None = None,
        installation_id: str | None = None,
        api_base: str = GITHUB_API,
        timeout: float = 10.0,
    ):
        if not isinstance(api_base, str) or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in api_base
        ):
            raise IntegrationError("GitHub API base must be a clean HTTPS URL.")
        try:
            parsed_base = urlsplit(api_base)
            hostname = parsed_base.hostname
            parsed_base.port
        except ValueError as exc:
            raise IntegrationError("GitHub API base must be a clean HTTPS URL.") from exc
        if (
            parsed_base.scheme != "https"
            or not hostname
            or parsed_base.username is not None
            or parsed_base.password is not None
            or parsed_base.query
            or parsed_base.fragment
            or "?" in api_base
            or "#" in api_base
            or "%" in parsed_base.netloc
            or "\\" in parsed_base.netloc
            or ".." in parsed_base.path.split("/")
        ):
            raise IntegrationError("GitHub API base must be a clean HTTPS URL.")
        self.app_id = app_id or os.getenv("GITHUB_APP_ID")
        self.installation_id = installation_id or os.getenv("GITHUB_INSTALLATION_ID")
        self.private_key = private_key or _load_private_key()
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self._installation_token: str | None = None
        self._installation_token_expires: datetime | None = None

    @property
    def configured(self) -> bool:
        return bool(self.app_id and self.installation_id and self.private_key)

    def app_jwt(self) -> str:
        if not self.app_id or not self.private_key:
            raise IntegrationError("GitHub App credentials are not configured.")
        now = int(time.time())
        return jwt.encode(
            {"iat": now - 30, "exp": now + 540, "iss": self.app_id},
            self.private_key,
            algorithm="RS256",
        )

    def installation_token(self) -> str:
        if not self.configured:
            raise IntegrationError("GitHub App installation is not configured.")
        now = datetime.now(UTC)
        if (
            self._installation_token
            and self._installation_token_expires
            and self._installation_token_expires > now + timedelta(minutes=2)
        ):
            return self._installation_token
        response = self._request(
            "POST",
            f"/app/installations/{self.installation_id}/access_tokens",
            token=self.app_jwt(),
        )
        try:
            token = response["token"]
            expires = datetime.fromisoformat(response["expires_at"].replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrationError(
                "GitHub returned an invalid installation token response."
            ) from exc
        if not token or expires <= now:
            raise IntegrationError("GitHub returned an expired installation token.")
        self._installation_token = token
        self._installation_token_expires = expires
        return token

    def request(self, method: str, path: str, payload: dict | None = None) -> Any:
        token = self.installation_token()
        return self._request(method, path, token=token, payload=payload)

    def _request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: dict | None = None,
    ) -> Any:
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or ".." in path.split("/")
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
        ):
            raise IntegrationError("Invalid GitHub API path.")
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        # GitHubAppClient validates an HTTPS base and this helper rejects redirects.
        request = Request(  # noqa: S310
            f"{self.api_base}{path}",
            data=body,
            method=method.upper(),
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "TALARIA-security-orchestrator",
            },
        )
        try:
            with urlopen_no_redirect(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise IntegrationError("GitHub API response exceeded the size limit.")
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            # Avoid returning provider body text, which can echo sensitive data.
            raise IntegrationError(f"GitHub API request failed with HTTP {exc.code}.") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise IntegrationError("GitHub API request failed.") from exc


class GitHubAdapter(IntegrationAdapter):
    def __init__(
        self,
        client: GitHubAppClient | None = None,
        approval_validator: Callable[[str, str, str, str], bool] | None = None,
        audit_action: Callable[[str, dict[str, str]], None] | None = None,
    ):
        self.client = client or GitHubAppClient()
        self.approval_validator = approval_validator
        self.audit_action = audit_action

    @classmethod
    def for_organization(
        cls,
        database: Database,
        organization_id: str,
        client: GitHubAppClient | None = None,
    ) -> GitHubAdapter:
        """Bind action checks and audit records to one organization."""
        approvals = ApprovalRegistry(database, organization_id)
        return cls(
            client=client,
            approval_validator=approvals.consume,
            audit_action=lambda event, details: database.audit(event, details),
        )

    @property
    def name(self) -> str:
        return "github"

    def health(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "configured": self.client.configured,
            "enabled": self.client.configured,
        }

    def repository(self, owner: str, repository: str) -> dict:
        _validate_segment(owner)
        _validate_segment(repository)
        return self.client.request("GET", f"/repos/{owner}/{repository}")

    def commit(self, owner: str, repository: str, sha: str) -> dict:
        _validate_segment(owner)
        _validate_segment(repository)
        if not _is_sha(sha):
            raise IntegrationError("Commit reference must be a full hexadecimal SHA.")
        return self.client.request("GET", f"/repos/{owner}/{repository}/commits/{sha}")

    def check_runs(self, owner: str, repository: str, sha: str) -> dict:
        _validate_segment(owner)
        _validate_segment(repository)
        if not _is_sha(sha):
            raise IntegrationError("Check reference must be a full hexadecimal SHA.")
        return self.client.request(
            "GET", f"/repos/{owner}/{repository}/commits/{sha}/check-runs?per_page=100"
        )

    def pull_request(self, owner: str, repository: str, number: int) -> dict:
        _validate_segment(owner)
        _validate_segment(repository)
        if not isinstance(number, int) or number < 1:
            raise IntegrationError("Pull request number must be positive.")
        return self.client.request(
            "GET", f"/repos/{owner}/{repository}/pulls/{number}"
        )

    def create_branch(
        self,
        owner: str,
        repository: str,
        branch: str,
        base_sha: str,
        patch_sha256: str,
        *,
        validated_patch: PatchValidationResult | None = None,
        approval_id: str,
        approved_by: str,
    ) -> dict:
        _validate_segment(owner)
        _validate_segment(repository)
        _validate_branch(branch)
        if not _is_sha(base_sha) or not _is_digest(patch_sha256):
            raise IntegrationError("Branch authorization requires valid base and patch digests.")
        if not isinstance(validated_patch, PatchValidationResult):
            raise IntegrationError(
                "Branch publication requires the exact validated patch output."
            )
        if (
            not isinstance(validated_patch.changed_files, tuple)
            or not validated_patch.changed_files
            or any(not isinstance(path, str) for path in validated_patch.changed_files)
            or not isinstance(validated_patch.file_contents, tuple)
            or not isinstance(validated_patch.file_modes, tuple)
        ):
            raise IntegrationError("Validated patch metadata is malformed.")
        expected_files = set(validated_patch.changed_files)
        try:
            contents = dict(validated_patch.file_contents)
            modes = dict(validated_patch.file_modes)
        except (TypeError, ValueError) as exc:
            raise IntegrationError("Validated patch metadata is malformed.") from exc
        if (
            not validated_patch.applied_to_temporary_copy
            or validated_patch.original_repository_modified
            or not isinstance(validated_patch.base_sha, str)
            or validated_patch.base_sha.lower() != base_sha.lower()
            or not isinstance(validated_patch.patch_sha256, str)
            or not _is_digest(validated_patch.patch_sha256)
            or validated_patch.patch_sha256.lower() != patch_sha256.lower()
            or not expected_files
            or set(contents) != expected_files
            or set(modes) != expected_files
            or len(expected_files) > 20
            or any(not _valid_patch_path(path) for path in expected_files)
            or any(
                not isinstance(content, bytes) or b"\x00" in content
                for content in contents.values()
            )
            or sum(len(content) for content in contents.values()) > 1_000_000
            or any(mode not in {"100644", "100755"} for mode in modes.values())
        ):
            raise IntegrationError("Branch publication requires the exact validated patch output.")
        self._require_approval(
            "github.create_branch",
            branch_approval_resource(owner, repository, branch, base_sha, patch_sha256),
            approval_id,
            approved_by,
        )
        details = {
            "repository": f"{owner}/{repository}",
            "branch": branch,
            "base_sha": base_sha,
            "approval_id": approval_id,
            "actor_id": approved_by,
        }
        self._audit("github.branch_create_attempted", details)
        expected_commit_sha = None
        try:
            base_commit = self.client.request(
                "GET", f"/repos/{owner}/{repository}/git/commits/{base_sha}"
            )
            if (
                not isinstance(base_commit, dict)
                or not isinstance(base_commit.get("sha"), str)
                or base_commit["sha"].lower() != base_sha.lower()
            ):
                raise IntegrationError("GitHub returned a different base commit.")
            base_tree_sha = _response_sha(
                base_commit.get("tree")
            )
            if base_tree_sha is None:
                raise IntegrationError("GitHub returned an invalid base commit tree.")
            tree_items = []
            for path in sorted(expected_files):
                blob = self.client.request(
                    "POST",
                    f"/repos/{owner}/{repository}/git/blobs",
                    {
                        "content": base64.b64encode(contents[path]).decode("ascii"),
                        "encoding": "base64",
                    },
                )
                blob_sha = _response_sha(blob)
                if blob_sha is None:
                    raise IntegrationError("GitHub returned an invalid file blob.")
                tree_items.append(
                    {"path": path, "mode": modes[path], "type": "blob", "sha": blob_sha}
                )
            tree = self.client.request(
                "POST",
                f"/repos/{owner}/{repository}/git/trees",
                {"base_tree": base_tree_sha, "tree": tree_items},
            )
            tree_sha = _response_sha(tree)
            if tree_sha is None:
                raise IntegrationError("GitHub returned an invalid patch tree.")
            commit = self.client.request(
                "POST",
                f"/repos/{owner}/{repository}/git/commits",
                {
                    "message": "Apply reviewed TALARIA remediation",
                    "tree": tree_sha,
                    "parents": [base_sha],
                },
            )
            expected_commit_sha = _response_sha(commit)
            if expected_commit_sha is None:
                raise IntegrationError("GitHub returned an invalid patch commit.")
            details["patch_commit_sha"] = expected_commit_sha
            result = self.client.request(
                "POST",
                f"/repos/{owner}/{repository}/git/refs",
                {"ref": f"refs/heads/{branch}", "sha": expected_commit_sha},
            )
            if not _matching_git_ref(result, branch, expected_commit_sha):
                raise IntegrationError("GitHub returned a branch at an unexpected commit.")
        except IntegrationError as exc:
            ref_path = f"/repos/{owner}/{repository}/git/ref/heads/{branch}"
            try:
                existing = self.client.request("GET", ref_path)
            except IntegrationError:
                existing = None
            if expected_commit_sha and _matching_git_ref(existing, branch, expected_commit_sha):
                self._audit(
                    "github.branch_reconciled_after_write_error",
                    details,
                )
                return existing
            failure = exc
            if (
                isinstance(existing, dict)
                and existing.get("ref") == f"refs/heads/{branch}"
                and isinstance(existing.get("object"), dict)
                and _is_sha(existing["object"].get("sha", ""))
            ):
                failure = IntegrationError(
                    "GitHub branch already exists at a different commit."
                )
            self._audit(
                "github.branch_create_failed",
                {**details, "error_type": type(failure).__name__},
            )
            if failure is exc:
                raise
            raise failure from exc
        self._audit(
            "github.branch_created",
            details,
        )
        return result

    def create_pull_request(
        self,
        owner: str,
        repository: str,
        *,
        head: str,
        base: str,
        title: str,
        body: str,
        patch_sha256: str,
        approval_id: str,
        approved_by: str,
    ) -> dict:
        _validate_segment(owner)
        _validate_segment(repository)
        _validate_branch(head)
        _validate_branch(base)
        if not _is_digest(patch_sha256):
            raise IntegrationError("Pull request authorization requires a patch digest.")
        if not title.strip() or len(title) > 256 or len(body) > 20_000:
            raise IntegrationError("Pull request text is invalid or too large.")
        self._require_approval(
            "github.create_pull_request",
            pull_request_approval_resource(
                owner, repository, head, base, title, body, patch_sha256
            ),
            approval_id,
            approved_by,
        )
        query = urlencode({"state": "all", "head": f"{owner}:{head}", "base": base})
        details = {
            "repository": f"{owner}/{repository}",
            "head": head,
            "base": base,
            "approval_id": approval_id,
            "actor_id": approved_by,
            "patch_sha256": patch_sha256.lower(),
        }
        approved_body = (
            body.rstrip()
            + f"\n\n<!-- talaria-patch-sha256:{patch_sha256.lower()} -->"
        )
        self._audit("github.pull_request_create_attempted", details)
        try:
            existing = self.client.request(
                "GET", f"/repos/{owner}/{repository}/pulls?{query}"
            )
            if existing:
                result = _matching_pull_request(
                    existing, head, base, title, approved_body
                )
                if result is None:
                    raise IntegrationError(
                        "An existing pull request uses this branch with different content."
                    )
                self._audit(
                    "github.pull_request_already_exists",
                    {**details, "pull_request_number": str(result.get("number", "unknown"))},
                )
                return result
            try:
                result = self.client.request(
                    "POST",
                    f"/repos/{owner}/{repository}/pulls",
                    {"head": head, "base": base, "title": title, "body": approved_body},
                )
            except IntegrationError:
                # A timeout or concurrent retry may happen after GitHub created
                # the PR. Reconcile once against the exact approved content.
                try:
                    reconciled = self.client.request(
                        "GET", f"/repos/{owner}/{repository}/pulls?{query}"
                    )
                    result = _matching_pull_request(
                        reconciled, head, base, title, approved_body
                    )
                except IntegrationError:
                    result = None
                if result is None:
                    raise
                self._audit(
                    "github.pull_request_reconciled_after_write_error",
                    {
                        **details,
                        "pull_request_number": str(result.get("number", "unknown")),
                    },
                )
                return result
        except IntegrationError as exc:
            self._audit(
                "github.pull_request_create_failed",
                {**details, "error_type": type(exc).__name__},
            )
            raise
        self._audit(
            "github.pull_request_created",
            {**details, "pull_request_number": str(result.get("number", "unknown"))},
        )
        return result


    def _require_approval(
        self, action: str, resource: str, approval_id: str, approved_by: str
    ) -> None:
        if (
            not approval_id.strip()
            or not approved_by.strip()
            or self.approval_validator is None
            or not self.approval_validator(approval_id, action, approved_by, resource)
        ):
            raise IntegrationError("A valid recorded human approval is required.")

    def _audit(self, event: str, details: dict[str, str]) -> None:
        if self.audit_action is not None:
            self.audit_action(event, details)


def _matching_pull_request(
    pull_requests: Any, head: str, base: str, title: str, body: str
) -> dict | None:
    if not isinstance(pull_requests, list):
        raise IntegrationError("GitHub returned an invalid pull request list.")
    return next(
        (
            item
            for item in pull_requests
            if isinstance(item, dict)
            and item.get("title") == title
            and item.get("body") == body
            and isinstance(item.get("head"), dict)
            and item["head"].get("ref") == head
            and isinstance(item.get("base"), dict)
            and item["base"].get("ref") == base
        ),
        None,
    )


def _matching_git_ref(reference: Any, branch: str, base_sha: str) -> bool:
    return (
        isinstance(reference, dict)
        and reference.get("ref") == f"refs/heads/{branch}"
        and isinstance(reference.get("object"), dict)
        and isinstance(reference["object"].get("sha"), str)
        and reference["object"]["sha"].lower() == base_sha.lower()
    )


def _response_sha(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    sha = value.get("sha")
    return sha.lower() if isinstance(sha, str) and _is_sha(sha) else None


def _valid_patch_path(path: str) -> bool:
    return (
        bool(path)
        and not path.startswith("/")
        and "\\" not in path
        and "\x00" not in path
        and all(part not in {"", ".", "..", ".git"} for part in path.split("/"))
        and len(path.encode("utf-8")) <= 4096
    )


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify X-Hub-Signature-256 with constant-time comparison."""
    if not isinstance(payload, bytes) or not signature.startswith("sha256=") or not secret:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def branch_approval_resource(
    owner: str,
    repository: str,
    branch: str,
    base_sha: str,
    patch_sha256: str,
) -> str:
    """Return a stable approval scope for one branch, base, and patch."""
    _validate_segment(owner)
    _validate_segment(repository)
    _validate_branch(branch)
    if not _is_sha(base_sha) or not _is_digest(patch_sha256):
        raise IntegrationError("Branch approval requires valid base and patch digests.")
    return _action_resource(
        owner,
        repository,
        "branch",
        {"branch": branch, "base_sha": base_sha.lower(), "patch_sha256": patch_sha256.lower()},
    )


def pull_request_approval_resource(
    owner: str,
    repository: str,
    head: str,
    base: str,
    title: str,
    body: str,
    patch_sha256: str,
) -> str:
    """Return an approval scope bound to exact PR content and patch digest."""
    _validate_segment(owner)
    _validate_segment(repository)
    _validate_branch(head)
    _validate_branch(base)
    if not _is_digest(patch_sha256):
        raise IntegrationError("Pull request approval requires a patch digest.")
    if not title.strip() or len(title) > 256 or len(body) > 20_000:
        raise IntegrationError("Pull request text is invalid or too large.")
    normalized_body = re.sub(
        r"(\*\*Approval record:\*\* `)[^`]*(`)",
        r"\1<approval-id>\2",
        body,
    )
    return _action_resource(
        owner,
        repository,
        "pull-request",
        {
            "head": head,
            "base": base,
            "title": title,
            "body": normalized_body,
            "patch_sha256": patch_sha256.lower(),
        },
    )


def _action_resource(owner: str, repository: str, action: str, details: dict) -> str:
    encoded = json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    return f"{owner}/{repository}:{action}:{digest}"


def build_pull_request_content(
    finding: dict,
    summary: str,
    base_sha: str,
    validation: Any,
    approval_id: str,
) -> tuple[str, str]:
    """Create a factual PR title/body from validated evidence and status."""
    if (
        not getattr(validation, "applied_to_temporary_copy", False)
        or getattr(validation, "original_repository_modified", True)
        or not getattr(validation, "python_files_syntax_valid", False)
    ):
        raise IntegrationError("Patch validation must pass before PR content is built.")
    if not _is_sha(base_sha) or not approval_id:
        raise IntegrationError("A full base commit and approval record are required.")
    rule = _safe_markdown(finding.get("rule_id", "security finding"), 80)
    title = _safe_markdown(summary, 200)
    path = _safe_markdown(finding.get("path", "unknown"), 300)
    line = _safe_markdown(finding.get("line", "unknown"), 20)
    severity = _safe_markdown(finding.get("severity", "unknown"), 30)
    evidence = _safe_markdown(finding.get("fingerprint", "unavailable"), 80)
    body = (
        "## Proposed security remediation\n\n"
        f"**Finding:** {rule} ({severity})\n\n"
        f"**Location:** `{path}:{line}`\n\n"
        f"**Fingerprint:** `{evidence}`\n\n"
        f"**Proposal:** {title}\n\n"
        f"**Base commit:** `{base_sha}`\n\n"
        f"**Validation:** applied to an isolated temporary copy; Python syntax checks passed. "
        "Repository tests and runtime behavior have not been verified.\n\n"
        f"**Approval record:** `{approval_id}`\n\n"
        "Review the diff, run the repository's approved test suite, and obtain normal "
        "repository review before merging. TALARIA does not merge this change."
    )
    return f"TALARIA: {rule}", body[:20_000]


def _load_private_key() -> str | None:
    inline = os.getenv("GITHUB_APP_PRIVATE_KEY")
    if inline:
        return inline.replace("\\n", "\n")
    key_path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH")
    if not key_path:
        return None
    try:
        return read_secret_file(
            key_path,
            label="GitHub App private key",
            strip=False,
            allow_empty=True,
        ) or None
    except SecretFileError as exc:
        raise IntegrationError("Cannot read GitHub App private key secret.") from exc


def _validate_segment(value: str) -> None:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value)
        or value in {".", ".."}
    ):
        raise IntegrationError("Invalid GitHub repository identifier.")


def _validate_branch(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
        or len(value) > 200
        or value.startswith("-")
        or value.startswith("/")
        or ".." in value
        or any(char in value for char in " ~^:?*[\\")
    ):
        raise IntegrationError("Invalid branch name.")


def _is_sha(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdefABCDEF" for char in value)


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value)


def _safe_markdown(value: Any, maximum: int) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("`", "'")[:maximum]
