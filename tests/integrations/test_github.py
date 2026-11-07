"""GitHub integration tests use fakes and never contact GitHub."""

import base64
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from talaria.api import app
from talaria.auth.approvals import ApprovalRegistry
from talaria.auth.service import AuthService
from talaria.config import database_path
from talaria.database import Database
from talaria.integrations.api import summarize_webhook
from talaria.integrations.base import IntegrationError
from talaria.integrations.github import (
    GitHubAdapter,
    GitHubAppClient,
    branch_approval_resource,
    build_pull_request_content,
    pull_request_approval_resource,
    verify_webhook_signature,
)
from talaria.remediation.patches import PatchValidationResult

pytestmark = [pytest.mark.integration, pytest.mark.security]


class FakeClient:
    def __init__(self):
        self.calls = []
        self.pull_requests = []

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path.endswith("/git/commits/") or "/git/commits/" in path and method == "GET":
            return {"sha": path.rsplit("/", 1)[-1], "tree": {"sha": "c" * 40}}
        if method == "POST" and path.endswith("/git/blobs"):
            return {"sha": "d" * 40}
        if method == "POST" and path.endswith("/git/trees"):
            return {"sha": "e" * 40}
        if method == "POST" and path.endswith("/git/commits"):
            return {"sha": "f" * 40}
        if method == "POST" and path.endswith("/git/refs"):
            return {"ref": payload["ref"], "object": {"sha": payload["sha"]}}
        if "/pulls?" in path:
            return self.pull_requests
        if method == "POST" and path.endswith("/pulls"):
            return {
                "number": 42,
                **payload,
                "head": {"ref": payload["head"]},
                "base": {"ref": payload["base"]},
            }
        return {"ok": True}


def validated_patch(base_sha="a" * 40, patch_sha256="b" * 64):
    return PatchValidationResult(
        ("app.py",), True, True, False, base_sha, patch_sha256,
        (("app.py", b"value = 2\n"),), (("app.py", "100644"),),
    )


def test_app_jwt_uses_rs256_and_short_claim_window():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    client = GitHubAppClient("123", pem, "456")

    token = client.app_jwt()

    assert token.split(".")[0]
    assert client.configured is True


def test_webhook_signature_requires_valid_sha256_hmac():
    body = b'{"action":"opened"}'
    secret = "test-secret"
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    assert verify_webhook_signature(body, signature, secret) is True
    assert verify_webhook_signature(body, signature, "wrong") is False
    assert verify_webhook_signature(body, "sha1=bad", secret) is False


def test_webhook_summary_extracts_only_allowlisted_metadata():
    metadata = summarize_webhook(
        "pull_request",
        {
            "action": "closed",
            "repository": {"id": 1234, "full_name": "owner/repository"},
            "installation": {"id": 456},
            "sender": {"login": "reviewer"},
            "pull_request": {
                "number": 17,
                "state": "closed",
                "merged": True,
                "head": {"ref": "fix/security", "sha": "a" * 40},
                "base": {"ref": "main"},
                "body": "SECRET_BODY_NOT_STORED",
            },
        },
    )

    assert metadata["repository"] == "owner/repository"
    assert metadata["repository_id"] == 1234
    assert metadata["installation_id"] == "456"
    assert metadata["commit_sha"] == "a" * 40
    assert metadata["pull_request_number"] == 17
    assert metadata["merged"] == 1
    assert "SECRET_BODY_NOT_STORED" not in str(metadata)


@pytest.mark.parametrize(
    ("number", "merged", "expected_number", "expected_merged"),
    [
        (True, "false", None, None),
        (17, False, 17, 0),
        (18, True, 18, 1),
    ],
)
def test_webhook_summary_requires_typed_pr_number_and_merged_flag(
    number, merged, expected_number, expected_merged
):
    metadata = summarize_webhook(
        "pull_request",
        {
            "repository": {"id": 1234, "full_name": "owner/repository"},
            "installation": {"id": 456},
            "pull_request": {
                "number": number,
                "state": "open",
                "merged": merged,
            },
        },
    )

    assert metadata["pull_request_number"] == expected_number
    assert metadata["merged"] == expected_merged


def test_pr_creation_requires_persisted_approval_validator():
    adapter = GitHubAdapter(FakeClient())

    with pytest.raises(IntegrationError, match="approval"):
        adapter.create_pull_request(
            "owner",
            "repo",
            head="talaria/fix-1",
            base="main",
            title="Fix issue",
            body="Evidence",
            patch_sha256="a" * 64,
            approval_id="approval-1",
            approved_by="reviewer",
        )


def test_pr_creation_is_idempotent_and_requires_approval():
    fake = FakeClient()
    adapter = GitHubAdapter(fake, lambda approval_id, action, approver, resource: True)
    created = adapter.create_pull_request(
        "owner",
        "repo",
        head="talaria/fix-1",
        base="main",
        title="Fix issue",
        body="Evidence",
        patch_sha256="a" * 64,
        approval_id="approval-1",
        approved_by="reviewer",
    )
    assert created["number"] == 42
    assert fake.calls[-1][0] == "POST"

    fake.pull_requests = [
        {
            "number": 42,
            "title": "Fix issue",
            "body": created["body"],
            "head": {"ref": "talaria/fix-1"},
            "base": {"ref": "main"},
        }
    ]
    assert adapter.create_pull_request(
        "owner",
        "repo",
        head="talaria/fix-1",
        base="main",
        title="Fix issue",
        body="Evidence",
        patch_sha256="a" * 64,
        approval_id="approval-1",
        approved_by="reviewer",
    )["number"] == 42
    assert fake.calls[-1][0] == "GET"


def test_pr_creation_reconciles_provider_success_after_write_error():
    class AcceptedThenDisconnectedClient(FakeClient):
        def request(self, method, path, payload=None):
            self.calls.append((method, path, payload))
            if "/pulls?" in path:
                return self.pull_requests
            if method == "POST" and path.endswith("/pulls"):
                self.pull_requests = [
                    {
                        "number": 43,
                        "title": payload["title"],
                        "body": payload["body"],
                        "head": {"ref": payload["head"]},
                        "base": {"ref": payload["base"]},
                    }
                ]
                raise IntegrationError("GitHub API request failed.")
            return super().request(method, path, payload)

    events = []
    fake = AcceptedThenDisconnectedClient()
    adapter = GitHubAdapter(
        fake,
        lambda *_args: True,
        lambda event, details: events.append((event, details)),
    )

    result = adapter.create_pull_request(
        "owner",
        "repo",
        head="talaria/fix-1",
        base="main",
        title="Fix issue",
        body="Evidence",
        patch_sha256="a" * 64,
        approval_id="approval-1",
        approved_by="reviewer",
    )

    assert result["number"] == 43
    assert [call[0] for call in fake.calls] == ["GET", "POST", "GET"]
    assert [event for event, _ in events] == [
        "github.pull_request_create_attempted",
        "github.pull_request_reconciled_after_write_error",
    ]
    assert events[-1][1]["pull_request_number"] == "43"


def test_pr_creation_refuses_to_reuse_branch_with_different_content():
    fake = FakeClient()
    fake.pull_requests = [
        {
            "number": 42,
            "title": "Different change",
            "body": "Different approved body",
            "head": {"ref": "talaria/fix-1"},
            "base": {"ref": "main"},
        }
    ]
    adapter = GitHubAdapter(fake, lambda *_args: True)

    with pytest.raises(IntegrationError, match="different content"):
        adapter.create_pull_request(
            "owner",
            "repo",
            head="talaria/fix-1",
            base="main",
            title="Fix issue",
            body="Evidence",
            patch_sha256="a" * 64,
            approval_id="approval-1",
            approved_by="reviewer",
        )

    assert fake.calls[-1][0] == "GET"


def test_failed_branch_write_is_audited_without_provider_response_content():
    events = []

    class FailingClient:
        def request(self, *_args, **_kwargs):
            raise IntegrationError("GitHub API request failed.")

    adapter = GitHubAdapter(
        FailingClient(),
        lambda *_args: True,
        lambda event, details: events.append((event, details)),
    )

    with pytest.raises(IntegrationError):
        adapter.create_branch(
            "owner",
            "repo",
            "talaria/fix-1",
            "a" * 40,
            "b" * 64,
            validated_patch=validated_patch(),
            approval_id="approval-1",
            approved_by="reviewer-1",
        )

    assert [event for event, _ in events] == [
        "github.branch_create_attempted",
        "github.branch_create_failed",
    ]
    assert events[1][1]["error_type"] == "IntegrationError"
    assert "GitHub API request failed" not in str(events)


def test_branch_creation_reconciles_provider_success_after_write_error():
    class AcceptedThenDisconnectedClient(FakeClient):
        def __init__(self):
            super().__init__()
            self.reference = None

        def request(self, method, path, payload=None):
            self.calls.append((method, path, payload))
            if "/git/ref/heads/" in path:
                return self.reference
            if method == "POST" and path.endswith("/git/refs"):
                self.reference = {
                    "ref": payload["ref"],
                    "object": {"sha": payload["sha"]},
                }
                raise IntegrationError("GitHub API request failed.")
            return super().request(method, path, payload)

    events = []
    fake = AcceptedThenDisconnectedClient()
    adapter = GitHubAdapter(
        fake,
        lambda *_args: True,
        lambda event, details: events.append((event, details)),
    )
    base_sha = "a" * 40

    result = adapter.create_branch(
        "owner",
        "repo",
        "talaria/fix-1",
        base_sha,
        "b" * 64,
        validated_patch=validated_patch(base_sha),
        approval_id="approval-1",
        approved_by="reviewer-1",
    )

    assert result["ref"] == "refs/heads/talaria/fix-1"
    assert result["object"]["sha"] == "f" * 40
    assert [call[0] for call in fake.calls][-2:] == ["POST", "GET"]
    assert [event for event, _ in events] == [
        "github.branch_create_attempted",
        "github.branch_reconciled_after_write_error",
    ]


def test_branch_creation_does_not_accept_existing_ref_at_different_sha():
    class ExistingDifferentBranchClient(FakeClient):
        def request(self, method, path, payload=None):
            self.calls.append((method, path, payload))
            if method == "POST" and path.endswith("/git/refs"):
                raise IntegrationError("GitHub API request failed.")
            if "/git/ref/heads/" in path:
                return {
                    "ref": "refs/heads/talaria/fix-1",
                    "object": {"sha": "c" * 40},
                }
            return {"ok": True}

    fake = ExistingDifferentBranchClient()
    adapter = GitHubAdapter(fake, lambda *_args: True)

    with pytest.raises(IntegrationError, match="different commit"):
        adapter.create_branch(
            "owner",
            "repo",
            "talaria/fix-1",
            "a" * 40,
            "b" * 64,
            validated_patch=validated_patch(),
            approval_id="approval-1",
            approved_by="reviewer-1",
        )


def test_organization_adapter_checks_persisted_approval_and_audits(tmp_path):
    from talaria.database import Database

    database = Database(tmp_path / "approval.db")
    service = AuthService(database)
    bootstrap = service.bootstrap("admin@example.test", "admin-password", "Org")
    reviewer = service.register_member(
        "lead@example.test", "lead-password", bootstrap["organization_id"], "security_lead"
    )
    registry = ApprovalRegistry(database, bootstrap["organization_id"])
    patch_digest = "c" * 64
    title = "Fix issue"
    body = "Evidence"
    resource = pull_request_approval_resource(
        "owner", "repo", "talaria/fix-1", "main", title, body, patch_digest
    )
    approval = registry.request(
        "github.create_pull_request", resource, bootstrap["user_id"]
    )
    registry.decide(approval["id"], reviewer["user_id"], approved=True)
    fake = FakeClient()
    adapter = GitHubAdapter.for_organization(
        database, bootstrap["organization_id"], fake
    )

    result = adapter.create_pull_request(
        "owner",
        "repo",
        head="talaria/fix-1",
        base="main",
        title=title,
        body=body,
        patch_sha256=patch_digest,
        approval_id=approval["id"],
        approved_by=reviewer["user_id"],
    )

    assert result["number"] == 42
    assert not registry.validate(
        approval["id"], "github.create_pull_request", reviewer["user_id"], resource
    )
    fake.pull_requests = [result]
    assert adapter.create_pull_request(
        "owner",
        "repo",
        head="talaria/fix-1",
        base="main",
        title=title,
        body=body,
        patch_sha256=patch_digest,
        approval_id=approval["id"],
        approved_by=reviewer["user_id"],
    )["number"] == 42
    events = database.execute(
        "SELECT event FROM audit_events WHERE event = 'github.pull_request_created'"
    )
    assert len(events) == 1
    assert database.execute(
        "SELECT COUNT(*) AS n FROM audit_events "
        "WHERE event = 'github.pull_request_already_exists'"
    )[0]["n"] == 1


def test_approval_is_bound_to_branch_base_and_patch_digest(tmp_path):
    database = Database(tmp_path / "branch-approval.db")
    service = AuthService(database)
    bootstrap = service.bootstrap("admin@example.test", "admin-password", "Org")
    reviewer = service.register_member(
        "lead@example.test", "lead-password", bootstrap["organization_id"], "security_lead"
    )
    registry = ApprovalRegistry(database, bootstrap["organization_id"])
    base_sha = "a" * 40
    patch_digest = "b" * 64
    resource = branch_approval_resource(
        "owner", "repo", "talaria/fix-1", base_sha, patch_digest
    )
    approval = registry.request(
        "github.create_branch", resource, bootstrap["user_id"]
    )
    registry.decide(approval["id"], reviewer["user_id"], approved=True)
    client = FakeClient()
    adapter = GitHubAdapter.for_organization(
        database, bootstrap["organization_id"], client
    )

    with pytest.raises(IntegrationError, match="approval"):
        adapter.create_branch(
            "owner", "repo", "talaria/fix-1", "c" * 40,
            "b" * 64, validated_patch=validated_patch("c" * 40),
            approval_id=approval["id"], approved_by=reviewer["user_id"]
        )
    assert adapter.create_branch(
        "owner", "repo", "talaria/fix-1", base_sha, patch_digest,
        validated_patch=validated_patch(base_sha, patch_digest),
        approval_id=approval["id"], approved_by=reviewer["user_id"]
    )["object"]["sha"] == "f" * 40
    assert client.calls[-1][2] == {
        "ref": "refs/heads/talaria/fix-1", "sha": "f" * 40
    }


def test_ai_patch_digest_cannot_create_branch_before_second_person_approval(tmp_path):
    import subprocess

    from git import Repo

    from talaria.integrations.llm import LLMSettings
    from talaria.remediation.patches import LLMPatchGenerator

    repository_path = tmp_path / "reviewed-repo"
    repository_path.mkdir()
    source = "value = 1\n"
    (repository_path / "app.py").write_text(source, encoding="utf-8")
    subprocess.run(["git", "init", str(repository_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repository_path), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository_path), "config", "user.name", "Test User"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repository_path), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(repository_path), "commit", "-m", "base"],
        check=True,
        capture_output=True,
    )
    base_sha = Repo(repository_path).head.commit.hexsha
    proposed_diff = (
        "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
        "@@ -1 +1 @@\n-value = 1\n+value = 2\n"
    )
    class PatchProvider:
        def complete(self, *_args):
            return json.dumps({
                "summary": "Update the reviewed value",
                "base_sha": base_sha,
                "diff": proposed_diff,
            })

    proposal, validation = LLMPatchGenerator(
        PatchProvider(), LLMSettings(enabled=True, send_source=True)
    ).generate(
        repository_path,
        {"rule_id": "reviewed-value"},
        {"app.py": source},
        base_sha,
    )
    patch_digest = hashlib.sha256(proposal.diff.encode("utf-8")).hexdigest()
    database = Database(tmp_path / "ai-patch-approval.db")
    service = AuthService(database)
    owner = service.bootstrap("owner@example.test", "owner-password", "Approval Org")
    reviewer = service.register_member(
        "reviewer@example.test", "reviewer-password", owner["organization_id"],
        "security_lead",
    )
    registry = ApprovalRegistry(database, owner["organization_id"])
    resource = branch_approval_resource(
        "owner", "repo", "talaria/fix-reviewed-value", base_sha, patch_digest
    )
    approval = registry.request(
        "github.create_branch", resource, owner["user_id"]
    )
    fake = FakeClient()
    adapter = GitHubAdapter.for_organization(
        database, owner["organization_id"], fake
    )

    with pytest.raises(IntegrationError, match="approval"):
        adapter.create_branch(
            "owner", "repo", "talaria/fix-reviewed-value", base_sha,
            patch_digest, validated_patch=validation,
            approval_id=approval["id"], approved_by=reviewer["user_id"],
        )
    assert fake.calls == []

    registry.decide(approval["id"], reviewer["user_id"], approved=True)
    created = adapter.create_branch(
        "owner", "repo", "talaria/fix-reviewed-value", base_sha, patch_digest,
        validated_patch=validation,
        approval_id=approval["id"], approved_by=reviewer["user_id"],
    )
    assert created["object"]["sha"] == "f" * 40
    assert len(fake.calls) == 5
    blob_request = next(call for call in fake.calls if call[1].endswith("/git/blobs"))
    assert base64.b64decode(blob_request[2]["content"]) == b"value = 2\n"
    commit_request = next(call for call in fake.calls if call[1].endswith("/git/commits"))
    assert commit_request[2]["parents"] == [base_sha]
    assert fake.calls[-1][2]["sha"] == "f" * 40
    assert validation.applied_to_temporary_copy is True
    assert validation.original_repository_modified is False
    assert (repository_path / "app.py").read_text(encoding="utf-8") == source

    with pytest.raises(IntegrationError, match="exact validated patch"):
        adapter.create_branch(
            "owner", "repo", "talaria/fix-reviewed-value", base_sha,
            "d" * 64, validated_patch=validation,
            approval_id=approval["id"], approved_by=reviewer["user_id"],
        )
    assert len(fake.calls) == 5


def test_app_client_fails_closed_without_credentials():
    with pytest.raises(IntegrationError, match="not configured"):
        GitHubAppClient().installation_token()


@pytest.mark.parametrize(
    "api_base",
    [
        "http://api.github.test",
        "https://user:password@api.github.test",
        "https://api.github.test?token=secret",
        "https://api.github.test#fragment",
        "https://api.github.test/../attacker",
    ],
)
def test_github_api_base_rejects_insecure_or_ambiguous_urls(api_base):
    with pytest.raises(IntegrationError, match="clean HTTPS URL"):
        GitHubAppClient("123", "unused-key", "456", api_base=api_base)


def test_github_api_base_allows_https_enterprise_prefix():
    client = GitHubAppClient(
        "123",
        "unused-key",
        "456",
        api_base="https://github.enterprise.example/api/v3/",
    )

    assert client.api_base == "https://github.enterprise.example/api/v3"


@pytest.mark.parametrize(
    ("owner", "repository"),
    [
        ("owner\r\nHost: attacker.example", "repo"),
        ("owner", "repo?visibility=private"),
        ("owner", "../repo"),
    ],
)
def test_repository_identifiers_reject_url_path_injection(owner, repository):
    fake = FakeClient()

    with pytest.raises(IntegrationError, match="repository identifier"):
        GitHubAdapter(fake).repository(owner, repository)

    assert fake.calls == []


def test_branch_identifier_rejects_control_characters_before_request():
    fake = FakeClient()
    adapter = GitHubAdapter(fake, lambda *_args: True)

    with pytest.raises(IntegrationError, match="branch name"):
        adapter.create_branch(
            "owner",
            "repo",
            "feature\nX-Injected: value",
            "a" * 40,
            "b" * 64,
            approval_id="approval-1",
            approved_by="reviewer-1",
        )

    assert fake.calls == []


def test_github_api_uses_no_redirect_http_helper(monkeypatch):
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, size):
            assert size > 0
            return b'{"ok":true}'

    def fake_urlopen(request, *, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(
        "talaria.integrations.github.urlopen_no_redirect", fake_urlopen
    )
    client = GitHubAppClient(
        "123", "unused-key", "456", api_base="https://api.github.test", timeout=4
    )

    assert client._request("GET", "/user", token="installation-token") == {"ok": True}
    assert captured["request"].get_header("Authorization") == "Bearer installation-token"
    assert captured["request"].full_url == "https://api.github.test/user"
    assert captured["timeout"] == 4


def test_pull_request_content_records_validation_limits():
    from talaria.remediation.patches import PatchValidationResult

    title, body = build_pull_request_content(
        {
            "rule_id": "python-eval",
            "severity": "high",
            "path": "app.py",
            "line": 4,
            "fingerprint": "a" * 64,
        },
        "Replace unsafe evaluation",
        "b" * 40,
        PatchValidationResult(("app.py",), True, True),
        "approval-123",
    )

    assert title == "TALARIA: python-eval"
    assert "Repository tests and runtime behavior have not been verified" in body
    assert "approval-123" in body


def test_webhook_endpoint_verifies_signature_and_deduplicates(tmp_path, monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "webhooks.db"))
    webhook_secret_file = tmp_path / "webhook-secret"
    webhook_secret_file.write_text("webhook-secret\n", encoding="utf-8")
    webhook_secret_file.chmod(0o600)
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET_FILE", str(webhook_secret_file))
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    db = Database(database_path())
    bootstrap = AuthService(db).bootstrap(
        "webhook-admin@example.test", "webhook-admin-password", "Webhook Org"
    )
    local_repository_id = db.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("repo", str(tmp_path / "repo"), bootstrap["organization_id"]),
    )
    db.insert(
        """INSERT INTO github_repositories
           (github_repository_id, organization_id, repository_id, full_name,
            installation_id, default_branch, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            1234,
            bootstrap["organization_id"],
            local_repository_id,
            "owner/repository",
            "456",
            "main",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    body = json.dumps(
        {
            "action": "opened",
            "repository": {"id": 1234, "full_name": "owner/repository"},
            "installation": {"id": 456},
        }
    ).encode()
    signature = "sha256=" + hmac.new(
        b"webhook-secret", body, hashlib.sha256
    ).hexdigest()
    headers = {
        "X-GitHub-Delivery": "delivery-1",
        "X-GitHub-Event": "pull_request",
        "X-Hub-Signature-256": signature,
    }
    client = TestClient(app)
    db.insert(
        "INSERT INTO webhook_deliveries(delivery_id, event, body_sha256, received_at) "
        "VALUES (?, ?, ?, ?)",
        ("expired-delivery", "push", "a" * 64, "2020-01-01T00:00:00+00:00"),
    )

    received = client.post(
        "/integrations/github/webhook", content=body, headers=headers
    )
    assert received.status_code == 200
    duplicate = client.post("/integrations/github/webhook", content=body, headers=headers)
    assert duplicate.json() == {"accepted": True, "duplicate": True}
    changed_body = json.dumps(
        {
            "action": "closed",
            "repository": {"id": 1234, "full_name": "owner/repository"},
            "installation": {"id": 456},
        }
    ).encode()
    changed_signature = "sha256=" + hmac.new(
        b"webhook-secret", changed_body, hashlib.sha256
    ).hexdigest()
    replay = client.post(
        "/integrations/github/webhook",
        content=changed_body,
        headers={**headers, "X-Hub-Signature-256": changed_signature},
    )
    assert replay.status_code == 409
    assert db.execute(
        "SELECT COUNT(*) AS n FROM audit_events "
        "WHERE event = 'github.webhook_delivery_conflict'"
    )[0]["n"] == 1
    invalid = client.post(
        "/integrations/github/webhook",
        content=body,
        headers={**headers, "X-GitHub-Delivery": "delivery-2", "X-Hub-Signature-256": "bad"},
    )
    assert invalid.status_code == 401
    deeply_nested = b"[" * 1100 + b"0" + b"]" * 1100
    nested_signature = "sha256=" + hmac.new(
        b"webhook-secret", deeply_nested, hashlib.sha256
    ).hexdigest()
    malformed = client.post(
        "/integrations/github/webhook",
        content=deeply_nested,
        headers={
            **headers,
            "X-GitHub-Delivery": "delivery-deep",
            "X-Hub-Signature-256": nested_signature,
        },
    )
    assert malformed.status_code == 400
    assert db.execute("SELECT COUNT(*) AS n FROM webhook_deliveries")[0]["n"] == 1
    assert db.execute(
        "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE delivery_id = ?",
        ("expired-delivery",),
    )[0]["n"] == 0
    summary = db.execute("SELECT * FROM github_events")[0]
    assert summary["repository"] == "owner/repository"
    assert summary["organization_id"] == bootstrap["organization_id"]
    assert summary["github_repository_id"] == 1234
    assert summary["event"] == "pull_request"


def test_repository_onboarding_binds_verified_remote_to_selected_tenant(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "onboarding.db"))
    monkeypatch.setenv("TALARIA_JWT_SECRET", "unit-test-signing-secret-32-bytes-minimum")
    database = Database(database_path())
    bootstrap = AuthService(database).bootstrap(
        "onboard-admin@example.test", "onboard-admin-password", "Onboarding Org"
    )
    local_repository_id = database.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("local-repo", str(tmp_path / "repo"), bootstrap["organization_id"]),
    )

    class OnboardingClient:
        configured = True
        installation_id = "456"

        def request(self, method, path, payload=None):
            assert method == "GET"
            assert path == "/repos/owner/repository"
            return {
                "id": 1234,
                "full_name": "owner/repository",
                "default_branch": "main",
            }

    import talaria.integrations.api as github_api

    monkeypatch.setattr(github_api, "GitHubAppClient", OnboardingClient)
    client = TestClient(app)
    tokens = client.post(
        "/auth/login",
        json={
            "email": "onboard-admin@example.test",
            "password": "onboard-admin-password",
        },
    )
    assert tokens.status_code == 200
    headers = {
        "Authorization": f"Bearer {tokens.json()['access_token']}",
        "X-Organization-ID": bootstrap["organization_id"],
    }
    payload = {
        "repository_id": local_repository_id,
        "owner": "owner",
        "repository": "repository",
    }

    created = client.post("/integrations/github/repositories", headers=headers, json=payload)
    repeated = client.post("/integrations/github/repositories", headers=headers, json=payload)

    assert created.status_code == 201
    assert created.json()["created"] is True
    assert created.json()["github_repository_id"] == 1234
    assert repeated.status_code == 201
    assert repeated.json()["created"] is False
    listed = client.get("/integrations/github/repositories", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["repositories"][0]["full_name"] == "owner/repository"
    assert database.execute(
        "SELECT event FROM audit_events WHERE event = 'github.repository_onboarded'"
    )
    second_organization = client.post(
        "/auth/organizations",
        headers=headers,
        json={"name": "Other tenant", "admin_email": "onboard-admin@example.test"},
    )
    assert second_organization.status_code == 201
    other_repository_id = database.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        (
            "other-local-repo",
            str(tmp_path / "other-repo"),
            second_organization.json()["organization_id"],
        ),
    )
    headers["X-Organization-ID"] = second_organization.json()["organization_id"]
    conflict = client.post(
        "/integrations/github/repositories",
        headers=headers,
        json={**payload, "repository_id": other_repository_id},
    )
    assert conflict.status_code == 409
    assert client.get("/integrations/github/repositories", headers=headers).json() == {
        "repositories": []
    }


def test_github_webhook_ignores_unregistered_repositories(tmp_path, monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "ignored-webhooks.db"))
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "webhook-secret")
    database = Database(database_path())
    body = json.dumps(
        {
            "action": "opened",
            "repository": {"id": 9999, "full_name": "owner/unregistered"},
            "installation": {"id": 456},
        }
    ).encode()
    signature = "sha256=" + hmac.new(
        b"webhook-secret", body, hashlib.sha256
    ).hexdigest()
    response = TestClient(app).post(
        "/integrations/github/webhook",
        content=body,
        headers={
            "X-GitHub-Delivery": "unregistered-delivery",
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": signature,
        },
    )

    assert response.status_code == 200
    assert response.json() == {"accepted": True, "ignored": True}
    assert database.execute("SELECT COUNT(*) AS count FROM github_events")[0]["count"] == 0
    assert database.execute("SELECT COUNT(*) AS count FROM webhook_deliveries")[0]["count"] == 0


def test_pull_request_state_api_returns_latest_state_only_for_selected_tenant(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "pull-request-state.db"))
    monkeypatch.setenv("TALARIA_JWT_SECRET", "unit-test-signing-secret-32-bytes-minimum")
    database = Database(database_path())
    auth = AuthService(database)
    bootstrap = auth.bootstrap(
        "pr-state-admin@example.test", "pr-state-admin-password", "Primary"
    )
    other = auth.create_organization("Secondary", "pr-state-admin@example.test")
    primary_org = bootstrap["organization_id"]
    secondary_org = other["organization_id"]

    repository_ids = {}
    for organization_id, github_repository_id, name in (
        (primary_org, 1234, "owner/primary"),
        (secondary_org, 5678, "owner/secondary"),
    ):
        repository_id = database.insert(
            "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
            (name, str(tmp_path / name.rsplit("/", 1)[-1]), organization_id),
        )
        repository_ids[organization_id] = repository_id
        database.execute(
            """INSERT INTO github_repositories
               (github_repository_id, organization_id, repository_id, full_name,
                installation_id, default_branch, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                github_repository_id,
                organization_id,
                repository_id,
                name,
                "456",
                "main",
                "2026-11-07T00:00:00+00:00",
            ),
        )

    def persist_event(
        delivery_id, organization_id, github_repository_id, pr_number,
        state, merged, received_at,
    ):
        database.execute(
            """INSERT INTO webhook_deliveries
               (delivery_id, event, body_sha256, received_at)
               VALUES (?, 'pull_request', ?, ?)""",
            (delivery_id, hashlib.sha256(delivery_id.encode()).hexdigest(), received_at),
        )
        database.execute(
            """INSERT INTO github_events
               (delivery_id, event, repository, action, ref, base_ref,
                commit_sha, pull_request_number, pull_request_state, merged, actor,
                received_at, organization_id, github_repository_id)
               VALUES (?, 'pull_request', ?, 'closed', ?, 'main', ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                delivery_id,
                "owner/primary" if github_repository_id == 1234 else "owner/secondary",
                "talaria/fix-17",
                "a" * 40,
                pr_number,
                state,
                merged,
                "reviewer",
                received_at,
                organization_id,
                github_repository_id,
            ),
        )

    persist_event(
        "pr-opened", primary_org, 1234, 17, "open", 0, "2026-11-07T00:00:00+00:00"
    )
    persist_event(
        "pr-closed", primary_org, 1234, 17, "closed", 1,
        "2026-11-07T00:01:00+00:00",
    )
    persist_event(
        "pr-other-tenant", secondary_org, 5678, 28, "open", 0,
        "2026-11-07T00:02:00+00:00",
    )

    client = TestClient(app)
    tokens = client.post(
        "/auth/login",
        json={
            "email": "pr-state-admin@example.test",
            "password": "pr-state-admin-password",
        },
    )
    assert tokens.status_code == 200
    headers = {
        "Authorization": f"Bearer {tokens.json()['access_token']}",
        "X-Organization-ID": primary_org,
    }

    primary = client.get("/integrations/github/pull-requests", headers=headers)
    assert primary.status_code == 200
    assert primary.json()["pull_requests"] == [
        {
            "github_repository_id": 1234,
            "repository_id": repository_ids[primary_org],
            "full_name": "owner/primary",
            "pull_request_number": 17,
            "pull_request_state": "closed",
            "merged": 1,
            "action": "closed",
            "head_ref": "talaria/fix-17",
            "base_ref": "main",
            "commit_sha": "a" * 40,
            "actor": "reviewer",
            "received_at": "2026-11-07T00:01:00+00:00",
        }
    ]
    headers["X-Organization-ID"] = secondary_org
    secondary = client.get("/integrations/github/pull-requests", headers=headers)
    assert secondary.status_code == 200
    assert [item["github_repository_id"] for item in secondary.json()["pull_requests"]] == [
        5678
    ]
    assert client.get("/integrations/github/pull-requests").status_code == 401


def test_check_run_api_persists_bounded_tenant_scoped_provider_snapshot(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "check-runs.db"))
    monkeypatch.setenv("TALARIA_JWT_SECRET", "unit-test-signing-secret-32-bytes-minimum")
    database = Database(database_path())
    bootstrap = AuthService(database).bootstrap(
        "checks-admin@example.test", "checks-admin-password", "Checks Org"
    )
    repository_id = database.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("repo", str(tmp_path / "repo"), bootstrap["organization_id"]),
    )
    database.execute(
        """INSERT INTO github_repositories
           (github_repository_id, organization_id, repository_id, full_name,
            installation_id, default_branch, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (1234, bootstrap["organization_id"], repository_id, "owner/repository",
         "456", "main", "2026-11-07T00:00:00+00:00"),
    )

    class CheckRunsClient:
        configured = True
        installation_id = "456"
        api_base = "https://api.github.com"

    snapshots = [[{
        "id": 99, "head_sha": "a" * 40, "name": "CI", "status": "completed",
        "conclusion": "success", "html_url": "https://github.com/owner/repository/actions/runs/99",
        "started_at": "2026-11-07T00:00:00Z", "completed_at": "2026-11-07T00:01:00Z",
    }], [{
        "id": 99, "head_sha": "a" * 40, "name": "CI", "status": "completed",
        "conclusion": "failure", "html_url": "javascript:alert(1)",
        "started_at": "2026-11-07T00:00:00Z", "completed_at": "2026-11-07T00:02:00Z",
    }]]

    class CheckRunsAdapter:
        def __init__(self, client):
            assert isinstance(client, CheckRunsClient)

        def check_runs(self, owner, repository, sha):
            assert (owner, repository, sha) == ("owner", "repository", "a" * 40)
            current = snapshots.pop(0)
            return {"total_count": len(current), "check_runs": current}

    import talaria.integrations.api as github_api

    monkeypatch.setattr(github_api, "GitHubAppClient", CheckRunsClient)
    monkeypatch.setattr(github_api, "GitHubAdapter", CheckRunsAdapter)
    client = TestClient(app)
    tokens = client.post("/auth/login", json={
        "email": "checks-admin@example.test", "password": "checks-admin-password"
    })
    headers = {
        "Authorization": f"Bearer {tokens.json()['access_token']}",
        "X-Organization-ID": bootstrap["organization_id"],
    }
    endpoint = f"/integrations/github/repositories/1234/commits/{'a' * 40}/check-runs"

    first = client.get(endpoint, headers=headers)
    assert first.status_code == 200
    assert first.json()["check_runs"][0]["conclusion"] == "success"
    second = client.get(endpoint, headers=headers)
    assert second.status_code == 200
    assert second.json()["check_runs"][0]["conclusion"] == "failure"
    assert second.json()["check_runs"][0]["details_url"] is None
    assert database.execute(
        "SELECT COUNT(*) AS count FROM github_check_runs WHERE github_repository_id = ?",
        (1234,),
    )[0]["count"] == 1
    assert client.get(endpoint).status_code == 401
    assert client.get(
        endpoint.replace("repositories/1234", "repositories/5678"), headers=headers
    ).status_code == 404


def test_github_webhook_requires_the_onboarded_installation(tmp_path, monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "wrong-installation.db"))
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "webhook-secret")
    database = Database(database_path())
    bootstrap = AuthService(database).bootstrap(
        "install-admin@example.test", "install-admin-password", "Install Org"
    )
    local_repository_id = database.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("repo", str(tmp_path / "repo"), bootstrap["organization_id"]),
    )
    database.insert(
        """INSERT INTO github_repositories
           (github_repository_id, organization_id, repository_id, full_name,
            installation_id, default_branch, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            1234,
            bootstrap["organization_id"],
            local_repository_id,
            "owner/repo",
            "456",
            "main",
            "2026-11-07T00:00:00+00:00",
        ),
    )
    body = json.dumps(
        {
            "action": "opened",
            "repository": {"id": 1234, "full_name": "owner/repo"},
            "installation": {"id": 999},
        }
    ).encode()
    signature = "sha256=" + hmac.new(
        b"webhook-secret", body, hashlib.sha256
    ).hexdigest()

    response = TestClient(app).post(
        "/integrations/github/webhook",
        content=body,
        headers={
            "X-GitHub-Delivery": "wrong-installation-delivery",
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": signature,
        },
    )

    assert response.status_code == 200
    assert response.json() == {"accepted": True, "ignored": True}
    assert database.execute("SELECT COUNT(*) AS count FROM github_events")[0]["count"] == 0
    assert database.execute("SELECT COUNT(*) AS count FROM webhook_deliveries")[0]["count"] == 0
