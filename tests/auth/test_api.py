"""Authentication and authorization API behavior."""

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from talaria.api import app
from talaria.auth.approvals import ApprovalError, ApprovalRegistry
from talaria.auth.service import AuthenticationError, AuthService
from talaria.config import database_path
from talaria.database import Database


@pytest.fixture
def auth_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "auth.db"))
    monkeypatch.delenv("TALARIA_JWT_SECRET_FILE", raising=False)
    monkeypatch.delenv("TALARIA_BOOTSTRAP_TOKEN_FILE", raising=False)
    monkeypatch.setenv("TALARIA_JWT_SECRET", "unit-test-signing-secret-32-bytes-minimum")
    monkeypatch.setenv("TALARIA_BOOTSTRAP_TOKEN", "bootstrap-secret-for-tests")
    db = Database(database_path())
    client = TestClient(app)
    response = client.post(
        "/auth/bootstrap",
        headers={"X-Talaria-Bootstrap-Token": "bootstrap-secret-for-tests"},
        json={
            "email": "root@example.test",
            "password": "strong-test-password",
            "organization_name": "Primary",
        },
    )
    assert response.status_code == 201
    organization_id = response.json()["organization_id"]
    return client, db, organization_id


def login(client, email="root@example.test", password="strong-test-password"):
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}, response.json()


def test_protected_api_requires_bearer_token(auth_environment):
    client, _, _ = auth_environment

    assert client.get("/repositories").status_code == 401
    assert client.get("/health").status_code == 200


def test_application_startup_fails_closed_without_jwt_signing_secret(
    auth_environment, monkeypatch
):
    monkeypatch.setenv("TALARIA_JWT_SECRET", "short")
    monkeypatch.delenv("TALARIA_JWT_SECRET_FILE", raising=False)

    with pytest.raises(ValueError, match="JWT signing configuration is invalid"):
        with TestClient(app):
            pass


def test_bootstrap_is_secret_gated_and_one_time(auth_environment):
    client, _, _ = auth_environment
    payload = {
        "email": "second@example.test",
        "password": "another-long-password",
        "organization_name": "Second",
    }

    assert client.post("/auth/bootstrap", json=payload).status_code == 403
    response = client.post(
        "/auth/bootstrap",
        headers={"X-Talaria-Bootstrap-Token": "bootstrap-secret-for-tests"},
        json=payload,
    )
    assert response.status_code == 409


def test_bootstrap_reads_token_from_mounted_secret_file(
    auth_environment, tmp_path, monkeypatch
):
    client, _, _ = auth_environment
    secret_file = tmp_path / "bootstrap-token"
    secret_file.write_text("mounted-bootstrap-token\n", encoding="utf-8")
    secret_file.chmod(0o600)
    monkeypatch.setenv("TALARIA_BOOTSTRAP_TOKEN_FILE", str(secret_file))

    headers = {"X-Talaria-Bootstrap-Token": "mounted-bootstrap-token"}
    response = client.post(
        "/auth/bootstrap",
        headers=headers,
        json={
            "email": "second@example.test",
            "password": "another-long-password",
            "organization_name": "Second",
        },
    )
    assert response.status_code == 409  # Correct secret; bootstrap already completed.


def test_concurrent_bootstrap_creates_only_one_platform_admin(tmp_path):
    database = Database(tmp_path / "bootstrap-race.db")

    def attempt(index):
        try:
            AuthService(database).bootstrap(
                f"admin{index}@example.test", "race-safe-bootstrap-password", "Org"
            )
            return "created"
        except AuthenticationError:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, range(2)))

    assert sorted(outcomes) == ["created", "denied"]
    assert database.execute("SELECT COUNT(*) AS total FROM users")[0]["total"] == 1
    assert database.execute(
        "SELECT COUNT(*) AS total FROM organizations"
    )[0]["total"] == 1


def test_account_provisioning_rejects_short_password(auth_environment):
    client, _, _ = auth_environment
    headers, _ = login(client)
    response = client.post(
        "/auth/register",
        headers=headers,
        json={"email": "weak@example.test", "password": "short", "role": "developer"},
    )

    assert response.status_code == 422


def test_login_me_and_refresh_rotation(auth_environment):
    client, _, organization_id = auth_environment
    headers, tokens = login(client)
    identity = client.get("/auth/me", headers=headers)
    assert identity.status_code == 200
    assert identity.json()["organization_id"] == organization_id
    assert identity.json()["is_platform_admin"] is True

    refreshed = client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refreshed.status_code == 200
    assert refreshed.json()["refresh_token"] != tokens["refresh_token"]

    reused = client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert reused.status_code == 401
    assert client.post(
        "/auth/refresh",
        json={"refresh_token": refreshed.json()["refresh_token"]},
    ).status_code == 401


def test_successful_login_rehashes_password_with_current_argon2_parameters(
    auth_environment,
):
    client, database, _ = auth_environment
    weak_hasher = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    weak_hash = weak_hasher.hash("strong-test-password")
    database.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (weak_hash, "root@example.test"),
    )

    response = client.post(
        "/auth/login",
        json={"email": "root@example.test", "password": "strong-test-password"},
    )

    assert response.status_code == 200
    upgraded_hash = database.execute(
        "SELECT password_hash FROM users WHERE email = ?", ("root@example.test",)
    )[0]["password_hash"]
    assert upgraded_hash != weak_hash
    assert upgraded_hash.startswith("$argon2id$")
    assert PasswordHasher().verify(upgraded_hash, "strong-test-password") is True
    assert database.execute(
        "SELECT event FROM audit_events WHERE event = 'auth.password_hash_upgraded'"
    )


def test_deactivated_user_loses_access_and_refresh_tokens(auth_environment):
    client, db, organization_id = auth_environment
    headers, tokens = login(client)
    headers["X-Organization-ID"] = organization_id
    user_id = db.execute(
        "SELECT id FROM users WHERE email = ?", ("root@example.test",)
    )[0]["id"]

    db.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))

    assert client.get("/repositories", headers=headers).status_code == 401
    assert client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    ).status_code == 401
    assert db.execute(
        "SELECT COUNT(*) AS total FROM refresh_sessions "
        "WHERE subject = ? AND revoked_at IS NULL",
        (user_id,),
    )[0]["total"] == 0


def test_deactivated_organization_revokes_member_tenant_access(auth_environment):
    client, db, organization_id = auth_environment
    headers, _ = login(client)
    created = client.post(
        "/auth/register",
        headers={**headers, "X-Organization-ID": organization_id},
        json={
            "email": "inactive-org-member@example.test",
            "password": "inactive-org-member-password",
            "role": "developer",
        },
    )
    assert created.status_code == 201

    member_headers, _ = login(
        client,
        "inactive-org-member@example.test",
        "inactive-org-member-password",
    )
    member_headers["X-Organization-ID"] = organization_id
    assert client.get("/repositories", headers=member_headers).status_code == 200

    db.execute(
        "UPDATE organizations SET is_active = 0 WHERE id = ?", (organization_id,)
    )

    assert client.get("/repositories", headers=member_headers).status_code == 403
    identity = client.get(
        "/auth/me", headers={"Authorization": member_headers["Authorization"]}
    )
    assert identity.status_code == 200
    assert identity.json()["memberships"] == []


def test_logout_revokes_only_presented_refresh_session(auth_environment):
    client, _, _ = auth_environment
    _, tokens = login(client)
    other = client.post(
        "/auth/login",
        json={"email": "root@example.test", "password": "strong-test-password"},
    ).json()
    response = client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert response.status_code == 200
    assert response.json()["revoked"] is True
    assert client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    ).status_code == 401
    assert client.post(
        "/auth/refresh", json={"refresh_token": other["refresh_token"]}
    ).status_code == 200


def test_logout_all_revokes_all_user_refresh_sessions(auth_environment):
    client, db, _ = auth_environment
    headers, _ = login(client)
    first = client.post(
        "/auth/login",
        json={"email": "root@example.test", "password": "strong-test-password"},
    ).json()
    response = client.post("/auth/logout-all", headers=headers)

    assert response.status_code == 200
    assert response.json()["sessions_revoked"] == 2
    assert db.execute(
        "SELECT COUNT(*) AS n FROM refresh_sessions "
        "WHERE revoked_at IS NULL AND subject = (SELECT id FROM users LIMIT 1)"
    )[0]["n"] == 0
    assert client.post(
        "/auth/refresh", json={"refresh_token": first["refresh_token"]}
    ).status_code == 401


def test_platform_admin_can_create_organization_for_existing_user(auth_environment):
    client, _, _ = auth_environment
    headers, _ = login(client)
    created_user = client.post(
        "/auth/register",
        headers=headers,
        json={
            "email": "org-admin@example.test",
            "password": "org-admin-password",
            "role": "developer",
        },
    )
    assert created_user.status_code == 201
    organization = client.post(
        "/auth/organizations",
        headers=headers,
        json={"name": "Second Org", "admin_email": "org-admin@example.test"},
    )
    assert organization.status_code == 201
    assert organization.json()["admin_user_id"] == created_user.json()["user_id"]

    org_headers, _ = login(client, "org-admin@example.test", "org-admin-password")
    org_headers["X-Organization-ID"] = organization.json()["organization_id"]
    assert client.get("/auth/me", headers=org_headers).json()["role"] == "org_admin"


def test_platform_admin_must_select_organization_before_registering_member(
    auth_environment,
):
    client, db, _ = auth_environment
    headers, _ = login(client)
    organization = client.post(
        "/auth/organizations",
        headers=headers,
        json={"name": "Second Org", "admin_email": "root@example.test"},
    )
    assert organization.status_code == 201

    payload = {
        "email": "member@example.test",
        "password": "member-test-password",
        "role": "developer",
    }
    missing_selection = client.post("/auth/register", headers=headers, json=payload)

    assert missing_selection.status_code == 400
    assert missing_selection.json() == {"detail": "Select an organization"}
    assert db.execute(
        "SELECT COUNT(*) AS count FROM users WHERE email = ?",
        (payload["email"],),
    )[0]["count"] == 0

    headers["X-Organization-ID"] = organization.json()["organization_id"]
    selected = client.post("/auth/register", headers=headers, json=payload)
    assert selected.status_code == 201


def test_platform_admin_data_access_still_requires_explicit_tenant_scope(
    auth_environment,
):
    client, db, first_organization_id = auth_environment
    headers, _ = login(client)
    second = client.post(
        "/auth/organizations",
        headers=headers,
        json={"name": "Second tenant", "admin_email": "root@example.test"},
    )
    assert second.status_code == 201
    second_organization_id = second.json()["organization_id"]
    first_repository_id = db.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("first-repo", "/first-repo", first_organization_id),
    )
    db.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("second-repo", "/second-repo", second_organization_id),
    )

    assert client.get("/repositories", headers=headers).status_code == 400
    headers["X-Organization-ID"] = first_organization_id
    first_result = client.get("/repositories", headers=headers)
    assert first_result.status_code == 200
    assert [item["id"] for item in first_result.json()] == [first_repository_id]
    headers["X-Organization-ID"] = second_organization_id
    second_result = client.get("/repositories", headers=headers)
    assert second_result.status_code == 200
    assert [item["name"] for item in second_result.json()] == ["second-repo"]


def test_external_action_approval_requires_a_second_organization_member(
    auth_environment,
):
    client, db, organization_id = auth_environment
    requester_headers, _ = login(client)
    created = client.post(
        "/auth/register",
        headers=requester_headers,
        json={
            "email": "lead@example.test",
            "password": "lead-test-password",
            "role": "security_lead",
        },
    )
    assert created.status_code == 201
    requested = client.post(
        "/auth/approvals",
        headers=requester_headers,
        json={
            "action": "github.create_pull_request",
            "resource": "owner/repo",
        },
    )
    assert requested.status_code == 201
    approval_id = requested.json()["id"]

    self_approval = client.post(
        f"/auth/approvals/{approval_id}/decision",
        headers=requester_headers,
        json={"approved": True},
    )
    assert self_approval.status_code == 409

    reviewer_headers, _ = login(client, "lead@example.test", "lead-test-password")
    reviewer_headers["X-Organization-ID"] = organization_id
    decision = client.post(
        f"/auth/approvals/{approval_id}/decision",
        headers=reviewer_headers,
        json={"approved": True},
    )
    assert decision.status_code == 200
    reviewer_id = created.json()["user_id"]
    registry = ApprovalRegistry(db, organization_id)
    assert registry.validate(
        approval_id,
        "github.create_pull_request",
        reviewer_id,
        "owner/repo",
    )
    assert not registry.validate(
        approval_id,
        "github.create_pull_request",
        reviewer_id,
        "other/repo",
    )


def test_approval_registry_rechecks_requester_and_reviewer_roles_transactionally(
    auth_environment,
):
    _, database, organization_id = auth_environment
    admin = AuthService(database)
    developer = admin.register_member(
        "developer@example.test",
        "developer-test-password",
        organization_id,
        "developer",
    )
    registry = ApprovalRegistry(database, organization_id)

    with pytest.raises(ApprovalError, match="organization administrator"):
        registry.request(
            "github.create_branch", "owner/repo:patch", developer["user_id"]
        )
    assert database.execute(
        "SELECT COUNT(*) AS count FROM approval_records"
    )[0]["count"] == 0

    reviewer = admin.register_member(
        "security-lead@example.test",
        "reviewer-test-password",
        organization_id,
        "security_lead",
    )
    approval = registry.request(
        "github.create_branch", "owner/repo:patch", database.execute(
            "SELECT id FROM users WHERE email = ?", ("root@example.test",)
        )[0]["id"]
    )
    database.execute("UPDATE users SET is_active = 0 WHERE id = ?", (reviewer["user_id"],))

    with pytest.raises(ApprovalError, match="active organization administrator"):
        registry.decide(approval["id"], reviewer["user_id"], approved=True)
    assert database.execute(
        "SELECT status FROM approval_records WHERE id = ?", (approval["id"],)
    ) == [{"status": "pending"}]


@pytest.mark.parametrize("approved", [1, "yes", None])
def test_approval_registry_rejects_non_boolean_decisions(auth_environment, approved):
    _, database, organization_id = auth_environment
    actor_id = database.execute(
        "SELECT id FROM users WHERE email = ?", ("root@example.test",)
    )[0]["id"]
    registry = ApprovalRegistry(database, organization_id)

    with pytest.raises(ApprovalError, match="boolean"):
        registry.decide("approval-id", actor_id, approved)


def test_invalid_login_does_not_disclose_account_existence(auth_environment):
    client, _, _ = auth_environment
    known = client.post(
        "/auth/login",
        json={"email": "root@example.test", "password": "wrong-password"},
    )
    unknown = client.post(
        "/auth/login",
        json={"email": "missing@example.test", "password": "wrong-password"},
    )

    assert known.status_code == unknown.status_code == 401
    assert known.json() == unknown.json()


def test_login_rejects_password_over_utf8_limit_before_password_verification(
    auth_environment, monkeypatch
):
    client, database, _ = auth_environment
    monkeypatch.setattr(
        "talaria.auth.service.verify_password",
        lambda *_args: pytest.fail("oversized password must not reach Argon2"),
    )

    response = client.post(
        "/auth/login",
        json={"email": "root@example.test", "password": "é" * 513},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}
    assert database.execute(
        "SELECT event FROM audit_events WHERE event = 'auth.login_failed'"
    )


def test_member_role_cannot_cross_organization_or_escalate(auth_environment):
    client, db, organization_id = auth_environment
    headers, _ = login(client)
    created = client.post(
        "/auth/register",
        headers=headers,
        json={
            "email": "developer@example.test",
            "password": "developer-password",
            "role": "developer",
        },
    )
    assert created.status_code == 201
    assert created.json()["role"] == "developer"

    user_id = created.json()["user_id"]
    organization_b = "organization-b"
    db.insert(
        "INSERT INTO organizations(id, name, created_at) VALUES (?, ?, ?)",
        (organization_b, "Other", "2026-11-06T00:00:00+00:00"),
    )
    db.insert(
        "INSERT INTO organization_memberships(user_id, organization_id, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        (user_id, organization_b, "developer", "2026-11-06T00:00:00+00:00"),
    )

    member_headers, _ = login(client, "developer@example.test", "developer-password")
    no_org = client.get("/auth/me", headers=member_headers)
    assert no_org.status_code == 200
    assert no_org.json()["organization_id"] is None
    assert len(no_org.json()["memberships"]) == 2
    assert client.get(
        "/repositories",
        headers={**member_headers, "X-Organization-ID": organization_id},
    ).status_code == 200
    assert client.get(
        "/repositories",
        headers={**member_headers, "X-Organization-ID": "not-a-member"},
    ).status_code == 403
    assert client.post(
        "/auth/register",
        headers={**member_headers, "X-Organization-ID": organization_id},
        json={
            "email": "escalation@example.test",
            "password": "some-password",
            "role": "org_admin",
        },
    ).status_code == 403
    assert db.execute(
        "SELECT COUNT(*) AS n FROM organization_memberships WHERE organization_id = ?",
        (organization_id,),
    )[0]["n"] == 2


def test_findings_are_tenant_scoped(auth_environment):
    client, db, organization_id = auth_environment
    headers, _ = login(client)
    other_org = "tenant-isolation-org"
    db.insert(
        "INSERT INTO organizations(id, name, created_at) VALUES (?, ?, ?)",
        (other_org, "Other tenant", "2026-11-06T00:00:00+00:00"),
    )
    repo_id = db.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("tenant-repo", "/tmp/tenant-repo", other_org),
    )
    scan_id = db.insert(
        "INSERT INTO scans(repository_id) VALUES (?)", (repo_id,)
    )
    finding_id = db.insert(
        """INSERT INTO findings
           (fingerprint, repository_id, payload, first_seen_at, last_seen_at)
           VALUES (?, ?, ?, ?, ?)""",
        ("d" * 64, repo_id, json.dumps({"severity": "high"}), "now", "now"),
    )
    db.insert(
        "INSERT INTO finding_occurrences(finding_id, scan_id, observed_at) VALUES (?, ?, ?)",
        (finding_id, scan_id, "2026-11-06T00:00:00+00:00"),
    )

    assert client.get("/findings", headers=headers).json() == []
    assert client.get(f"/findings/{finding_id}", headers=headers).status_code == 404
    assert client.patch(
        f"/findings/{finding_id}/status",
        headers=headers,
        json={"status": "confirmed"},
    ).status_code == 404
    # A platform administrator must explicitly select the other tenant.
    assert client.get(
        "/findings",
        headers={**headers, "X-Organization-ID": other_org},
    ).json()[0]["id"] == finding_id


def test_bootstrap_assigns_legacy_repositories_to_initial_organization(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "legacy.db"))
    monkeypatch.delenv("TALARIA_JWT_SECRET_FILE", raising=False)
    monkeypatch.delenv("TALARIA_BOOTSTRAP_TOKEN_FILE", raising=False)
    monkeypatch.setenv("TALARIA_JWT_SECRET", "unit-test-signing-secret-32-bytes-minimum")
    monkeypatch.setenv("TALARIA_BOOTSTRAP_TOKEN", "bootstrap-secret-for-tests")
    db = Database(database_path())
    db.insert(
        "INSERT INTO repositories(name, path) VALUES (?, ?)",
        ("legacy", "/tmp/legacy"),
    )
    response = TestClient(app).post(
        "/auth/bootstrap",
        headers={"X-Talaria-Bootstrap-Token": "bootstrap-secret-for-tests"},
        json={
            "email": "owner@example.test",
            "password": "owner-password",
            "organization_name": "Imported local data",
        },
    )

    assert response.status_code == 201
    assert db.execute("SELECT organization_id FROM repositories")[0][
        "organization_id"
    ] == response.json()["organization_id"]
