"""Exercise representative API operations against every organization role."""

import pytest
from fastapi.testclient import TestClient

from talaria.api import app
from talaria.auth.service import AuthService
from talaria.config import database_path
from talaria.database import Database

pytestmark = pytest.mark.security

ROLES = (
    "org_admin",
    "security_lead",
    "security_analyst",
    "developer",
    "auditor",
)

OPERATIONS = (
    ("GET", "/repositories", set(ROLES), None, 200),
    ("GET", "/auth/me", set(ROLES), None, 200),
    ("GET", "/dashboard/summary", set(ROLES), None, 200),
    ("GET", "/dashboard/severity", set(ROLES), None, 200),
    ("GET", "/dashboard/trends", set(ROLES), None, 200),
    ("GET", "/scans", set(ROLES), None, 200),
    ("GET", "/findings", set(ROLES), None, 200),
    (
        "GET",
        "/investigations",
        {"org_admin", "security_lead", "security_analyst", "auditor"},
        None,
        200,
    ),
    (
        "GET",
        "/integrations/github/repositories",
        {"org_admin", "security_lead", "security_analyst", "auditor"},
        None,
        200,
    ),
    (
        "GET",
        "/integrations/github/pull-requests",
        {"org_admin", "security_lead", "security_analyst", "auditor"},
        None,
        200,
    ),
    (
        "GET",
        "/integrations/github/repositories/{github_repository_id}/commits/{sha}/check-runs",
        {"org_admin", "security_lead", "security_analyst", "auditor"},
        None,
        404,
    ),
    ("GET", "/findings/1", set(ROLES), None, 200),
    (
        "POST",
        "/findings/1/investigate",
        {"org_admin", "security_lead", "security_analyst"},
        None,
        503,
    ),
    (
        "POST",
        "/auth/organizations",
        set(),
        {"name": "Denied", "admin_email": "matrix-root@example.test"},
        403,
    ),
    (
        "POST",
        "/integrations/github/repositories",
        set(),
        {"repository_id": 1, "owner": "owner", "repository": "repo"},
        403,
    ),
    (
        "POST",
        "/repositories",
        {"org_admin", "security_lead"},
        {"path": "/not/a/registered/repository"},
        400,
    ),
    (
        "POST",
        "/scans",
        {"org_admin", "security_lead", "security_analyst"},
        {"repository_path": "/not/a/registered/repository"},
        400,
    ),
    (
        "PATCH",
        "/findings/1/status",
        {"org_admin", "security_lead", "security_analyst"},
        {"status": "needs_review"},
        200,
    ),
    (
        "GET",
        "/auth/approvals",
        {"org_admin", "security_lead", "security_analyst", "auditor"},
        None,
        200,
    ),
    (
        "POST",
        "/auth/approvals",
        {"org_admin", "security_lead", "security_analyst"},
        {"action": "github.create_branch", "resource": "owner/repo"},
        201,
    ),
    (
        "POST",
        "/auth/approvals/missing/decision",
        {"org_admin", "security_lead"},
        {"approved": True},
        409,
    ),
    (
        "POST",
        "/auth/register",
        {"org_admin"},
        {"email": "new@example.test", "password": "long-enough-password", "role": "developer"},
        201,
    ),
    ("POST", "/auth/logout-all", set(ROLES), None, 200),
)


def test_role_matrix_lists_every_bearer_protected_api_operation():
    protected = {
        (method.upper(), path)
        for path, methods in app.openapi()["paths"].items()
        for method, operation in methods.items()
        if any(
            "HTTPBearer" in requirement
            for requirement in operation.get("security", [])
        )
    }
    covered = set()
    for method, path, *_ in OPERATIONS:
        parts = path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "findings" and parts[1].isdigit():
            path = "/findings/{finding_id}"
        elif (
            len(parts) == 3
            and parts[0] == "findings"
            and parts[1].isdigit()
            and parts[2] in {"investigate", "status"}
        ):
            path = f"/findings/{{finding_id}}/{parts[2]}"
        elif (
            len(parts) == 4
            and parts[:2] == ["auth", "approvals"]
            and parts[3] == "decision"
        ):
            path = "/auth/approvals/{approval_id}/decision"
        covered.add((method.upper(), path))

    assert protected <= covered


@pytest.fixture
def role_matrix_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "matrix.db"))
    monkeypatch.delenv("TALARIA_JWT_SECRET_FILE", raising=False)
    monkeypatch.delenv("TALARIA_BOOTSTRAP_TOKEN_FILE", raising=False)
    monkeypatch.setenv("TALARIA_JWT_SECRET", "unit-test-signing-secret-32-bytes-minimum")
    monkeypatch.setenv("TALARIA_BOOTSTRAP_TOKEN", "matrix-bootstrap-secret")
    database = Database(database_path())
    response = TestClient(app).post(
        "/auth/bootstrap",
        headers={"X-Talaria-Bootstrap-Token": "matrix-bootstrap-secret"},
        json={
            "email": "matrix-root@example.test",
            "password": "matrix-root-password",
            "organization_name": "Matrix Org",
        },
    )
    assert response.status_code == 201
    return database, response.json()["organization_id"]


def test_role_action_matrix(role_matrix_environment):
    database, organization_id = role_matrix_environment
    repository_id = database.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("matrix-repo", "/matrix-repo", organization_id),
    )
    database.insert(
        "INSERT INTO scans(repository_id, status) VALUES (?, 'completed')",
        (repository_id,),
    )
    database.insert(
        """INSERT INTO findings(
            fingerprint, repository_id, payload, status, first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, 'open', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
        ("matrix-finding", repository_id, '{"severity":"high"}'),
    )

    for role in ROLES:
        if role == "org_admin":
            email = "matrix-root@example.test"
            password = "matrix-root-password"
            database.execute(
                "UPDATE users SET is_platform_admin = 0 WHERE email = ?",
                (email,),
            )
        else:
            email = f"{role}@example.test"
            password = "role-matrix-test-password"
            AuthService(database).register_member(
                email,
                password,
                organization_id,
                role,
            )
        token_response = TestClient(app).post(
            "/auth/login",
            json={"email": email, "password": password},
        )
        assert token_response.status_code == 200
        client = TestClient(app, client=(f"matrix-{role}", 12345))
        headers = {
            "Authorization": f"Bearer {token_response.json()['access_token']}",
            "X-Organization-ID": organization_id,
        }

        for method, path, allowed_roles, payload, allowed_status in OPERATIONS:
            path = path.replace("{github_repository_id}", "999")
            path = path.replace("{sha}", "a" * 40)
            request = getattr(client, method.lower())
            response = (
                request(path, headers=headers, json=payload)
                if payload is not None
                else request(path, headers=headers)
            )
            if role in allowed_roles:
                assert response.status_code == allowed_status, response.text
            else:
                assert response.status_code == 403, response.text
