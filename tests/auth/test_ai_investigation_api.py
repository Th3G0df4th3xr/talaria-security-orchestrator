"""AI endpoint uses authenticated tenant data and opt-in bounded context."""

import hashlib
import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from talaria.api import app
from talaria.config import database_path
from talaria.database import Database
from talaria.integrations.base import IntegrationError


def _finding(db, organization_id, repository_path, payload):
    repository_id = db.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("sample", str(repository_path), organization_id),
    )
    db.insert(
        "INSERT INTO scans(repository_id, status) VALUES (?, 'completed')",
        (repository_id,),
    )
    return db.insert(
        """INSERT INTO findings
           (fingerprint, repository_id, payload, first_seen_at, last_seen_at)
           VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
        (payload.get("fingerprint", "f" * 64), repository_id, json.dumps(payload)),
    )


def _login(client):
    response = client.post(
        "/auth/login",
        json={"email": "root@example.test", "password": "strong-test-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def auth_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "auth.db"))
    monkeypatch.delenv("TALARIA_JWT_SECRET_FILE", raising=False)
    monkeypatch.delenv("TALARIA_BOOTSTRAP_TOKEN_FILE", raising=False)
    monkeypatch.setenv("TALARIA_JWT_SECRET", "unit-test-signing-secret-32-bytes-minimum")
    monkeypatch.setenv("TALARIA_BOOTSTRAP_TOKEN", "bootstrap-secret-for-tests")
    db = Database(database_path())
    client = TestClient(app)
    bootstrap = client.post(
        "/auth/bootstrap",
        headers={"X-Talaria-Bootstrap-Token": "bootstrap-secret-for-tests"},
        json={
            "email": "root@example.test",
            "password": "strong-test-password",
            "organization_name": "Primary",
        },
    )
    assert bootstrap.status_code == 201
    return client, db, bootstrap.json()["organization_id"]


def test_ai_investigation_is_tenant_authorized_and_sends_only_opted_in_context(
    auth_environment, tmp_path, monkeypatch
):
    import talaria.integrations.llm as llm

    client, db, organization_id = auth_environment
    repository = tmp_path / "repo"
    repository.mkdir()
    source = b"eval(user_input)\n"
    (repository / "app.py").write_bytes(source)
    source_digest = hashlib.sha256(source).hexdigest()
    source_ref = f"source:{source_digest}:app.py:1"
    finding_id = _finding(
        db,
        organization_id,
        repository,
        {
            "fingerprint": "f" * 64,
            "rule_id": "python-eval",
            "title": "Dynamic evaluation",
            "severity": "high",
            "path": "app.py",
            "line": 1,
            "snippet": "DO_NOT_SEND_THIS_FIELD",
            "source_sha256": source_digest,
        },
    )
    monkeypatch.setenv("TALARIA_ALLOWED_REPOSITORY_ROOTS", str(tmp_path))
    monkeypatch.setenv("TALARIA_AI_ENABLED", "true")
    monkeypatch.setenv("TALARIA_AI_SEND_SOURCE", "true")
    monkeypatch.setenv("TALARIA_LLM_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("TALARIA_LLM_MODEL", "test-model")
    monkeypatch.setenv("TALARIA_LLM_API_KEY", "test-key")
    captured = {}
    echoed_token = "".join(("ghp_", "123456789012345678901234567890123456"))

    class FakeProvider:
        def complete(self, system_prompt, user_prompt):
            captured["system"] = system_prompt
            captured["user"] = user_prompt
            return json.dumps(
                {
                    "triage": "manual_review",
                    "rationale": f"The source pattern needs review; echoed {echoed_token}.",
                    "confidence": "low",
                    "evidence_refs": [source_ref],
                    "remediation": "Review Authorization: Bearer leaked-response-secret.",
                }
            )

    monkeypatch.setattr(llm, "OpenAICompatibleProvider", lambda _settings: FakeProvider())
    headers = _login(client)
    headers["X-Organization-ID"] = organization_id

    response = client.post(
        f"/findings/{finding_id}/investigate", headers=headers
    )

    assert response.status_code == 200
    investigation_id = response.json()["investigation_id"]
    assert response.json()["investigation"]["evidence_refs"] == [source_ref]
    assert "eval(user_input)" in captured["user"]
    assert "DO_NOT_SEND_THIS_FIELD" not in captured["user"]
    assert echoed_token not in response.text
    assert "leaked-response-secret" not in response.text
    assert db.execute(
        "SELECT details FROM audit_events WHERE event = 'ai.investigation_completed'"
    )
    assert '"source_sent":true' in db.execute(
        "SELECT details FROM audit_events WHERE event = 'ai.investigation_completed'"
    )[0]["details"]
    stored = db.execute(
        "SELECT organization_id, finding_id, initiated_by, status, result "
        "FROM investigations WHERE id = ?",
        (investigation_id,),
    )[0]
    assert stored["organization_id"] == organization_id
    assert stored["finding_id"] == finding_id
    assert stored["status"] == "completed"
    assert json.loads(stored["result"]) == response.json()["investigation"]
    assert echoed_token not in stored["result"]
    assert "leaked-response-secret" not in stored["result"]
    history = client.get("/investigations", headers=headers)
    assert history.status_code == 200
    assert history.json()["investigations"][0]["id"] == investigation_id
    other_org = client.post(
        "/auth/organizations",
        headers=headers,
        json={"name": "Other tenant", "admin_email": "root@example.test"},
    )
    assert other_org.status_code == 201
    other_headers = {
        **headers,
        "X-Organization-ID": other_org.json()["organization_id"],
    }
    assert client.get("/investigations", headers=other_headers).json() == {
        "investigations": []
    }


def test_failed_ai_investigation_is_persisted_without_provider_error_text(
    auth_environment, tmp_path, monkeypatch
):
    import talaria.integrations.llm as llm

    client, db, organization_id = auth_environment
    repository = tmp_path / "repo"
    repository.mkdir()
    finding_id = _finding(
        db,
        organization_id,
        repository,
        {"fingerprint": "f" * 64, "rule_id": "python-eval"},
    )
    monkeypatch.setenv("TALARIA_AI_ENABLED", "true")
    monkeypatch.setenv("TALARIA_LLM_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("TALARIA_LLM_MODEL", "test-model")
    monkeypatch.setenv("TALARIA_LLM_API_KEY", "test-key")

    class FailingProvider:
        def complete(self, *_args):
            raise IntegrationError("provider secret response must not be returned")

    monkeypatch.setattr(llm, "OpenAICompatibleProvider", lambda _settings: FailingProvider())
    headers = _login(client)
    headers["X-Organization-ID"] = organization_id

    response = client.post(f"/findings/{finding_id}/investigate", headers=headers)

    assert response.status_code == 503
    investigation = db.execute(
        "SELECT status, error_type, result FROM investigations WHERE finding_id = ?",
        (finding_id,),
    )[0]
    assert investigation == {
        "status": "failed",
        "error_type": "IntegrationError",
        "result": None,
    }
    assert "provider secret response" not in response.text


def test_ai_investigation_rejects_source_changed_since_scan(
    auth_environment, tmp_path, monkeypatch
):
    import talaria.integrations.llm as llm

    client, db, organization_id = auth_environment
    repository = tmp_path / "repo"
    repository.mkdir()
    original = b"eval(user_input)\n"
    source = repository / "app.py"
    source.write_bytes(original)
    finding_id = _finding(
        db,
        organization_id,
        repository,
        {
            "fingerprint": "f" * 64,
            "rule_id": "python-eval",
            "path": "app.py",
            "line": 1,
            "source_sha256": hashlib.sha256(original).hexdigest(),
        },
    )
    source.write_bytes(b"# changed after scan\neval(user_input)\n")
    monkeypatch.setenv("TALARIA_ALLOWED_REPOSITORY_ROOTS", str(tmp_path))
    monkeypatch.setenv("TALARIA_AI_ENABLED", "true")
    monkeypatch.setenv("TALARIA_AI_SEND_SOURCE", "true")
    monkeypatch.setenv("TALARIA_LLM_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("TALARIA_LLM_MODEL", "test-model")
    monkeypatch.setenv("TALARIA_LLM_API_KEY", "test-key")
    provider_called = False

    class FakeProvider:
        def complete(self, *_args):
            nonlocal provider_called
            provider_called = True
            raise AssertionError("Changed source must not reach the provider")

    monkeypatch.setattr(llm, "OpenAICompatibleProvider", lambda _settings: FakeProvider())
    headers = _login(client)
    headers["X-Organization-ID"] = organization_id

    response = client.post(
        f"/findings/{finding_id}/investigate", headers=headers
    )

    assert response.status_code == 422
    assert provider_called is False
    assert db.execute(
        "SELECT status, error_type FROM investigations WHERE finding_id = ?",
        (finding_id,),
    )[0] == {"status": "failed", "error_type": "ContextError"}


def test_unexpected_ai_provider_exception_is_persisted_as_failed(
    auth_environment, tmp_path, monkeypatch
):
    import talaria.integrations.llm as llm

    client, db, organization_id = auth_environment
    repository = tmp_path / "repo"
    repository.mkdir()
    finding_id = _finding(
        db,
        organization_id,
        repository,
        {"fingerprint": "f" * 64, "rule_id": "python-eval"},
    )
    monkeypatch.setenv("TALARIA_AI_ENABLED", "true")
    monkeypatch.setenv("TALARIA_LLM_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("TALARIA_LLM_MODEL", "test-model")
    monkeypatch.setenv("TALARIA_LLM_API_KEY", "test-key")

    class FailingProvider:
        def complete(self, *_args):
            raise RuntimeError("provider response included private-secret-text")

    monkeypatch.setattr(llm, "OpenAICompatibleProvider", lambda _settings: FailingProvider())
    headers = _login(client)
    headers["X-Organization-ID"] = organization_id

    response = client.post(f"/findings/{finding_id}/investigate", headers=headers)

    assert response.status_code == 503
    assert "private-secret-text" not in response.text
    assert db.execute(
        "SELECT status, error_type, result FROM investigations WHERE finding_id = ?",
        (finding_id,),
    )[0] == {"status": "failed", "error_type": "RuntimeError", "result": None}


def test_investigation_history_recovers_only_stale_runs_in_current_tenant(
    auth_environment, tmp_path
):
    client, db, organization_id = auth_environment
    finding_id = _finding(
        db,
        organization_id,
        tmp_path / "repo",
        {"fingerprint": "f" * 64, "rule_id": "python-eval"},
    )
    repository_id = db.execute(
        "SELECT repository_id FROM findings WHERE id = ?", (finding_id,)
    )[0]["repository_id"]
    user_id = db.execute("SELECT id FROM users WHERE email = ?", ("root@example.test",))[0]["id"]
    stale_id = "stale-investigation"
    fresh_id = "fresh-investigation"
    db.execute(
        """INSERT INTO investigations
           (id, organization_id, repository_id, finding_id, initiated_by,
            provider, model, status, started_at)
           VALUES (?, ?, ?, ?, ?, 'provider.example', 'test-model', 'running', ?)""",
        (
            stale_id,
            organization_id,
            repository_id,
            finding_id,
            user_id,
            "2020-01-01T00:00:00+00:00",
        ),
    )
    db.execute(
        """INSERT INTO investigations
           (id, organization_id, repository_id, finding_id, initiated_by,
            provider, model, status, started_at)
           VALUES (?, ?, ?, ?, ?, 'provider.example', 'test-model', 'running', ?)""",
        (
            fresh_id,
            organization_id,
            repository_id,
            finding_id,
            user_id,
            datetime.now(UTC).isoformat(),
        ),
    )

    headers = _login(client)
    headers["X-Organization-ID"] = organization_id
    other_org = client.post(
        "/auth/organizations",
        headers=headers,
        json={"name": "Recovery isolation", "admin_email": "root@example.test"},
    )
    assert other_org.status_code == 201
    other_organization_id = other_org.json()["organization_id"]
    other_finding_id = _finding(
        db,
        other_organization_id,
        tmp_path / "other-repo",
        {"fingerprint": "e" * 64, "rule_id": "python-eval"},
    )
    other_repository_id = db.execute(
        "SELECT repository_id FROM findings WHERE id = ?", (other_finding_id,)
    )[0]["repository_id"]
    db.insert(
        """INSERT INTO investigations
           (id, organization_id, repository_id, finding_id, initiated_by,
            provider, model, status, started_at)
           VALUES (?, ?, ?, ?, ?, 'provider.example', 'test-model', 'running', ?)""",
        (
            "other-tenant-stale",
            other_organization_id,
            other_repository_id,
            other_finding_id,
            user_id,
            "2020-01-01T00:00:00+00:00",
        ),
    )
    response = client.get("/investigations", headers=headers)

    assert response.status_code == 200
    statuses = {item["id"]: item for item in response.json()["investigations"]}
    assert statuses[stale_id]["status"] == "failed"
    assert statuses[stale_id]["error_type"] == "StaleInvestigation"
    assert statuses[stale_id]["finished_at"]
    assert statuses[fresh_id]["status"] == "running"
    audit = db.execute(
        "SELECT details FROM audit_events WHERE event = 'ai.investigation_stale_failed'"
    )
    assert len(audit) == 1
    assert stale_id in audit[0]["details"]
    assert db.execute(
        "SELECT status FROM investigations WHERE id = ?", ("other-tenant-stale",)
    )[0]["status"] == "running"


def test_application_startup_recovers_stale_investigations(auth_environment, tmp_path):
    from talaria.api import app

    _client, db, organization_id = auth_environment
    finding_id = _finding(
        db,
        organization_id,
        tmp_path / "repo",
        {"fingerprint": "f" * 64, "rule_id": "python-eval"},
    )
    finding = db.execute(
        "SELECT repository_id FROM findings WHERE id = ?", (finding_id,)
    )[0]
    user_id = db.execute("SELECT id FROM users WHERE email = ?", ("root@example.test",))[0]["id"]
    db.insert(
        """INSERT INTO investigations
           (id, organization_id, repository_id, finding_id, initiated_by,
            provider, model, status, started_at)
           VALUES (?, ?, ?, ?, ?, 'provider.example', 'test-model', 'running', ?)""",
        (
            "startup-stale-investigation",
            organization_id,
            finding["repository_id"],
            finding_id,
            user_id,
            "2020-01-01T00:00:00+00:00",
        ),
    )

    with TestClient(app):
        pass

    recovered = db.execute(
        "SELECT status, error_type FROM investigations WHERE id = ?",
        ("startup-stale-investigation",),
    )[0]
    assert recovered == {"status": "failed", "error_type": "StaleInvestigation"}


def test_ai_investigation_does_not_read_source_when_disabled(
    auth_environment, tmp_path, monkeypatch
):
    client, db, organization_id = auth_environment
    finding_id = _finding(
        db,
        organization_id,
        tmp_path / "missing-repository",
        {"rule_id": "python-eval", "path": "missing.py", "line": 1},
    )
    monkeypatch.setenv("TALARIA_AI_ENABLED", "false")
    monkeypatch.setenv("TALARIA_AI_SEND_SOURCE", "true")
    headers = _login(client)
    headers["X-Organization-ID"] = organization_id

    response = client.post(
        f"/findings/{finding_id}/investigate", headers=headers
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "AI investigation is disabled"


def test_ai_investigation_requires_authentication(auth_environment):
    client, _, _ = auth_environment

    assert client.post("/findings/1/investigate").status_code == 401


def test_developer_cannot_request_ai_investigation(auth_environment):
    client, _, organization_id = auth_environment
    admin_headers = _login(client)
    registered = client.post(
        "/auth/register",
        headers=admin_headers,
        json={
            "email": "developer@example.test",
            "password": "developer-test-password",
            "role": "developer",
        },
    )
    assert registered.status_code == 201
    developer = client.post(
        "/auth/login",
        json={
            "email": "developer@example.test",
            "password": "developer-test-password",
        },
    ).json()
    headers = {
        "Authorization": f"Bearer {developer['access_token']}",
        "X-Organization-ID": organization_id,
    }

    response = client.post("/findings/1/investigate", headers=headers)

    assert response.status_code == 403


def test_findings_endpoint_paginates_within_the_active_tenant(auth_environment):
    client, db, organization_id = auth_environment
    repository_id = db.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("paged-repo", "/paged-repo", organization_id),
    )
    for number in range(3):
        db.insert(
            """INSERT INTO findings
               (fingerprint, repository_id, payload, first_seen_at, last_seen_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
            (f"{number:064x}", repository_id, json.dumps({"number": number})),
        )
    headers = _login(client)
    headers["X-Organization-ID"] = organization_id

    response = client.get("/findings?limit=1&offset=1", headers=headers)

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["payload"]["number"] == 1
    assert client.get("/findings?limit=501", headers=headers).status_code == 422
