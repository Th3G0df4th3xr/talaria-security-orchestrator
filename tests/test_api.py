import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from talaria.api import app
from talaria.config import database_path
from talaria.database import CURRENT_SCHEMA_VERSION, Database


@pytest.fixture
def api_environment(isolated_db, monkeypatch):
    monkeypatch.setenv("TALARIA_JWT_SECRET", "unit-test-signing-secret-32-bytes-minimum")
    monkeypatch.setenv("TALARIA_BOOTSTRAP_TOKEN", "unit-test-bootstrap-secret")
    db = Database(database_path())
    client = TestClient(app)
    bootstrap = client.post(
        "/auth/bootstrap",
        headers={"X-Talaria-Bootstrap-Token": "unit-test-bootstrap-secret"},
        json={
            "email": "admin@example.test",
            "password": "a-long-test-password",
            "organization_name": "Example Org",
        },
    )
    assert bootstrap.status_code == 201
    organization_id = bootstrap.json()["organization_id"]
    tokens = client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "a-long-test-password"},
    ).json()
    client.headers.update({"Authorization": f"Bearer {tokens['access_token']}"})
    return client, db, organization_id


def seed_dashboard_data(db, organization_id):
    repository_id = db.insert(
        "INSERT INTO repositories(name, path, organization_id) VALUES (?, ?, ?)",
        ("sample-repo", "/tmp/sample-repo", organization_id),
    )

    scan_id = db.insert(
        """
        INSERT INTO scans(
            repository_id, started_at, completed_at,
            finding_count, status
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            repository_id,
            "2026-11-06T10:00:00",
            "2026-11-06T10:05:00",
            3,
            "completed",
        ),
    )

    findings = [
        ("a" * 64, {"severity": "high"}, "open"),
        ("b" * 64, {"severity": "critical"}, "confirmed"),
        ("c" * 64, {"severity": "medium"}, "fixed"),
    ]

    for fingerprint, payload, status in findings:
        finding_id = db.insert(
            """
            INSERT INTO findings(
                fingerprint, repository_id, payload, status,
                first_seen_at, last_seen_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint,
                repository_id,
                json.dumps(payload),
                status,
                "2026-11-06T10:00:00",
                "2026-11-06T10:05:00",
            ),
        )

        db.insert(
            """
            INSERT INTO finding_occurrences(
                finding_id, scan_id, observed_at
            )
            VALUES (?, ?, ?)
            """,
            (finding_id, scan_id, "2026-11-06T10:05:00"),
        )


def test_health_endpoint(api_environment):
    client, _, _ = api_environment

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"

    protected = client.get("/repositories", headers={"Authorization": ""})
    assert protected.status_code == 401
    assert protected.headers["X-Content-Type-Options"] == "nosniff"
    assert protected.headers["X-Frame-Options"] == "DENY"


def test_readiness_probe_reports_current_schema(api_environment):
    client, _, _ = api_environment

    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["schema_version"] == CURRENT_SCHEMA_VERSION


def test_readiness_does_not_migrate_legacy_database(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE legacy_marker(value TEXT); PRAGMA user_version = 0;"
    )
    connection.commit()
    connection.close()
    monkeypatch.setenv("TALARIA_DATABASE", str(path))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall() == [("legacy_marker",)]
    connection.close()


def test_readiness_does_not_create_missing_database(tmp_path, monkeypatch):
    path = tmp_path / "missing" / "talaria.db"
    monkeypatch.setenv("TALARIA_DATABASE", str(path))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert not path.exists()
    assert not path.parent.exists()


def test_dashboard_summary_empty_database(api_environment):
    client, _, _ = api_environment

    response = client.get("/dashboard/summary")

    assert response.status_code == 200
    data = response.json()

    assert data["repositories"] == 0
    assert data["scans"]["total"] == 0
    assert data["findings"]["total"] == 0


def test_dashboard_summary_with_data(api_environment):
    client, db, org_id = api_environment
    seed_dashboard_data(db, org_id)

    response = client.get("/dashboard/summary")

    assert response.status_code == 200
    data = response.json()

    assert data["repositories"] == 1
    assert data["scans"]["total"] == 1
    assert data["scans"]["completed"] == 1
    assert data["findings"]["total"] == 3
    assert data["findings"]["open"] == 1
    assert data["findings"]["confirmed"] == 1
    assert data["findings"]["fixed"] == 1


def test_scan_history(api_environment):
    client, db, org_id = api_environment
    seed_dashboard_data(db, org_id)

    response = client.get("/scans")

    assert response.status_code == 200
    data = response.json()

    assert len(data) == 1
    assert data[0]["repository"] == "sample-repo"
    assert data[0]["branch"] is None
    assert data[0]["status"] == "completed"
    assert data[0]["finding_count"] == 3


def test_scan_history_rejects_invalid_limit(api_environment):
    client, _, _ = api_environment

    assert client.get("/scans?limit=0").status_code == 422
    assert client.get("/scans?limit=501").status_code == 422


def test_dashboard_severity_distribution(api_environment):
    client, db, org_id = api_environment
    seed_dashboard_data(db, org_id)

    response = client.get("/dashboard/severity")

    assert response.status_code == 200
    data = response.json()

    assert data["total"] == 3
    assert data["distribution"]["critical"] == 1
    assert data["distribution"]["high"] == 1
    assert data["distribution"]["medium"] == 1
    assert data["distribution"]["unknown"] == 0


def test_dashboard_trends(api_environment):
    client, db, org_id = api_environment
    seed_dashboard_data(db, org_id)

    response = client.get("/dashboard/trends?days=30")

    assert response.status_code == 200
    data = response.json()

    assert data["period_days"] == 30
    assert len(data["data"]) == 1
    assert data["data"][0]["occurrences"] == 3
    assert data["data"][0]["unique_findings"] == 3


@pytest.mark.parametrize("days", [0, 366])
def test_dashboard_trends_rejects_invalid_days(api_environment, days):
    client, _, _ = api_environment

    response = client.get(f"/dashboard/trends?days={days}")

    assert response.status_code == 422
