import json

import pytest
from fastapi.testclient import TestClient

from talaria.api import app
from talaria.config import database_path
from talaria.database import Database


@pytest.fixture
def api_environment(isolated_db):
    db = Database(database_path())
    client = TestClient(app)
    return client, db


def seed_dashboard_data(db):
    repository_id = db.insert(
        "INSERT INTO repositories(name, path) VALUES (?, ?)",
        ("sample-repo", "/tmp/sample-repo"),
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
    client, _ = api_environment

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dashboard_summary_empty_database(api_environment):
    client, _ = api_environment

    response = client.get("/dashboard/summary")

    assert response.status_code == 200
    data = response.json()

    assert data["repositories"] == 0
    assert data["scans"]["total"] == 0
    assert data["findings"]["total"] == 0


def test_dashboard_summary_with_data(api_environment):
    client, db = api_environment
    seed_dashboard_data(db)

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
    client, db = api_environment
    seed_dashboard_data(db)

    response = client.get("/scans")

    assert response.status_code == 200
    data = response.json()

    assert len(data) == 1
    assert data[0]["repository"] == "sample-repo"
    assert data[0]["status"] == "completed"
    assert data[0]["finding_count"] == 3


def test_scan_history_rejects_invalid_limit(api_environment):
    client, _ = api_environment

    assert client.get("/scans?limit=0").status_code == 422
    assert client.get("/scans?limit=501").status_code == 422


def test_dashboard_severity_distribution(api_environment):
    client, db = api_environment
    seed_dashboard_data(db)

    response = client.get("/dashboard/severity")

    assert response.status_code == 200
    data = response.json()

    assert data["total"] == 3
    assert data["distribution"]["critical"] == 1
    assert data["distribution"]["high"] == 1
    assert data["distribution"]["medium"] == 1
    assert data["distribution"]["unknown"] == 0


def test_dashboard_trends(api_environment):
    client, db = api_environment
    seed_dashboard_data(db)

    response = client.get("/dashboard/trends?days=30")

    assert response.status_code == 200
    data = response.json()

    assert data["period_days"] == 30
    assert len(data["data"]) == 1
    assert data["data"][0]["occurrences"] == 3
    assert data["data"][0]["unique_findings"] == 3


@pytest.mark.parametrize("days", [0, 366])
def test_dashboard_trends_rejects_invalid_days(api_environment, days):
    client, _ = api_environment

    response = client.get(f"/dashboard/trends?days={days}")

    assert response.status_code == 422
