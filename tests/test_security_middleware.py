import logging

import pytest
from fastapi.testclient import TestClient

from talaria.api import app
from talaria.security.middleware import (
    MAX_REQUEST_BODY_BYTES,
    RequestMetrics,
    RequestRateLimiter,
    _limit_for,
    _rate_limit_route,
)

pytestmark = pytest.mark.security


def test_request_rate_limiter_enforces_sliding_window(monkeypatch):
    import talaria.security.middleware as middleware

    current = [100.0]
    monkeypatch.setattr(middleware, "monotonic", lambda: current[0])
    limiter = RequestRateLimiter()
    key = ("127.0.0.1", "/auth/login")

    assert limiter.allow(key, 2, 60.0)
    assert limiter.allow(key, 2, 60.0)
    assert not limiter.allow(key, 2, 60.0)
    current[0] = 161.0
    assert limiter.allow(key, 2, 60.0)


def test_rate_limiter_bounds_client_key_memory():
    limiter = RequestRateLimiter(max_keys=2)

    assert limiter.allow(("db", "client-a"), 1, 60)
    assert limiter.allow(("db", "client-b"), 1, 60)
    assert limiter.allow(("db", "client-c"), 1, 60)

    assert len(limiter._hits) == 2
    assert ("db", "client-a") not in limiter._hits


def test_request_metrics_bound_labels_and_render_scan_outcomes():
    metrics = RequestMetrics()
    metrics.observe_request("GET", "/findings/12345/investigate", 200, 0.2)
    metrics.observe_request("TRACE", "/customer-secret-path", 404, 0.01)
    metrics.record_scan("completed")
    metrics.record_scan("invalid")

    rendered = metrics.render()

    assert 'route="/findings/{finding_id}/investigate"' in rendered
    assert 'route="other"' in rendered
    assert "12345" not in rendered
    assert "customer-secret-path" not in rendered
    assert 'method="OTHER"' in rendered
    assert 'status="completed"' in rendered
    assert 'status="other"' in rendered
    assert "talaria_http_request_duration_seconds_bucket" in rendered


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/auth/register", 10),
        ("/auth/organizations", 5),
        ("/auth/approvals", 30),
        ("/auth/approvals/approval-id/decision", 30),
        ("/auth/logout-all", 30),
        ("/integrations/github/repositories", 10),
    ],
)
def test_authentication_and_approval_mutations_are_rate_limited(path, expected):
    assert _limit_for(path, "POST") == expected


def test_approval_throttle_does_not_match_unrelated_auth_paths():
    assert _limit_for("/auth/approvals-extra", "POST") is None
    assert _limit_for("/auth/approvals/approval-id", "POST") is None


def test_rate_limit_keys_canonicalize_caller_controlled_resource_ids():
    finding_route = "/findings/{finding_id}/investigate"
    assert _rate_limit_route("/findings/1/investigate") == finding_route
    assert _rate_limit_route("/findings/987654/investigate") == finding_route
    approval_route = "/auth/approvals/{approval_id}/decision"
    assert _rate_limit_route("/auth/approvals/first/decision") == approval_route
    assert _rate_limit_route("/auth/approvals/second/decision") == approval_route
    check_run_route = (
        "/integrations/github/repositories/{repository_id}/commits/{sha}/check-runs"
    )
    assert _rate_limit_route(
        f"/integrations/github/repositories/123/commits/{'a' * 40}/check-runs"
    ) == check_run_route
    assert _rate_limit_route(
        f"/integrations/github/repositories/124/commits/{'b' * 40}/check-runs"
    ) == check_run_route
    assert _rate_limit_route("/findings/not-an-id/investigate") == (
        "/findings/not-an-id/investigate"
    )


def test_expensive_resource_limits_apply_only_to_mutations():
    assert _limit_for("/scans", "POST") == 5
    assert _limit_for("/scans", "GET") is None
    assert _limit_for("/auth/approvals", "GET") == 60
    assert _limit_for("/integrations/github/repositories", "GET") is None
    assert _limit_for(
        "/integrations/github/repositories/{repository_id}/commits/{sha}/check-runs",
        "GET",
    ) == 10


def test_request_logs_are_structured_redacted_and_correlated(caplog):
    caplog.set_level(logging.INFO, logger="talaria.http")

    response = TestClient(app).get("/health?access_token=must-not-be-logged")

    assert response.status_code == 200
    request_id = response.headers["X-Request-ID"]
    assert len(request_id) == 32
    messages = [record.getMessage() for record in caplog.records]
    assert any('"event":"http.request"' in message for message in messages)
    assert any(request_id in message and '"path":"/health"' in message for message in messages)
    assert all("must-not-be-logged" not in message for message in messages)


def test_metrics_endpoint_requires_configured_bearer_token(monkeypatch):
    monkeypatch.delenv("TALARIA_METRICS_TOKEN_FILE", raising=False)
    monkeypatch.delenv("TALARIA_METRICS_TOKEN", raising=False)
    client = TestClient(app)

    assert client.get("/metrics").status_code == 404

    monkeypatch.setenv("TALARIA_METRICS_TOKEN", "metrics-test-token")
    assert client.get("/metrics").status_code == 401
    response = client.get(
        "/metrics", headers={"Authorization": "Bearer metrics-test-token"}
    )

    assert response.status_code == 200
    assert "talaria_http_requests_total" in response.text
    assert "talaria_scans_total" in response.text
    assert response.headers["Cache-Control"] == "no-store"


def test_oversized_request_is_rejected_with_security_headers(tmp_path, monkeypatch):
    from talaria.database import Database

    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "rate-limiter.db"))
    Database(tmp_path / "rate-limiter.db")
    response = TestClient(app).post(
        "/auth/login",
        content=b"x" * (MAX_REQUEST_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body is too large"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Request-ID"]


def test_limited_routes_fail_closed_without_shared_database(tmp_path, monkeypatch):
    monkeypatch.setenv("TALARIA_DATABASE", str(tmp_path / "missing.db"))

    response = TestClient(app).post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "test-password"},
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Request protection is temporarily unavailable"
    }


def test_ai_rate_limit_cannot_be_bypassed_by_changing_finding_id(tmp_path, monkeypatch):
    from talaria.database import Database

    database_path = tmp_path / "ai-rate-limit.db"
    monkeypatch.setenv("TALARIA_DATABASE", str(database_path))
    Database(database_path)
    client = TestClient(app)

    responses = [
        client.post(f"/findings/{finding_id}/investigate")
        for finding_id in range(1, 7)
    ]

    assert [response.status_code for response in responses[:5]] == [401] * 5
    assert responses[5].status_code == 429


def test_chunked_oversized_request_is_rejected_without_content_length():
    import asyncio

    from talaria.security.middleware import RequestBodyLimitMiddleware

    delivered = []
    body = b"x" * (MAX_REQUEST_BODY_BYTES + 1)

    async def receive():
        if delivered:
            return {"type": "http.request", "body": b"", "more_body": False}
        delivered.append(True)
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        delivered.append(message)

    async def downstream(scope, receive, send):
        raise AssertionError("Oversized request reached downstream application")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/auth/login",
        "raw_path": b"/auth/login",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
    }
    middleware = RequestBodyLimitMiddleware(downstream)

    asyncio.run(middleware(scope, receive, send))

    assert any(
        message.get("type") == "http.response.start" and message["status"] == 413
        for message in delivered
        if isinstance(message, dict)
    )
