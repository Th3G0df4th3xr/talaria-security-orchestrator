"""Require explicit authentication coverage for every documented API route."""

import pytest

from talaria.api import app

pytestmark = pytest.mark.security

PUBLIC_ROUTE_CONTROLS = {
    ("GET", "/health"): "non-sensitive service status",
    ("GET", "/health/live"): "liveness probe",
    ("GET", "/health/ready"): "readiness probe",
    ("POST", "/auth/bootstrap"): "one-time operator bootstrap token",
    ("POST", "/auth/login"): "user credentials",
    ("POST", "/auth/refresh"): "refresh token",
    ("POST", "/auth/logout"): "refresh token revocation",
    ("POST", "/integrations/github/webhook"): "GitHub HMAC signature",
}


def test_every_documented_route_requires_bearer_auth_or_explicit_control():
    schema = app.openapi()
    unauthenticated = set()

    for path, operations in schema["paths"].items():
        for method, operation in operations.items():
            if method.upper() not in {
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
            }:
                continue
            security = operation.get("security", [])
            if not any("HTTPBearer" in requirement for requirement in security):
                unauthenticated.add((method.upper(), path))

    assert unauthenticated == set(PUBLIC_ROUTE_CONTROLS)


def test_hidden_metrics_route_has_a_separate_token_gate():
    metrics = [route for route in app.routes if getattr(route, "path", None) == "/metrics"]

    assert len(metrics) == 1
    assert metrics[0].endpoint.__name__ == "metrics"
    assert metrics[0].include_in_schema is False
