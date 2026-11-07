import pytest
import requests

from talaria.dashboard.client import DashboardAPIError, TalariaAPIClient


class FakeResponse:
    status_code = 500
    text = "INTERNAL_PATH_OR_SECRET"

    def raise_for_status(self):
        raise requests.HTTPError("server failure", response=self)


def test_dashboard_client_does_not_render_api_error_body():
    client = TalariaAPIClient("https://talaria.example")
    client.session.request = lambda *args, **kwargs: FakeResponse()

    with pytest.raises(DashboardAPIError) as raised:
        client.summary()

    assert "HTTP 500" in str(raised.value)
    assert "INTERNAL_PATH_OR_SECRET" not in str(raised.value)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://dashboard.example.test",
        "http://talaria-api.evil.test:8000",
        "https://user:password@talaria.example.test",
        "https://talaria.example.test/api?token=secret",
        "https://talaria.example.test/#fragment",
    ],
)
def test_dashboard_client_rejects_unsafe_api_origins(base_url):
    with pytest.raises(ValueError, match="TALARIA API"):
        TalariaAPIClient(base_url)


@pytest.mark.parametrize(
    "base_url",
    [
        "https://talaria.example.test",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://[::1]:8000",
        "http://talaria-api:8000",
    ],
)
def test_dashboard_client_accepts_tls_and_explicit_local_api_origins(base_url):
    assert TalariaAPIClient(base_url).base_url == base_url


def test_dashboard_client_sends_bearer_and_tenant_headers():
    client = TalariaAPIClient("https://talaria.example")
    client.access_token = "access-token"
    client.organization_id = "organization-1"
    captured = {}

    class SuccessResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "ok"}

    def request(method, url, **kwargs):
        captured.update(method=method, url=url, **kwargs)
        return SuccessResponse()

    client.session.request = request

    assert client.health() == {"status": "ok"}
    assert captured["headers"]["Authorization"] == "Bearer access-token"
    assert captured["headers"]["X-Organization-ID"] == "organization-1"
    assert captured["allow_redirects"] is False


def test_dashboard_client_rejects_api_redirects():
    client = TalariaAPIClient("https://talaria.example")
    client.access_token = "access-token"
    requests_seen = []

    class RedirectResponse:
        status_code = 302

        def raise_for_status(self):
            raise AssertionError("redirect responses should be rejected first")

    def request(method, url, **kwargs):
        requests_seen.append((method, url, kwargs))
        return RedirectResponse()

    client.session.request = request

    with pytest.raises(DashboardAPIError, match="redirects are not accepted"):
        client.summary()

    assert len(requests_seen) == 1
    assert requests_seen[0][2]["allow_redirects"] is False


def test_dashboard_client_rotates_refresh_token_once_after_401():
    changes = []
    client = TalariaAPIClient(
        "https://talaria.example",
        token_callback=lambda access, refresh: changes.append((access, refresh)),
    )
    client.access_token = "expired-access"
    client.refresh_token = "old-refresh"
    requests_seen = []

    class Response:
        def __init__(self, status, data):
            self.status_code = status
            self.data = data

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError("request failed", response=self)

        def json(self):
            return self.data

    def request(method, url, **kwargs):
        requests_seen.append((method, url, kwargs))
        if url.endswith("/auth/refresh"):
            assert kwargs["json"] == {"refresh_token": "old-refresh"}
            return Response(200, {"access_token": "new-access", "refresh_token": "new-refresh"})
        if len([item for item in requests_seen if item[1].endswith("/dashboard/summary")]) == 1:
            return Response(401, {})
        return Response(200, {"summary": True})

    client.session.request = request

    assert client.summary() == {"summary": True}
    assert client.access_token == "new-access"
    assert client.refresh_token == "new-refresh"
    assert changes == [("new-access", "new-refresh")]
    summary_requests = [item for item in requests_seen if item[1].endswith("/dashboard/summary")]
    assert len(summary_requests) == 2
    assert summary_requests[0][2]["headers"]["Authorization"] == "Bearer expired-access"
    assert summary_requests[1][2]["headers"]["Authorization"] == "Bearer new-access"
    assert all(item[2]["allow_redirects"] is False for item in requests_seen)


def test_dashboard_client_clears_local_credentials_if_refresh_fails():
    client = TalariaAPIClient("https://talaria.example")
    client.access_token = "expired-access"
    client.refresh_token = "invalid-refresh"

    def request(method, url, **kwargs):
        if url.endswith("/auth/refresh"):
            return FakeResponse()
        response = FakeResponse()
        response.status_code = 401
        return response

    client.session.request = request

    with pytest.raises(DashboardAPIError, match="HTTP 401"):
        client.summary()

    assert client.access_token is None
    assert client.refresh_token is None


def test_dashboard_client_clears_credentials_if_refresh_redirects():
    client = TalariaAPIClient("https://talaria.example")
    client.access_token = "expired-access"
    client.refresh_token = "old-refresh"
    captured = {}

    class RedirectResponse:
        status_code = 302

        def raise_for_status(self):
            return None

        def json(self):
            raise AssertionError("redirect response body must not be parsed")

    def request(method, url, **kwargs):
        captured.update(method=method, url=url, **kwargs)
        return RedirectResponse()

    client.session.request = request

    assert client._rotate_refresh_token() is False
    assert captured["allow_redirects"] is False
    assert client.access_token is None
    assert client.refresh_token is None


def test_dashboard_client_requests_authenticated_ai_investigation():
    client = TalariaAPIClient("https://talaria.example")
    client.access_token = "access-token"
    client.organization_id = "organization-1"
    captured = {}

    class SuccessResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"finding_id": 7, "investigation": {"triage": "manual_review"}}

    def request(method, url, **kwargs):
        captured.update(method=method, url=url, **kwargs)
        return SuccessResponse()

    client.session.request = request

    assert client.investigate_finding(7)["finding_id"] == 7
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/findings/7/investigate")
    assert captured["headers"]["Authorization"] == "Bearer access-token"
    assert captured["headers"]["X-Organization-ID"] == "organization-1"


def test_dashboard_client_requests_a_bounded_finding_page():
    client = TalariaAPIClient("https://talaria.example")
    captured = {}

    class SuccessResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return []

    def request(method, url, **kwargs):
        captured.update(method=method, url=url, **kwargs)
        return SuccessResponse()

    client.session.request = request

    assert client.findings(limit=100, offset=200) == []
    assert captured["params"] == {"limit": 100, "offset": 200}
