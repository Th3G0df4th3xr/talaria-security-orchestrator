"""HTTP client for the TALARIA dashboard."""

import os
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import requests


class DashboardAPIError(RuntimeError):
    """Raised when the TALARIA API request fails."""


class TalariaAPIClient:
    """Communicate with TALARIA exclusively through its HTTP API."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 8.0,
        token_callback: Callable[[str | None, str | None], None] | None = None,
    ) -> None:
        configured_url = (
            base_url
            or os.getenv(
                "TALARIA_API_URL",
                "http://127.0.0.1:8000",
            )
        )
        self.base_url = _validated_api_url(configured_url)
        self.timeout = timeout
        self.session = requests.Session()
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.organization_id: str | None = None
        self.token_callback = token_callback

    def _notify_tokens(self) -> None:
        if self.token_callback:
            self.token_callback(self.access_token, self.refresh_token)

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        retry_after_refresh: bool = True,
        **kwargs: Any,
    ) -> Any:
        url = f"{self.base_url}{endpoint}"
        headers = dict(kwargs.pop("headers", {}))
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if self.organization_id:
            headers["X-Organization-ID"] = self.organization_id

        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                headers=headers,
                allow_redirects=False,
                **kwargs,
            )
            if 300 <= response.status_code < 400:
                raise DashboardAPIError("TALARIA API redirects are not accepted.")
            response.raise_for_status()
        except requests.Timeout as exc:
            raise DashboardAPIError(
                "TALARIA API request timed out."
            ) from exc
        except requests.ConnectionError as exc:
            raise DashboardAPIError(
                "Cannot connect to TALARIA API. "
                "Start the FastAPI server and try again."
            ) from exc
        except requests.HTTPError as exc:
            if (
                response.status_code == 401
                and retry_after_refresh
                and self.refresh_token
                and endpoint not in {"/auth/login", "/auth/refresh", "/auth/logout"}
                and self._rotate_refresh_token()
            ):
                return self._request(
                    method,
                    endpoint,
                    retry_after_refresh=False,
                    **kwargs,
                )
            raise DashboardAPIError(
                f"TALARIA API returned HTTP {response.status_code}."
            ) from exc
        except requests.RequestException as exc:
            raise DashboardAPIError(
                f"TALARIA API request failed: {type(exc).__name__}"
            ) from exc

        try:
            return response.json()
        except ValueError as exc:
            raise DashboardAPIError(
                "TALARIA API returned an invalid JSON response."
            ) from exc

    def _rotate_refresh_token(self) -> bool:
        """Rotate the refresh credential once after an expired access token."""
        if not self.refresh_token:
            return False
        try:
            response = self.session.request(
                "POST",
                f"{self.base_url}/auth/refresh",
                timeout=self.timeout,
                json={"refresh_token": self.refresh_token},
                allow_redirects=False,
            )
            if 300 <= response.status_code < 400:
                raise requests.TooManyRedirects("Refresh redirect rejected")
            response.raise_for_status()
            tokens = response.json()
            access_token = tokens["access_token"]
            refresh_token = tokens["refresh_token"]
            if not access_token or not refresh_token:
                raise ValueError("Missing rotated credentials")
        except (requests.RequestException, ValueError, KeyError, TypeError):
            self.access_token = None
            self.refresh_token = None
            self.organization_id = None
            self._notify_tokens()
            return False
        self.access_token = access_token
        self.refresh_token = refresh_token
        self._notify_tokens()
        return True

    def health(self) -> dict:
        return self._request("GET", "/health")

    def login(self, email: str, password: str) -> dict:
        result = self._request(
            "POST", "/auth/login", json={"email": email, "password": password}
        )
        self.access_token = result["access_token"]
        self.refresh_token = result["refresh_token"]
        self._notify_tokens()
        return result

    def me(self) -> dict:
        return self._request("GET", "/auth/me")

    def logout(self) -> None:
        if self.refresh_token and self.access_token:
            try:
                self._request(
                    "POST", "/auth/logout", json={"refresh_token": self.refresh_token}
                )
            except DashboardAPIError:
                # Local UI credentials are discarded even when the API is down.
                pass
            finally:
                self.access_token = None
                self.refresh_token = None
                self.organization_id = None
                self._notify_tokens()

    def summary(self) -> dict:
        return self._request("GET", "/dashboard/summary")

    def repositories(self) -> list[dict]:
        return self._request("GET", "/repositories")

    def scans(self, limit: int = 100) -> list[dict]:
        return self._request(
            "GET",
            "/scans",
            params={"limit": limit},
        )

    def severity(self) -> dict:
        return self._request("GET", "/dashboard/severity")

    def trends(self, days: int = 30) -> dict:
        return self._request(
            "GET",
            "/dashboard/trends",
            params={"days": days},
        )

    def findings(self, limit: int = 100, offset: int = 0) -> list[dict]:
        return self._request(
            "GET", "/findings", params={"limit": limit, "offset": offset}
        )

    def finding(
        self, finding_id: int, occurrence_limit: int = 100, occurrence_offset: int = 0
    ) -> dict:
        return self._request(
            "GET",
            f"/findings/{finding_id}",
            params={
                "occurrence_limit": occurrence_limit,
                "occurrence_offset": occurrence_offset,
            },
        )

    def investigate_finding(self, finding_id: int) -> dict:
        return self._request(
            "POST", f"/findings/{finding_id}/investigate"
        )

    def update_finding_status(
        self,
        finding_id: int,
        status: str,
    ) -> dict:
        return self._request(
            "PATCH",
            f"/findings/{finding_id}/status",
            json={"status": status},
        )


def _validated_api_url(value: str) -> str:
    """Require TLS except for loopback development and the Compose API service."""
    if not isinstance(value, str) or not value or any(
        ord(character) <= 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError("TALARIA API URL must be a clean HTTP(S) origin.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("TALARIA API URL must be a clean HTTP(S) origin.") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or "\\" in parsed.netloc
        or "%" in parsed.netloc
    ):
        raise ValueError("TALARIA API URL must be a clean HTTP(S) origin.")
    if parsed.scheme == "http":
        normalized_host = hostname.casefold().rstrip(".")
        loopback = normalized_host in {"localhost", "127.0.0.1", "::1"}
        compose_api = normalized_host == "talaria-api" and port == 8000
        if not loopback and not compose_api:
            raise ValueError("TALARIA API must use HTTPS outside trusted local origins.")
    return value.rstrip("/")
