"""HTTP client for the TALARIA dashboard."""

import os
from typing import Any

import requests


class DashboardAPIError(RuntimeError):
    """Raised when the TALARIA API request fails."""


class TalariaAPIClient:
    """Communicate with TALARIA exclusively through its HTTP API."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 8.0,
    ) -> None:
        self.base_url = (
            base_url or os.getenv(
                "TALARIA_API_URL",
                "http://127.0.0.1:8000",
            )
        ).rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> Any:
        url = f"{self.base_url}{endpoint}"

        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                **kwargs,
            )
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
            detail = response.text[:500]
            raise DashboardAPIError(
                f"TALARIA API returned HTTP "
                f"{response.status_code}: {detail}"
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

    def health(self) -> dict:
        return self._request("GET", "/health")

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

    def findings(self) -> list[dict]:
        return self._request("GET", "/findings")

    def finding(self, finding_id: int) -> dict:
        return self._request("GET", f"/findings/{finding_id}")

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
