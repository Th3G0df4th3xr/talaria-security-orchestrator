"""GitHub integration placeholder.

No network operations are implemented here yet. This module deliberately
fails closed until authentication, permissions, idempotency, and audit
requirements have dedicated implementations and tests.
"""
from __future__ import annotations

from typing import Any

from talaria.integrations.base import IntegrationAdapter, IntegrationError


class GitHubAdapter(IntegrationAdapter):
    @property
    def name(self) -> str:
        return "github"

    def health(self) -> dict[str, Any]:
        return {"name": self.name, "configured": False, "enabled": False}

    def create_pull_request(self, *_: Any, **__: Any) -> None:
        raise IntegrationError(
            "GitHub PR operations are not implemented; no remote action was taken."
        )
