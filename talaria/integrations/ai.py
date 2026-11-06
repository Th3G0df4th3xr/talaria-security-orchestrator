"""AI investigation integration placeholder.

The deterministic investigation path remains the default. This adapter does
not send repository content to an external provider.
"""
from __future__ import annotations

from typing import Any

from talaria.integrations.base import IntegrationAdapter, IntegrationError


class AIInvestigationAdapter(IntegrationAdapter):
    @property
    def name(self) -> str:
        return "ai-investigation"

    def health(self) -> dict[str, Any]:
        return {"name": self.name, "configured": False, "enabled": False}

    def investigate(self, *_: Any, **__: Any) -> dict[str, Any]:
        raise IntegrationError(
            "AI investigation is not configured; deterministic analysis remains available."
        )
