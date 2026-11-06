"""Common integration contracts.

Concrete integrations should implement these interfaces without exposing
provider-specific response objects to the domain layer.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class IntegrationError(RuntimeError):
    """Raised when an external integration operation fails."""


class IntegrationAdapter(ABC):
    """Base contract for an optional external integration."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return a stable integration identifier."""

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Return a redacted integration health summary."""
