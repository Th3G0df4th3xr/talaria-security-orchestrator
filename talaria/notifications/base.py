"""Notification contract; delivery adapters are not enabled by default."""
from abc import ABC, abstractmethod
from typing import Any


class NotificationAdapter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Stable adapter identifier."""

    @abstractmethod
    def send(self, message: dict[str, Any]) -> str:
        """Deliver a notification and return a provider delivery identifier."""
