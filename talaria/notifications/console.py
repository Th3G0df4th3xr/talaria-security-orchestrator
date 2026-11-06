"""Local console notification adapter."""
import json
import logging
from typing import Any
from uuid import uuid4

from talaria.notifications.base import NotificationAdapter

logger = logging.getLogger("talaria.notifications")

SAFE_FIELDS = {
    "event",
    "scan_id",
    "repository",
    "finding_count",
    "status",
    "error_type",
}


class ConsoleNotificationAdapter(NotificationAdapter):
    """Emit sanitized notification summaries through standard logging."""

    @property
    def name(self) -> str:
        return "console"

    def send(self, message: dict[str, Any]) -> str:
        if not isinstance(message, dict):
            raise TypeError("Notification message must be a dictionary")

        safe_message = {
            key: value
            for key, value in message.items()
            if key in SAFE_FIELDS
        }

        delivery_id = f"console:{uuid4()}"

        logger.info(
            "notification.delivered id=%s payload=%s",
            delivery_id,
            json.dumps(safe_message, sort_keys=True, default=str),
        )

        return delivery_id
