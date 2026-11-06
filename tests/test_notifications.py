import logging

import pytest

from talaria.notifications.console import ConsoleNotificationAdapter


def test_console_adapter_sends_notification(caplog):
    adapter = ConsoleNotificationAdapter()

    with caplog.at_level(logging.INFO, logger="talaria.notifications"):
        delivery_id = adapter.send(
            {
                "event": "scan.completed",
                "scan_id": 12,
                "repository": "sample-repo",
                "finding_count": 3,
            }
        )

    assert adapter.name == "console"
    assert delivery_id.startswith("console:")
    assert "scan.completed" in caplog.text
    assert "sample-repo" in caplog.text


def test_console_adapter_does_not_log_unapproved_fields(caplog):
    adapter = ConsoleNotificationAdapter()

    with caplog.at_level(logging.INFO, logger="talaria.notifications"):
        adapter.send(
            {
                "event": "scan.completed",
                "snippet": "SECRET_VALUE",
                "password": "DO_NOT_LOG",
            }
        )

    assert "scan.completed" in caplog.text
    assert "SECRET_VALUE" not in caplog.text
    assert "DO_NOT_LOG" not in caplog.text


def test_console_adapter_rejects_non_dictionary():
    adapter = ConsoleNotificationAdapter()

    with pytest.raises(TypeError):
        adapter.send("invalid")
