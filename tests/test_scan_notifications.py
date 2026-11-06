import logging

import pytest

from talaria.database import Database
from talaria.notifications.base import NotificationAdapter
from talaria.scanning.service import ScanService


class RecordingNotifier(NotificationAdapter):
    def __init__(self):
        self.messages = []

    @property
    def name(self):
        return "test"

    def send(self, message):
        self.messages.append(message)
        return "test-delivery-id"


class BrokenNotifier(NotificationAdapter):
    @property
    def name(self):
        return "broken"

    def send(self, message):
        raise RuntimeError("Notification provider unavailable")


def test_successful_scan_sends_completion_notification(isolated_db, git_repo):
    db = Database(isolated_db / "db.sqlite")
    notifier = RecordingNotifier()
    scanner = ScanService(db, notifier=notifier)

    result = scanner.scan(str(git_repo))

    assert len(notifier.messages) == 1
    assert notifier.messages[0]["event"] == "scan.completed"
    assert notifier.messages[0]["scan_id"] == result["scan_id"]
    assert notifier.messages[0]["status"] == "completed"


def test_failed_scan_sends_failure_notification(
    isolated_db, git_repo, monkeypatch
):
    db = Database(isolated_db / "db.sqlite")
    notifier = RecordingNotifier()
    scanner = ScanService(db, notifier=notifier)

    def fail_collection(root, profile):
        raise RuntimeError("Simulated scanner failure")

    monkeypatch.setattr(scanner, "_collect_findings", fail_collection)

    with pytest.raises(RuntimeError, match="Simulated scanner failure"):
        scanner.scan(str(git_repo))

    assert len(notifier.messages) == 1
    assert notifier.messages[0]["event"] == "scan.failed"
    assert notifier.messages[0]["status"] == "failed"
    assert notifier.messages[0]["error_type"] == "RuntimeError"


def test_notification_failure_does_not_fail_successful_scan(
    isolated_db, git_repo, caplog
):
    db = Database(isolated_db / "db.sqlite")
    scanner = ScanService(db, notifier=BrokenNotifier())

    with caplog.at_level(logging.WARNING):
        result = scanner.scan(str(git_repo))

    scans = db.execute(
        "SELECT status FROM scans WHERE id = ?",
        (result["scan_id"],),
    )

    assert scans[0]["status"] == "completed"
    assert "Notification delivery failed" in caplog.text
