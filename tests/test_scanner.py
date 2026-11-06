
import pytest

from talaria.database import Database
from talaria.scanning.service import ScanService


def test_scan_finds_eval_and_persists(isolated_db, git_repo):
    db = Database(isolated_db / "db.sqlite")
    result = ScanService(db).scan(str(git_repo))

    assert result["finding_count"] >= 1
    assert any(item["rule_id"] == "python-eval" for item in result["findings"])

    findings = db.execute("SELECT * FROM findings")
    occurrences = db.execute("SELECT * FROM finding_occurrences")
    scans = db.execute("SELECT * FROM scans")

    assert len(findings) >= 1
    assert len(occurrences) == len(findings)
    assert scans[0]["status"] == "completed"


def test_scanner_does_not_modify_source(isolated_db, git_repo):
    source = git_repo / "app.py"
    before = source.read_bytes()

    ScanService(Database(isolated_db / "db.sqlite")).scan(str(git_repo))

    assert source.read_bytes() == before


def test_repeated_scan_creates_occurrences_without_duplicate_findings(
    isolated_db, git_repo
):
    db = Database(isolated_db / "db.sqlite")
    scanner = ScanService(db)

    first = scanner.scan(str(git_repo))
    second = scanner.scan(str(git_repo))

    assert first["finding_count"] == second["finding_count"]

    findings = db.execute("SELECT COUNT(*) AS count FROM findings")
    occurrences = db.execute("SELECT COUNT(*) AS count FROM finding_occurrences")

    assert findings[0]["count"] == first["finding_count"]
    assert occurrences[0]["count"] == first["finding_count"] * 2


def test_repeated_scan_preserves_finding_status(isolated_db, git_repo):
    db = Database(isolated_db / "db.sqlite")
    scanner = ScanService(db)

    first = scanner.scan(str(git_repo))
    fingerprint = first["findings"][0]["fingerprint"]

    db.execute(
        "UPDATE findings SET status = 'confirmed' WHERE fingerprint = ?",
        (fingerprint,),
    )

    scanner.scan(str(git_repo))

    result = db.execute(
        "SELECT status FROM findings WHERE fingerprint = ?",
        (fingerprint,),
    )

    assert result[0]["status"] == "confirmed"


def test_invalid_profile_does_not_create_scan(isolated_db, git_repo):
    db = Database(isolated_db / "db.sqlite")
    scanner = ScanService(db)

    with pytest.raises((ValueError, FileNotFoundError)):
        scanner.scan(str(git_repo), "nonexistent-profile")

    scans = db.execute("SELECT COUNT(*) AS count FROM scans")
    assert scans[0]["count"] == 0


def test_failed_scan_is_recorded(isolated_db, git_repo, monkeypatch):
    db = Database(isolated_db / "db.sqlite")
    scanner = ScanService(db)

    def fail_collection(root, profile):
        raise RuntimeError("Simulated scanner failure")

    monkeypatch.setattr(scanner, "_collect_findings", fail_collection)

    with pytest.raises(RuntimeError, match="Simulated scanner failure"):
        scanner.scan(str(git_repo))

    scans = db.execute("SELECT status, error_summary FROM scans")
    events = db.execute(
        "SELECT event FROM audit_events WHERE event = 'scan.failed'"
    )

    assert scans[0]["status"] == "failed"
    assert "Simulated scanner failure" in scans[0]["error_summary"]
    assert len(events) == 1


def test_scanner_enforces_max_file_bytes(isolated_db, git_repo):
    from talaria.scanning.limits import ScanLimits
    from talaria.scanning.service import ScanLimitExceeded

    (git_repo / "large.py").write_text("x = 1\n" * 100, encoding="utf-8")
    scanner = ScanService(
        Database(isolated_db / "large.db"),
        limits=ScanLimits(max_file_bytes=20),
    )

    with pytest.raises(ScanLimitExceeded, match="max_file_bytes"):
        scanner.scan(str(git_repo))


def test_scanner_enforces_max_files(isolated_db, git_repo):
    from talaria.scanning.limits import ScanLimits
    from talaria.scanning.service import ScanLimitExceeded

    (git_repo / "second.py").write_text("x = 1\n", encoding="utf-8")
    scanner = ScanService(
        Database(isolated_db / "files.db"),
        limits=ScanLimits(max_files=1),
    )

    with pytest.raises(ScanLimitExceeded, match="max_files"):
        scanner.scan(str(git_repo))


def test_scanner_enforces_max_total_bytes(isolated_db, git_repo):
    from talaria.scanning.limits import ScanLimits
    from talaria.scanning.service import ScanLimitExceeded

    (git_repo / "second.py").write_text("x = 1\n" * 10, encoding="utf-8")
    scanner = ScanService(
        Database(isolated_db / "total.db"),
        limits=ScanLimits(max_total_bytes=20),
    )

    with pytest.raises(ScanLimitExceeded, match="max_total_bytes"):
        scanner.scan(str(git_repo))


def test_scanner_respects_max_depth(isolated_db, git_repo):
    from talaria.scanning.limits import ScanLimits

    nested = git_repo / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "deep.py").write_text("value = eval(user_input)\n", encoding="utf-8")

    scanner = ScanService(
        Database(isolated_db / "depth.db"),
        limits=ScanLimits(max_depth=1),
    )

    result = scanner.scan(str(git_repo))

    assert not any(item["path"] == "one/two/deep.py" for item in result["findings"])


def test_scanner_does_not_follow_symlinked_files(isolated_db, git_repo, tmp_path):
    from talaria.scanning.limits import ScanLimits

    external = tmp_path / "external.py"
    external.write_text("value = eval(user_input)\n", encoding="utf-8")
    (git_repo / "linked.py").symlink_to(external)

    scanner = ScanService(
        Database(isolated_db / "symlink.db"),
        limits=ScanLimits(),
    )

    result = scanner.scan(str(git_repo))

    assert not any(item["path"] == "linked.py" for item in result["findings"])
