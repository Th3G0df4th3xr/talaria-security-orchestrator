import json

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from talaria.config import database_path
from talaria.database import Database
from talaria.findings.lifecycle import FindingStatus, can_transition
from talaria.models import RepositoryInput, ScanInput
from talaria.repositories.service import RepositoryError, RepositoryService
from talaria.scanning.service import ScanService


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: FindingStatus


app = FastAPI(
    title="TALARIA",
    version="0.2.0",
    description="Local-first application security orchestration platform",
)


def services():
    db = Database(database_path())
    return db, RepositoryService(db), ScanService(db)


def finding_record(db: Database, finding_id: int):
    rows = db.execute(
        """
        SELECT id, fingerprint, repository_id, payload,
               status, first_seen_at, last_seen_at
        FROM findings
        WHERE id = ?
        """,
        (finding_id,),
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Finding not found")

    record = rows[0]
    record["payload"] = json.loads(record["payload"])

    return record


@app.get("/health")
def health():
    return {"status": "ok", "service": "talaria", "version": "0.2.0"}


@app.get("/repositories")
def repositories():
    _, service, _ = services()
    return service.list()


@app.post("/repositories")
def register_repository(payload: RepositoryInput):
    _, service, _ = services()

    try:
        return service.register(payload.path)
    except RepositoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scans")
def run_scan(payload: ScanInput):
    _, _, service = services()

    try:
        return service.scan(payload.repository_path)
    except (RepositoryError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc




@app.get("/dashboard/summary")
def dashboard_summary():
    db, _, _ = services()

    repositories = db.execute(
        "SELECT COUNT(*) AS total FROM repositories"
    )[0]["total"]

    scans = db.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running
        FROM scans
        """
    )[0]

    findings = db.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open,
            SUM(CASE WHEN status = 'confirmed' THEN 1 ELSE 0 END) AS confirmed,
            SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) AS fixed,
            SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END)
                AS false_positive
        FROM findings
        """
    )[0]

    return {
        "repositories": repositories,
        "scans": {key: value or 0 for key, value in scans.items()},
        "findings": {key: value or 0 for key, value in findings.items()},
    }


@app.get("/scans")
def scan_history(limit: int = Query(default=100, ge=1, le=500)):
    db, _, _ = services()

    return db.execute(
        """
        SELECT
            s.id,
            s.repository_id,
            r.name AS repository,
            s.started_at,
            s.completed_at,
            s.status,
            s.finding_count,
            s.error_summary
        FROM scans AS s
        JOIN repositories AS r ON r.id = s.repository_id
        ORDER BY s.id DESC
        LIMIT ?
        """,
        (limit,),
    )


@app.get("/dashboard/severity")
def dashboard_severity():
    db, _, _ = services()

    rows = db.execute("SELECT payload FROM findings")

    distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }

    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except (TypeError, ValueError):
            distribution["unknown"] += 1
            continue

        severity = str(payload.get("severity", "unknown")).lower()

        if severity not in distribution:
            severity = "unknown"

        distribution[severity] += 1

    return {
        "total": len(rows),
        "distribution": distribution,
    }


@app.get("/dashboard/trends")
def dashboard_trends(days: int = Query(default=30, ge=1, le=365)):
    db, _, _ = services()

    rows = db.execute(
        """
        SELECT
            date(observed_at) AS date,
            COUNT(*) AS occurrences,
            COUNT(DISTINCT finding_id) AS unique_findings
        FROM finding_occurrences
        WHERE date(observed_at) >= date('now', ?)
        GROUP BY date(observed_at)
        ORDER BY date ASC
        """,
        (f"-{days - 1} days",),
    )

    return {
        "period_days": days,
        "data": rows,
    }


@app.get("/findings")
def findings():
    db, _, _ = services()

    rows = db.execute(
        """
        SELECT id, fingerprint, repository_id, payload,
               status, first_seen_at, last_seen_at
        FROM findings
        ORDER BY id DESC
        """
    )

    for row in rows:
        row["payload"] = json.loads(row["payload"])

    return rows


@app.get("/findings/{finding_id}")
def finding(finding_id: int):
    db, _, _ = services()
    record = finding_record(db, finding_id)

    record["occurrences"] = db.execute(
        """
        SELECT
            fo.scan_id,
            fo.observed_at,
            s.status AS scan_status,
            s.completed_at
        FROM finding_occurrences AS fo
        JOIN scans AS s ON s.id = fo.scan_id
        WHERE fo.finding_id = ?
        ORDER BY fo.observed_at DESC
        """,
        (finding_id,),
    )

    return record


@app.patch("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
):
    db, _, _ = services()

    with db.transaction() as connection:
        row = connection.execute(
            """
            SELECT id, fingerprint, status
            FROM findings
            WHERE id = ?
            """,
            (finding_id,),
        ).fetchone()

        if row is None:
            raise HTTPException(status_code=404, detail="Finding not found")

        current = FindingStatus(row["status"])
        target = payload.status

        if current == target:
            return {
                "finding_id": finding_id,
                "previous_status": current.value,
                "status": target.value,
                "changed": False,
            }

        if not can_transition(current, target):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Transition from {current.value} "
                    f"to {target.value} is not permitted"
                ),
            )

        cursor = connection.execute(
            """
            UPDATE findings
            SET status = ?
            WHERE id = ? AND status = ?
            """,
            (target.value, finding_id, current.value),
        )

        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=409,
                detail="Finding status changed concurrently",
            )

        connection.execute(
            """
            INSERT INTO audit_events(event, details)
            VALUES (?, ?)
            """,
            (
                "finding.status_changed",
                json.dumps(
                    {
                        "finding_id": finding_id,
                        "fingerprint": row["fingerprint"],
                        "previous_status": current.value,
                        "new_status": target.value,
                    },
                    sort_keys=True,
                ),
            ),
        )

    return {
        "finding_id": finding_id,
        "previous_status": current.value,
        "status": target.value,
        "changed": True,
    }
