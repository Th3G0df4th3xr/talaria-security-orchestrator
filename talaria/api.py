import asyncio
import hmac
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from starlette.responses import Response

from talaria.auth.api import (
    RequestContext,
    require_roles,
)
from talaria.auth.api import (
    router as auth_router,
)
from talaria.config import (
    allowed_repository_roots,
    database_path,
    validate_runtime_configuration,
)
from talaria.database import CURRENT_SCHEMA_VERSION, Database
from talaria.findings.lifecycle import FindingStatus, can_transition
from talaria.integrations.api import router as github_router
from talaria.integrations.base import IntegrationError
from talaria.integrations.llm import AIInvestigationAdapter, LLMSettings
from talaria.investigation.context import ContextError, RepositoryContextCollector
from talaria.models import RepositoryInput, ScanInput
from talaria.repositories.service import RepositoryError, RepositoryService
from talaria.scanning.service import ScanService
from talaria.security.middleware import (
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
    request_metrics,
)
from talaria.security.secrets import SecretFileError, read_secret_file

AI_INVESTIGATION_STALE_AFTER = timedelta(minutes=5)
AI_INVESTIGATION_RECOVERY_BATCH_SIZE = 100
AI_INVESTIGATION_RECOVERY_INTERVAL_SECONDS = 60
logger = logging.getLogger(__name__)


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: FindingStatus


@asynccontextmanager
async def _application_lifespan(_app):
    validate_runtime_configuration()
    database = Database(database_path(), initialize=False)
    while _recover_stale_investigations(database) == AI_INVESTIGATION_RECOVERY_BATCH_SIZE:
        await asyncio.sleep(0)
    recovery_task = asyncio.create_task(_periodic_investigation_recovery(database))
    try:
        yield
    finally:
        recovery_task.cancel()
        try:
            await recovery_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="TALARIA",
    version="0.2.0",
    description="Local-first application security orchestration platform",
    lifespan=_application_lifespan,
)
app.include_router(auth_router)
app.include_router(github_router)
# Starlette wraps middleware in reverse registration order, so security
# headers and request logging also cover body-limit responses.
app.add_middleware(RequestBodyLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


def services():
    db = Database(database_path(), initialize=False)
    allowed_roots = allowed_repository_roots()
    return (
        db,
        RepositoryService(db, allowed_roots),
        ScanService(db, allowed_roots=allowed_roots),
    )


def _fail_investigation(
    database: Database,
    investigation_id: str,
    finding_id: int,
    user_id: str,
    error_type: str,
) -> None:
    with database.transaction() as connection:
        cursor = connection.execute(
            """UPDATE investigations SET status = 'failed', finished_at = ?,
                      error_type = ? WHERE id = ? AND status = 'running'""",
            (datetime.now(UTC).isoformat(), error_type, investigation_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("Investigation state changed unexpectedly")
        database.audit_in_transaction(
            connection,
            "ai.investigation_failed",
            {
                "investigation_id": investigation_id,
                "finding_id": finding_id,
                "user_id": user_id,
                "error_type": error_type,
            },
        )


def _recover_stale_investigations(
    database: Database, organization_id: str | None = None
) -> int:
    """Mark abandoned investigations failed and audit each transition."""
    cutoff = (datetime.now(UTC) - AI_INVESTIGATION_STALE_AFTER).isoformat()
    recovered = 0
    with database.transaction() as connection:
        query_parameters = (cutoff, AI_INVESTIGATION_RECOVERY_BATCH_SIZE)
        if organization_id:
            stale_query = """SELECT id, organization_id, finding_id, initiated_by, started_at
                FROM investigations
                WHERE status = 'running' AND started_at < ? AND organization_id = ?
                ORDER BY started_at, id LIMIT ?"""
            query_parameters = (
                cutoff,
                organization_id,
                AI_INVESTIGATION_RECOVERY_BATCH_SIZE,
            )
        else:
            stale_query = """SELECT id, organization_id, finding_id, initiated_by, started_at
                FROM investigations
                WHERE status = 'running' AND started_at < ?
                ORDER BY started_at, id LIMIT ?"""
        stale = connection.execute(
            stale_query,
            query_parameters,
        ).fetchall()
        for investigation in stale:
            cursor = connection.execute(
                """UPDATE investigations
                   SET status = 'failed', finished_at = ?, error_type = 'StaleInvestigation'
                   WHERE id = ? AND organization_id = ? AND status = 'running'
                     AND started_at < ?""",
                (
                    datetime.now(UTC).isoformat(),
                    investigation["id"],
                    investigation["organization_id"],
                    cutoff,
                ),
            )
            if cursor.rowcount != 1:
                continue
            database.audit_in_transaction(
                connection,
                "ai.investigation_stale_failed",
                {
                    "investigation_id": investigation["id"],
                    "finding_id": investigation["finding_id"],
                    "initiated_by": investigation["initiated_by"],
                    "organization_id": investigation["organization_id"],
                    "started_at": investigation["started_at"],
                    "error_type": "StaleInvestigation",
                },
            )
            recovered += 1
    return recovered


async def _periodic_investigation_recovery(database: Database) -> None:
    """Recheck abandoned investigations periodically after application startup."""
    while True:
        await asyncio.sleep(AI_INVESTIGATION_RECOVERY_INTERVAL_SECONDS)
        try:
            while (
                _recover_stale_investigations(database)
                == AI_INVESTIGATION_RECOVERY_BATCH_SIZE
            ):
                await asyncio.sleep(0)
        except Exception:
            # Do not log exception text that may contain provider or database details.
            logger.error("Periodic stale-investigation recovery failed")


def finding_record(db: Database, finding_id: int, organization_id: str):
    rows = db.execute(
        """
        SELECT findings.id, findings.fingerprint, findings.repository_id,
               findings.payload, findings.status, findings.first_seen_at,
               findings.last_seen_at
        FROM findings
        JOIN repositories ON repositories.id = findings.repository_id
        WHERE findings.id = ? AND repositories.organization_id = ?
        """,
        (finding_id, organization_id),
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Finding not found")

    record = rows[0]
    record["payload"] = json.loads(record["payload"])

    return record


@app.get("/health")
def health():
    return {"status": "ok", "service": "talaria", "version": "0.2.0"}


@app.get("/health/live")
def liveness():
    return {"status": "alive"}


@app.get("/health/ready")
def readiness():
    ready, version = Database.readiness(database_path())
    if not ready:
        raise HTTPException(status_code=503, detail="Database is not ready")
    return {"status": "ready", "schema_version": CURRENT_SCHEMA_VERSION}


@app.get("/metrics", include_in_schema=False)
def metrics(authorization: str | None = Header(default=None)):
    credential_path = os.getenv("TALARIA_METRICS_TOKEN_FILE")
    if credential_path:
        try:
            expected = read_secret_file(
                credential_path, label="metrics configuration", allow_empty=True
            )
        except SecretFileError as exc:
            raise HTTPException(status_code=503, detail="Metrics are unavailable") from exc
    else:
        expected = os.getenv("TALARIA_METRICS_TOKEN", "").strip()
    if not expected:
        raise HTTPException(status_code=404, detail="Not found")
    scheme, separator, supplied = (authorization or "").partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not hmac.compare_digest(supplied, expected)
    ):
        raise HTTPException(status_code=401, detail="Invalid metrics credentials")
    return Response(
        request_metrics.render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/repositories")
def repositories(context: RequestContext = Depends(require_roles(
    "org_admin", "security_lead", "security_analyst", "developer", "auditor"
))):
    _, service, _ = services()
    return service.list(_organization(context))


@app.post("/repositories")
def register_repository(
    payload: RepositoryInput,
    context: RequestContext = Depends(require_roles("org_admin", "security_lead")),
):
    _, service, _ = services()

    try:
        return service.register(payload.path, _organization(context))
    except RepositoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scans")
def run_scan(
    payload: ScanInput,
    context: RequestContext = Depends(require_roles(
        "org_admin", "security_lead", "security_analyst"
    )),
):
    _, _, service = services()

    try:
        result = service.scan(payload.repository_path, organization_id=_organization(context))
    except (RepositoryError, ValueError) as exc:
        request_metrics.record_scan("rejected")
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        request_metrics.record_scan("failed")
        raise
    request_metrics.record_scan("completed")
    return result




@app.get("/dashboard/summary")
def dashboard_summary(context: RequestContext = Depends(require_roles(
    "org_admin", "security_lead", "security_analyst", "developer", "auditor"
))):
    db, _, _ = services()
    organization_id = _organization(context)

    repositories = db.execute(
        "SELECT COUNT(*) AS total FROM repositories WHERE organization_id = ?",
        (organization_id,),
    )[0]["total"]

    scans = db.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running
        FROM scans JOIN repositories ON repositories.id = scans.repository_id
        WHERE repositories.organization_id = ?
        """,
        (organization_id,),
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
        FROM findings JOIN repositories ON repositories.id = findings.repository_id
        WHERE repositories.organization_id = ?
        """,
        (organization_id,),
    )[0]

    return {
        "repositories": repositories,
        "scans": {key: value or 0 for key, value in scans.items()},
        "findings": {key: value or 0 for key, value in findings.items()},
    }


@app.get("/scans")
def scan_history(
    limit: int = Query(default=100, ge=1, le=500),
    context: RequestContext = Depends(require_roles(
        "org_admin", "security_lead", "security_analyst", "developer", "auditor"
    )),
):
    db, _, _ = services()

    return db.execute(
        """
        SELECT
            s.id,
            s.repository_id,
            r.name AS repository,
            s.branch,
            s.commit_sha,
            s.started_at,
            s.completed_at,
            s.status,
            s.finding_count,
            s.error_summary
        FROM scans AS s
        JOIN repositories AS r ON r.id = s.repository_id
        WHERE r.organization_id = ?
        ORDER BY s.id DESC
        LIMIT ?
        """,
        (_organization(context), limit),
    )


@app.get("/dashboard/severity")
def dashboard_severity(context: RequestContext = Depends(require_roles(
    "org_admin", "security_lead", "security_analyst", "developer", "auditor"
))):
    db, _, _ = services()

    rows = db.execute(
        """SELECT findings.payload FROM findings
           JOIN repositories ON repositories.id = findings.repository_id
           WHERE repositories.organization_id = ?""",
        (_organization(context),),
    )

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
def dashboard_trends(
    days: int = Query(default=30, ge=1, le=365),
    context: RequestContext = Depends(require_roles(
        "org_admin", "security_lead", "security_analyst", "developer", "auditor"
    )),
):
    db, _, _ = services()

    rows = db.execute(
        """
        SELECT
            substr(observed_at, 1, 10) AS date,
            COUNT(*) AS occurrences,
            COUNT(DISTINCT finding_id) AS unique_findings
        FROM finding_occurrences
        JOIN findings ON findings.id = finding_occurrences.finding_id
        JOIN repositories ON repositories.id = findings.repository_id
        WHERE repositories.organization_id = ?
          AND substr(observed_at, 1, 10) >= ?
        GROUP BY substr(observed_at, 1, 10)
        ORDER BY date ASC
        """,
        (
            _organization(context),
            (datetime.now(UTC).date() - timedelta(days=days - 1)).isoformat(),
        ),
    )

    return {
        "period_days": days,
        "data": rows,
    }


@app.get("/findings")
def findings(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    context: RequestContext = Depends(require_roles(
        "org_admin", "security_lead", "security_analyst", "developer", "auditor"
    )),
):
    db, _, _ = services()

    rows = db.execute(
        """
        SELECT findings.id, findings.fingerprint, findings.repository_id,
               findings.payload, findings.status, findings.first_seen_at,
               findings.last_seen_at
        FROM findings
        JOIN repositories ON repositories.id = findings.repository_id
        WHERE repositories.organization_id = ?
        ORDER BY findings.id DESC
        LIMIT ? OFFSET ?
        """,
        (_organization(context), limit, offset),
    )

    for row in rows:
        row["payload"] = json.loads(row["payload"])

    return rows


@app.get("/findings/{finding_id}")
def finding(
    finding_id: int,
    occurrence_limit: int = Query(default=100, ge=1, le=500),
    occurrence_offset: int = Query(default=0, ge=0, le=1_000_000),
    context: RequestContext = Depends(require_roles(
        "org_admin", "security_lead", "security_analyst", "developer", "auditor"
    )),
):
    db, _, _ = services()
    record = finding_record(db, finding_id, _organization(context))

    record["occurrences"] = db.execute(
        """
        SELECT
            fo.scan_id,
            fo.observed_at,
            s.status AS scan_status,
            s.completed_at,
            s.branch,
            s.commit_sha
        FROM finding_occurrences AS fo
        JOIN scans AS s ON s.id = fo.scan_id
        WHERE fo.finding_id = ?
        ORDER BY fo.observed_at DESC
        LIMIT ? OFFSET ?
        """,
        (finding_id, occurrence_limit, occurrence_offset),
    )

    return record


@app.post("/findings/{finding_id}/investigate")
def investigate_finding(
    finding_id: int,
    context: RequestContext = Depends(require_roles(
        "org_admin", "security_lead", "security_analyst"
    )),
):
    db, _, _ = services()
    organization_id = _organization(context)
    rows = db.execute(
        """
        SELECT findings.payload, findings.repository_id,
               repositories.path AS repository_path
        FROM findings
        JOIN repositories ON repositories.id = findings.repository_id
        WHERE findings.id = ? AND repositories.organization_id = ?
        """,
        (finding_id, organization_id),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Finding not found")
    try:
        finding_data = json.loads(rows[0]["payload"])
        settings = LLMSettings.from_environment()
    except (TypeError, ValueError, IntegrationError) as exc:
        raise HTTPException(status_code=503, detail="AI investigation is unavailable") from exc
    if not settings.enabled:
        raise HTTPException(status_code=503, detail="AI investigation is disabled")
    investigation_id = str(uuid4())
    started_at = datetime.now(UTC).isoformat()
    provider = urlparse(settings.base_url).hostname or "unknown"
    with db.transaction() as connection:
        connection.execute(
            """INSERT INTO investigations
               (id, organization_id, repository_id, finding_id, initiated_by,
                provider, model, status, started_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?)""",
            (
                investigation_id,
                organization_id,
                rows[0]["repository_id"],
                finding_id,
                context.user["id"],
                provider,
                settings.model,
                started_at,
            ),
        )
        db.audit_in_transaction(
            connection,
            "ai.investigation_started",
            {
                "investigation_id": investigation_id,
                "finding_id": finding_id,
                "user_id": context.user["id"],
                "organization_id": organization_id,
            },
        )
    try:
        adapter = AIInvestigationAdapter(settings=settings)
    except (TypeError, ValueError, IntegrationError) as exc:
        _fail_investigation(
            db, investigation_id, finding_id, context.user["id"], type(exc).__name__
        )
        raise HTTPException(
            status_code=503, detail="AI investigation provider is unavailable"
        ) from exc

    source_context = None
    if settings.send_source:
        repository_path = Path(rows[0]["repository_path"]).expanduser()
        finding_path = finding_data.get("path") if isinstance(finding_data, dict) else None
        finding_line = finding_data.get("line") if isinstance(finding_data, dict) else None
        if (
            not isinstance(finding_path, str)
            or not isinstance(finding_line, int)
            or isinstance(finding_line, bool)
            or finding_line < 1
        ):
            _fail_investigation(
                db, investigation_id, finding_id, context.user["id"], "ContextError"
            )
            raise HTTPException(status_code=422, detail="Finding has no safe source location")
        try:
            repository_root = repository_path.resolve(strict=True)
            allowed = allowed_repository_roots()
            if not any(
                repository_root == root or root in repository_root.parents
                for root in allowed
            ):
                raise ContextError("Repository is outside the configured context roots")
            source_item = RepositoryContextCollector().collect(
                repository_root, finding_path, finding_line
            )
            scanned_digest = (
                finding_data.get("source_sha256")
                if isinstance(finding_data, dict)
                else None
            )
            if not isinstance(scanned_digest, str) or not re.fullmatch(
                r"[0-9a-f]{64}", scanned_digest
            ):
                raise ContextError(
                    "Finding lacks a scan-time source digest; rescan before sharing source"
                )
            if not hmac.compare_digest(
                source_item["content_sha256"], scanned_digest
            ):
                raise ContextError(
                    "Repository source changed after the finding was scanned"
                )
            source_context = [source_item]
        except (ContextError, OSError, RuntimeError, ValueError) as exc:
            _fail_investigation(
                db, investigation_id, finding_id, context.user["id"], type(exc).__name__
            )
            raise HTTPException(
                status_code=422,
                detail="Finding source context could not be collected safely",
            ) from exc

    try:
        result = adapter.investigate(finding_data, source_context)
    except Exception as exc:
        _fail_investigation(
            db, investigation_id, finding_id, context.user["id"], type(exc).__name__
        )
        detail = (
            "AI investigation is disabled"
            if not settings.enabled
            else "AI investigation provider failed"
        )
        raise HTTPException(status_code=503, detail=detail) from exc

    with db.transaction() as connection:
        cursor = connection.execute(
            """UPDATE investigations SET status = 'completed', finished_at = ?,
                      evidence_refs = ?, result = ?
               WHERE id = ? AND status = 'running'""",
            (
                datetime.now(UTC).isoformat(),
                json.dumps(result["evidence_refs"], separators=(",", ":")),
                json.dumps(result, separators=(",", ":"), sort_keys=True),
                investigation_id,
            ),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("Investigation state changed unexpectedly")
        db.audit_in_transaction(
            connection,
            "ai.investigation_completed",
            {
                "investigation_id": investigation_id,
                "finding_id": finding_id,
                "user_id": context.user["id"],
                "organization_id": organization_id,
                "triage": result["triage"],
                "confidence": result["confidence"],
                "evidence_count": len(result["evidence_refs"]),
                "source_sent": bool(source_context and settings.send_source),
            },
        )
    return {
        "investigation_id": investigation_id,
        "finding_id": finding_id,
        "investigation": result,
    }


@app.get("/investigations")
def list_investigations(
    limit: int = Query(default=100, ge=1, le=500),
    context: RequestContext = Depends(require_roles(
        "org_admin", "security_lead", "security_analyst", "auditor"
    )),
):
    db, _, _ = services()
    _recover_stale_investigations(db, _organization(context))
    rows = db.execute(
        """SELECT id, finding_id, initiated_by, provider, model, status,
                  started_at, finished_at, evidence_refs, result, error_type
           FROM investigations WHERE organization_id = ?
           ORDER BY started_at DESC, id LIMIT ?""",
        (_organization(context), limit),
    )
    for row in rows:
        row["evidence_refs"] = json.loads(row["evidence_refs"])
        row["result"] = json.loads(row["result"]) if row["result"] else None
    return {"investigations": rows}


@app.patch("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    context: RequestContext = Depends(require_roles(
        "org_admin", "security_lead", "security_analyst"
    )),
):
    db, _, _ = services()

    with db.transaction() as connection:
        row = connection.execute(
            """
            SELECT findings.id, findings.fingerprint, findings.status
            FROM findings
            JOIN repositories ON repositories.id = findings.repository_id
            WHERE findings.id = ? AND repositories.organization_id = ?
            """,
            (finding_id, _organization(context)),
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

        db.audit_in_transaction(
            connection,
            "finding.status_changed",
            {
                "finding_id": finding_id,
                "fingerprint": row["fingerprint"],
                "previous_status": current.value,
                "new_status": target.value,
            },
        )

    return {
        "finding_id": finding_id,
        "previous_status": current.value,
        "status": target.value,
        "changed": True,
    }


def _organization(context: RequestContext) -> str:
    if not context.organization_id:
        raise HTTPException(status_code=400, detail="Select an organization")
    return context.organization_id
