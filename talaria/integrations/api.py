"""Authenticated GitHub webhook intake."""

import hashlib
import hmac
import json
import os
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from talaria.auth.api import RequestContext, require_roles
from talaria.config import database_path
from talaria.database import Database
from talaria.integrations.base import IntegrationError
from talaria.integrations.github import (
    GitHubAdapter,
    GitHubAppClient,
    verify_webhook_signature,
)
from talaria.security.secrets import SecretFileError, read_secret_file

router = APIRouter(prefix="/integrations/github", tags=["github"])
MAX_WEBHOOK_BYTES = 1_000_000
WEBHOOK_DELIVERY_RETENTION_DAYS = 30


class GitHubRepositoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_id: int = Field(ge=1)
    owner: str = Field(min_length=1, max_length=100)
    repository: str = Field(min_length=1, max_length=100)


@router.post("/repositories", status_code=201)
def onboard_repository(
    payload: GitHubRepositoryInput,
    context: RequestContext = Depends(
        require_roles("platform_admin")
    ),
):
    if not context.organization_id:
        raise HTTPException(status_code=400, detail="Select an organization")
    database = Database(database_path(), initialize=False)
    local = database.execute(
        "SELECT id FROM repositories WHERE id = ? AND organization_id = ?",
        (payload.repository_id, context.organization_id),
    )
    if not local:
        raise HTTPException(status_code=404, detail="Repository not found")
    try:
        client = GitHubAppClient()
    except IntegrationError as exc:
        raise HTTPException(status_code=503, detail="GitHub App is not configured") from exc
    if (
        not client.configured
        or not client.installation_id
        or not client.installation_id.isdigit()
    ):
        raise HTTPException(status_code=503, detail="GitHub App is not configured")
    try:
        remote = GitHubAdapter(client=client).repository(
            payload.owner, payload.repository
        )
    except IntegrationError as exc:
        raise HTTPException(
            status_code=503, detail="GitHub repository could not be verified"
        ) from exc
    github_repository_id = remote.get("id") if isinstance(remote, dict) else None
    full_name = remote.get("full_name") if isinstance(remote, dict) else None
    default_branch = remote.get("default_branch") if isinstance(remote, dict) else None
    expected_name = f"{payload.owner}/{payload.repository}"
    if (
        not isinstance(github_repository_id, int)
        or isinstance(github_repository_id, bool)
        or github_repository_id < 1
        or not isinstance(full_name, str)
        or full_name.casefold() != expected_name.casefold()
        or not isinstance(default_branch, str)
        or not default_branch
        or len(default_branch) > 255
    ):
        raise HTTPException(status_code=502, detail="GitHub returned invalid repository data")

    with database.transaction() as connection:
        existing = connection.execute(
            """SELECT organization_id, repository_id, full_name, installation_id,
                      default_branch, enabled
               FROM github_repositories WHERE github_repository_id = ?""",
            (github_repository_id,),
        ).fetchone()
        if existing is not None:
            if (
                existing["organization_id"] != context.organization_id
                or existing["repository_id"] != payload.repository_id
                or existing["installation_id"] != client.installation_id
            ):
                raise HTTPException(status_code=409, detail="GitHub repository is already bound")
            return {
                "github_repository_id": github_repository_id,
                "organization_id": context.organization_id,
                "repository_id": payload.repository_id,
                "full_name": existing["full_name"],
                "default_branch": existing["default_branch"],
                "enabled": bool(existing["enabled"]),
                "created": False,
            }
        conflict = connection.execute(
            """SELECT github_repository_id FROM github_repositories
               WHERE organization_id = ? AND full_name = ?""",
            (context.organization_id, full_name),
        ).fetchone()
        if conflict is not None:
            raise HTTPException(status_code=409, detail="GitHub repository name is already bound")
        cursor = connection.execute(
            """INSERT INTO github_repositories
               (github_repository_id, organization_id, repository_id, full_name,
                installation_id, default_branch, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
            (
                github_repository_id,
                context.organization_id,
                payload.repository_id,
                full_name,
                client.installation_id,
                default_branch,
                datetime.now(UTC).isoformat(),
            ),
        )
        if cursor.rowcount != 1:
            raise HTTPException(status_code=409, detail="GitHub repository is already bound")
        database.audit_in_transaction(
            connection,
            "github.repository_onboarded",
            {
                "github_repository_id": github_repository_id,
                "organization_id": context.organization_id,
                "repository_id": payload.repository_id,
                "full_name": full_name,
                "installation_id": client.installation_id,
                "actor_id": context.user["id"],
            },
        )
    return {
        "github_repository_id": github_repository_id,
        "organization_id": context.organization_id,
        "repository_id": payload.repository_id,
        "full_name": full_name,
        "default_branch": default_branch,
        "enabled": True,
        "created": True,
    }


@router.get("/repositories")
def list_onboarded_repositories(
    context: RequestContext = Depends(
        require_roles(
            "org_admin", "security_lead", "security_analyst", "auditor"
        )
    ),
):
    if not context.organization_id:
        raise HTTPException(status_code=400, detail="Select an organization")
    database = Database(database_path(), initialize=False)
    repositories = database.execute(
        """SELECT github_repository_id, repository_id, full_name, default_branch,
                  enabled, created_at
           FROM github_repositories WHERE organization_id = ?
           ORDER BY full_name LIMIT 500""",
        (context.organization_id,),
    )
    for repository in repositories:
        repository["enabled"] = bool(repository["enabled"])
    return {"repositories": repositories}


@router.get("/pull-requests")
def list_pull_request_states(
    limit: int = Query(default=100, ge=1, le=500),
    context: RequestContext = Depends(
        require_roles("org_admin", "security_lead", "security_analyst", "auditor")
    ),
):
    """Return the latest persisted signed-event state per tenant PR."""
    if not context.organization_id:
        raise HTTPException(status_code=400, detail="Select an organization")
    database = Database(database_path(), initialize=False)
    pull_requests = database.execute(
        """WITH ranked_events AS (
               SELECT github_repository_id, pull_request_number,
                      pull_request_state, merged, action, ref, base_ref,
                      commit_sha, actor, received_at, delivery_id,
                      ROW_NUMBER() OVER (
                          PARTITION BY github_repository_id, pull_request_number
                          ORDER BY received_at DESC, delivery_id DESC
                      ) AS event_rank
               FROM github_events
               WHERE organization_id = ? AND event = 'pull_request'
                 AND github_repository_id IS NOT NULL
                 AND pull_request_number IS NOT NULL
           )
           SELECT events.github_repository_id, repositories.repository_id,
                  repositories.full_name, events.pull_request_number,
                  events.pull_request_state, events.merged, events.action,
                  events.ref AS head_ref, events.base_ref, events.commit_sha,
                  events.actor, events.received_at
           FROM ranked_events AS events
           JOIN github_repositories AS repositories
             ON repositories.github_repository_id = events.github_repository_id
            AND repositories.organization_id = ? AND repositories.enabled = 1
           WHERE events.event_rank = 1
           ORDER BY events.received_at DESC, events.delivery_id DESC
           LIMIT ?""",
        (context.organization_id, context.organization_id, limit),
    )
    return {"pull_requests": pull_requests}


@router.get("/repositories/{github_repository_id}/commits/{sha}/check-runs")
def synchronize_check_runs(
    github_repository_id: int,
    sha: str,
    context: RequestContext = Depends(
        require_roles("org_admin", "security_lead", "security_analyst", "auditor")
    ),
):
    """Fetch and persist the bounded check-run snapshot for an onboarded commit."""
    if not context.organization_id:
        raise HTTPException(status_code=400, detail="Select an organization")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
        raise HTTPException(status_code=422, detail="Invalid commit SHA")
    database = Database(database_path(), initialize=False)
    repositories = database.execute(
        """SELECT full_name, installation_id FROM github_repositories
           WHERE github_repository_id = ? AND organization_id = ? AND enabled = 1""",
        (github_repository_id, context.organization_id),
    )
    if not repositories:
        raise HTTPException(status_code=404, detail="GitHub repository not found")
    try:
        client = GitHubAppClient()
    except IntegrationError as exc:
        raise HTTPException(status_code=503, detail="GitHub App is not configured") from exc
    installation_id = repositories[0]["installation_id"]
    if not client.configured or client.installation_id != installation_id:
        raise HTTPException(status_code=503, detail="GitHub installation is unavailable")
    owner, separator, repository = repositories[0]["full_name"].partition("/")
    if not separator or not owner or not repository:
        raise HTTPException(status_code=409, detail="GitHub repository mapping is invalid")
    try:
        response = GitHubAdapter(client=client).check_runs(owner, repository, sha)
    except IntegrationError as exc:
        raise HTTPException(status_code=503, detail="GitHub check runs are unavailable") from exc
    raw_runs = response.get("check_runs") if isinstance(response, dict) else None
    total_count = response.get("total_count") if isinstance(response, dict) else None
    if (
        not isinstance(raw_runs, list)
        or len(raw_runs) > 100
        or not isinstance(total_count, int)
        or isinstance(total_count, bool)
        or total_count != len(raw_runs)
    ):
        raise HTTPException(status_code=502, detail="GitHub returned invalid check-run data")

    now = datetime.now(UTC).isoformat()
    persisted = []
    for run in raw_runs:
        if not isinstance(run, dict):
            raise HTTPException(status_code=502, detail="GitHub returned invalid check-run data")
        run_id = run.get("id")
        head_sha = run.get("head_sha")
        name = run.get("name")
        status = run.get("status")
        conclusion = run.get("conclusion")
        if (
            not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1
            or not isinstance(head_sha, str) or head_sha.casefold() != sha.casefold()
            or not isinstance(name, str) or not name or len(name) > 255
            or not isinstance(status, str)
            or status not in {"queued", "in_progress", "completed"}
            or (
                conclusion is not None
                and (not isinstance(conclusion, str) or len(conclusion) > 64)
            )
        ):
            raise HTTPException(status_code=502, detail="GitHub returned invalid check-run data")
        details_url = run.get("html_url")
        try:
            parsed_url = urlsplit(details_url) if isinstance(details_url, str) else None
        except ValueError:
            parsed_url = None
        allowed_hosts = {urlsplit(client.api_base).hostname, "github.com"}
        if (
            parsed_url is None or parsed_url.scheme != "https"
            or not parsed_url.hostname or parsed_url.username or parsed_url.password
            or parsed_url.query or parsed_url.fragment or len(details_url) > 2048
            or (
                parsed_url.hostname.casefold() not in allowed_hosts
                and not parsed_url.hostname.casefold().endswith(".github.com")
            )
        ):
            details_url = None
        started_at = run.get("started_at")
        completed_at = run.get("completed_at")
        started_at = started_at if isinstance(started_at, str) and len(started_at) <= 64 else None
        completed_at = (
            completed_at if isinstance(completed_at, str) and len(completed_at) <= 64 else None
        )
        persisted.append(
            (
                run_id,
                head_sha.lower(),
                name,
                status,
                conclusion,
                details_url,
                started_at,
                completed_at,
                now,
            )
        )

    with database.transaction() as connection:
        connection.execute(
            "DELETE FROM github_check_runs WHERE github_repository_id = ? AND head_sha = ?",
            (github_repository_id, sha.lower()),
        )
        connection.executemany(
            """INSERT INTO github_check_runs
               (github_repository_id, check_run_id, head_sha, name, status, conclusion,
                details_url, started_at, completed_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(github_repository_id, check_run_id) DO UPDATE SET
                 head_sha = excluded.head_sha, name = excluded.name,
                 status = excluded.status, conclusion = excluded.conclusion,
                 details_url = excluded.details_url, started_at = excluded.started_at,
                 completed_at = excluded.completed_at, updated_at = excluded.updated_at""",
            [(github_repository_id, *run) for run in persisted],
        )
        database.audit_in_transaction(
            connection,
            "github.check_runs_synchronized",
            {"github_repository_id": github_repository_id, "commit_sha": sha.lower(),
             "count": len(persisted), "actor_id": context.user["id"]},
        )
        rows = connection.execute(
            """SELECT check_run_id, head_sha, name, status, conclusion, details_url,
                      started_at, completed_at, updated_at
               FROM github_check_runs
               WHERE github_repository_id = ? AND head_sha = ?
               ORDER BY name, check_run_id LIMIT 100""",
            (github_repository_id, sha.lower()),
        ).fetchall()
    return {"check_runs": [dict(row) for row in rows]}


@router.post("/webhook")
async def receive_webhook(request: Request):
    secret_file = os.getenv("GITHUB_WEBHOOK_SECRET_FILE")
    if secret_file:
        try:
            secret = read_secret_file(
                secret_file, label="GitHub webhook", allow_empty=True
            )
        except SecretFileError:
            secret = None
    else:
        secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=503, detail="GitHub webhook is not configured")
    delivery_id = request.headers.get("X-GitHub-Delivery", "")
    event = request.headers.get("X-GitHub-Event", "")
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not delivery_id or len(delivery_id) > 128 or not event or len(event) > 80:
        raise HTTPException(status_code=400, detail="Invalid webhook headers")

    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > MAX_WEBHOOK_BYTES:
            raise HTTPException(status_code=413, detail="Webhook payload is too large")
    payload = bytes(chunks)
    if not verify_webhook_signature(payload, signature, secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="Invalid webhook JSON") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="Webhook JSON must be an object")

    db = Database(database_path(), initialize=False)
    digest = hashlib.sha256(payload).hexdigest()
    metadata = summarize_webhook(event, parsed)
    if metadata["repository_id"] is None:
        return {"accepted": True, "ignored": True}
    mapping = db.execute(
        """SELECT organization_id, installation_id FROM github_repositories
           WHERE github_repository_id = ? AND enabled = 1""",
        (metadata["repository_id"],),
    )
    if (
        not mapping
        or metadata["installation_id"] is None
        or mapping[0]["installation_id"] != metadata["installation_id"]
    ):
        return {"accepted": True, "ignored": True}
    organization_id = mapping[0]["organization_id"]
    received_at = datetime.now(UTC)
    cutoff = (received_at - timedelta(days=WEBHOOK_DELIVERY_RETENTION_DAYS)).isoformat()
    delivery_conflict = False
    with db.transaction() as connection:
        connection.execute(
            "DELETE FROM webhook_deliveries WHERE received_at < ?",
            (cutoff,),
        )
        cursor = connection.execute(
            """INSERT INTO webhook_deliveries
               (delivery_id, event, body_sha256, received_at)
               VALUES (?, ?, ?, ?) ON CONFLICT(delivery_id) DO NOTHING""",
            (delivery_id, event, digest, received_at.isoformat()),
        )
        if cursor.rowcount == 1:
            connection.execute(
                """INSERT INTO github_events
                   (delivery_id, event, repository, action, ref, base_ref,
                    commit_sha, pull_request_number, pull_request_state,
                    merged, actor, received_at, organization_id, github_repository_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    delivery_id,
                    event,
                    metadata["repository"],
                    metadata["action"],
                    metadata["ref"],
                    metadata["base_ref"],
                    metadata["commit_sha"],
                    metadata["pull_request_number"],
                    metadata["pull_request_state"],
                    metadata["merged"],
                    metadata["actor"],
                    received_at.isoformat(),
                    organization_id,
                    metadata["repository_id"],
                ),
            )
            db.audit_in_transaction(
                connection,
                "github.webhook_received",
                {
                    "delivery_id": delivery_id,
                    "event": event,
                    "body_sha256": digest,
                    "organization_id": organization_id,
                    "github_repository_id": metadata["repository_id"],
                    "repository": metadata["repository"],
                    "actor": metadata["actor"],
                    "action": metadata["action"],
                    "commit_sha": metadata["commit_sha"],
                    "pull_request_number": metadata["pull_request_number"],
                },
            )
        else:
            existing = connection.execute(
                "SELECT event, body_sha256 FROM webhook_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            delivery_conflict = (
                existing is not None
                and (
                    existing["event"] != event
                    or not hmac.compare_digest(existing["body_sha256"], digest)
                )
            )
            if delivery_conflict:
                db.audit_in_transaction(
                    connection,
                    "github.webhook_delivery_conflict",
                    {
                        "delivery_id": delivery_id,
                        "organization_id": organization_id,
                        "github_repository_id": metadata["repository_id"],
                        "stored_event": existing["event"],
                        "received_event": event,
                        "stored_body_sha256": existing["body_sha256"],
                        "received_body_sha256": digest,
                    },
                )
    if delivery_conflict:
        raise HTTPException(status_code=409, detail="Webhook delivery ID was reused")
    return {"accepted": True, "duplicate": cursor.rowcount == 0}


def summarize_webhook(event: str, payload: dict) -> dict:
    """Extract a small allowlisted event summary; discard the source payload."""
    repository = payload.get("repository")
    repository_name = repository.get("full_name") if isinstance(repository, dict) else None
    repository_id = repository.get("id") if isinstance(repository, dict) else None
    installation = payload.get("installation")
    installation_id = installation.get("id") if isinstance(installation, dict) else None
    sender = payload.get("sender")
    actor = sender.get("login") if isinstance(sender, dict) else None
    action = payload.get("action")
    ref = payload.get("ref")
    base_ref = None
    commit_sha = payload.get("after")
    pr_number = None
    pr_state = None
    merged = None

    if event == "pull_request":
        pull_request = payload.get("pull_request")
        if isinstance(pull_request, dict):
            base = pull_request.get("base")
            head = pull_request.get("head")
            base_ref = base.get("ref") if isinstance(base, dict) else None
            if isinstance(head, dict):
                ref = head.get("ref")
                commit_sha = head.get("sha")
            number = pull_request.get("number") or payload.get("number")
            pr_number = (
                number
                if isinstance(number, int)
                and not isinstance(number, bool)
                and number > 0
                else None
            )
            state = pull_request.get("state")
            pr_state = state if isinstance(state, str) and state in {"open", "closed"} else None
            merged_value = pull_request.get("merged")
            merged = int(merged_value) if isinstance(merged_value, bool) else None
    elif event in {"check_run", "check_suite"}:
        check = payload.get("check_run") or payload.get("check_suite")
        if isinstance(check, dict):
            commit_sha = check.get("head_sha")

    return {
        "repository": _bounded(repository_name, 250),
        "repository_id": (
            repository_id
            if isinstance(repository_id, int)
            and not isinstance(repository_id, bool)
            and repository_id > 0
            else None
        ),
        "installation_id": (
            str(installation_id)
            if isinstance(installation_id, (int, str))
            and not isinstance(installation_id, bool)
            and str(installation_id).isdigit()
            else None
        ),
        "action": _bounded(action, 80),
        "ref": _bounded(ref, 500),
        "base_ref": _bounded(base_ref, 500),
        "commit_sha": commit_sha if isinstance(commit_sha, str) and re.fullmatch(
            r"[0-9a-fA-F]{40}", commit_sha
        ) else None,
        "pull_request_number": pr_number,
        "pull_request_state": pr_state,
        "merged": merged,
        "actor": _bounded(actor, 100),
    }


def _bounded(value, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) else None
