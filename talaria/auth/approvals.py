"""Two-person approval records for external repository actions."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from talaria.database import Database

APPROVAL_LIFETIME = timedelta(hours=24)
APPROVABLE_ACTIONS = {"github.create_branch", "github.create_pull_request"}


class ApprovalError(ValueError):
    """Raised when an approval request or decision is invalid."""


class ApprovalRegistry:
    def __init__(self, database: Database, organization_id: str):
        self.database = database
        self.organization_id = organization_id

    def request(self, action: str, resource: str, requested_by: str) -> dict:
        if not isinstance(action, str) or action not in APPROVABLE_ACTIONS:
            raise ApprovalError("Action is not eligible for approval.")
        if not isinstance(resource, str) or not resource.strip() or len(resource) > 300:
            raise ApprovalError("Approval resource is invalid.")
        if not isinstance(requested_by, str) or not requested_by:
            raise ApprovalError("Requester is required.")
        record_id = str(uuid4())
        with self.database.transaction() as connection:
            authorized = connection.execute(
                """SELECT 1 FROM users AS u
                   LEFT JOIN organization_memberships AS m
                     ON m.user_id = u.id AND m.organization_id = ?
                   WHERE u.id = ? AND u.is_active = 1
                     AND (u.is_platform_admin = 1 OR m.role IN (
                         'org_admin', 'security_lead', 'security_analyst'))""",
                (self.organization_id, requested_by),
            ).fetchone()
            if authorized is None:
                raise ApprovalError(
                    "An active organization administrator or security member is required."
                )
            now = datetime.now(UTC)
            record = {
                "id": record_id,
                "organization_id": self.organization_id,
                "action": action,
                "resource": resource.strip(),
                "requested_by": requested_by,
                "decided_by": None,
                "status": "pending",
                "created_at": now.isoformat(),
                "expires_at": (now + APPROVAL_LIFETIME).isoformat(),
                "decided_at": None,
            }
            connection.execute(
                """INSERT INTO approval_records
                   (id, organization_id, action, resource, requested_by, status,
                    created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["id"],
                    record["organization_id"],
                    record["action"],
                    record["resource"],
                    record["requested_by"],
                    record["status"],
                    record["created_at"],
                    record["expires_at"],
                ),
            )
            self.database.audit_in_transaction(
                connection,
                "approval.requested",
                {
                    "approval_id": record["id"],
                    "organization_id": self.organization_id,
                    "action": action,
                    "requested_by": requested_by,
                },
            )
        return record

    def decide(self, approval_id: str, actor_id: str, approved: bool) -> dict:
        if not isinstance(approval_id, str) or not approval_id:
            raise ApprovalError("Approval request ID is invalid.")
        if not isinstance(actor_id, str) or not actor_id:
            raise ApprovalError("Approver is required.")
        if not isinstance(approved, bool):
            raise ApprovalError("Approval decision must be a boolean.")
        expired = False
        result = None
        with self.database.transaction() as connection:
            now = datetime.now(UTC).isoformat()
            row = connection.execute(
                """SELECT * FROM approval_records
                   WHERE id = ? AND organization_id = ?""",
                (approval_id, self.organization_id),
            ).fetchone()
            if row is None:
                raise ApprovalError("Approval request not found.")
            if row["requested_by"] == actor_id:
                raise ApprovalError("The requester cannot approve their own request.")
            if row["status"] != "pending":
                raise ApprovalError("Approval request has already been decided.")
            authorized = connection.execute(
                """SELECT 1 FROM users AS u
                   LEFT JOIN organization_memberships AS m
                     ON m.user_id = u.id AND m.organization_id = ?
                   WHERE u.id = ? AND u.is_active = 1
                     AND (u.is_platform_admin = 1 OR m.role IN (
                         'org_admin', 'security_lead'))""",
                (self.organization_id, actor_id),
            ).fetchone()
            if authorized is None:
                raise ApprovalError(
                    "An active organization administrator or security lead is required."
                )
            if row["expires_at"] <= now:
                connection.execute(
                    "UPDATE approval_records SET status = 'expired' WHERE id = ?",
                    (approval_id,),
                )
                expired = True
            else:
                status = "approved" if approved else "rejected"
                cursor = connection.execute(
                    """UPDATE approval_records
                       SET status = ?, decided_by = ?, decided_at = ?
                       WHERE id = ? AND status = 'pending'""",
                    (status, actor_id, now, approval_id),
                )
                if cursor.rowcount != 1:
                    raise ApprovalError("Approval request changed concurrently.")
                self.database.audit_in_transaction(
                    connection,
                    "approval.decided",
                    {
                        "approval_id": approval_id,
                        "status": status,
                        "decided_by": actor_id,
                    },
                )
                result = {"approval_id": approval_id, "status": status, "decided_at": now}
        if expired:
            raise ApprovalError("Approval request has expired.")
        return result

    def validate(
        self,
        approval_id: str,
        action: str,
        approved_by: str,
        resource: str,
    ) -> bool:
        now = datetime.now(UTC).isoformat()
        rows = self.database.execute(
            """SELECT 1 AS valid FROM approval_records AS a
               JOIN users AS u ON u.id = a.decided_by AND u.is_active = 1
               LEFT JOIN organization_memberships AS m
                 ON m.user_id = u.id AND m.organization_id = a.organization_id
               WHERE a.id = ? AND a.organization_id = ? AND a.action = ?
                 AND a.resource = ? AND a.decided_by = ? AND a.status = 'approved'
                 AND a.expires_at > ?
                 AND a.consumed_at IS NULL
                 AND (u.is_platform_admin = 1 OR m.role IN ('org_admin', 'security_lead'))""",
            (
                approval_id,
                self.organization_id,
                action,
                resource,
                approved_by,
                now,
            ),
        )
        return bool(rows)

    def consume(
        self,
        approval_id: str,
        action: str,
        actor_id: str,
        resource: str,
    ) -> bool:
        """Authorize one exact action; identical retries remain idempotent."""
        with self.database.transaction() as connection:
            now = datetime.now(UTC).isoformat()
            row = connection.execute(
                """SELECT a.consumed_at FROM approval_records AS a
                   JOIN users AS u ON u.id = a.decided_by AND u.is_active = 1
                   LEFT JOIN organization_memberships AS m
                     ON m.user_id = u.id AND m.organization_id = a.organization_id
                   WHERE a.id = ? AND a.organization_id = ? AND a.action = ?
                     AND a.resource = ? AND a.decided_by = ? AND a.status = 'approved'
                     AND a.expires_at > ?
                     AND (u.is_platform_admin = 1 OR m.role IN ('org_admin', 'security_lead'))""",
                (
                    approval_id,
                    self.organization_id,
                    action,
                    resource,
                    actor_id,
                    now,
                ),
            ).fetchone()
            if row is None:
                return False
            if row["consumed_at"] is not None:
                return True
            cursor = connection.execute(
                """UPDATE approval_records SET consumed_at = ?
                   WHERE id = ? AND consumed_at IS NULL AND status = 'approved'""",
                (now, approval_id),
            )
            if cursor.rowcount != 1:
                return False
            self.database.audit_in_transaction(
                connection,
                "approval.consumed",
                {"approval_id": approval_id, "action": action, "actor_id": actor_id},
            )
            return True

    def list(self, limit: int = 100) -> list[dict]:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        return self.database.execute(
            """SELECT id, action, resource, requested_by, decided_by, status,
                      created_at, expires_at, decided_at
               FROM approval_records WHERE organization_id = ?
               ORDER BY created_at DESC LIMIT ?""",
            (self.organization_id, limit),
        )
