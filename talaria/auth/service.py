"""Account, organization, and credential workflows."""

from datetime import UTC, datetime
from uuid import uuid4

from talaria.auth.passwords import (
    hash_password,
    password_needs_rehash,
    verify_password,
)
from talaria.auth.session_store import RefreshSessionStore, RefreshTokenReuseError
from talaria.auth.tokens import create_access_token, decode_access_token
from talaria.database import Database

_DUMMY_PASSWORD_HASH = hash_password("not-a-real-user-password")


class AuthenticationError(ValueError):
    """Raised when credentials or session state are invalid."""


class AuthService:
    def __init__(self, database: Database):
        self.database = database
        self.sessions = RefreshSessionStore(database)

    def bootstrap(
        self,
        email: str,
        password: str,
        organization_name: str,
    ) -> dict:
        email = _normalize_email(email)
        organization_name = _required(organization_name, "Organization name")
        _validate_new_password(password)
        encoded = hash_password(password)
        user_id = str(uuid4())
        organization_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            if self.database.is_postgres:
                connection.execute("SELECT pg_advisory_xact_lock(1145131089)")
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM users"
            ).fetchone()["count"]
            if count:
                raise AuthenticationError("Platform bootstrap is already complete.")
            connection.execute(
                """INSERT INTO users
                   (id, email, password_hash, created_at, is_platform_admin)
                   VALUES (?, ?, ?, ?, 1)""",
                (user_id, email, encoded, now),
            )
            connection.execute(
                "INSERT INTO organizations(id, name, created_at) VALUES (?, ?, ?)",
                (organization_id, organization_name, now),
            )
            connection.execute(
                """INSERT INTO organization_memberships
                   (user_id, organization_id, role, created_at)
                   VALUES (?, ?, 'org_admin', ?)""",
                (user_id, organization_id, now),
            )
            # Existing local-MVP data has no tenant owner. Assign it once to
            # the first explicitly bootstrapped administrator's organization.
            connection.execute(
                "UPDATE repositories SET organization_id = ? "
                "WHERE organization_id IS NULL",
                (organization_id,),
            )
        self.database.audit(
            "auth.platform_bootstrapped",
            {"user_id": user_id, "organization_id": organization_id},
        )
        return {"user_id": user_id, "organization_id": organization_id}

    def register_member(
        self,
        email: str,
        password: str,
        organization_id: str,
        role: str,
    ) -> dict:
        email = _normalize_email(email)
        organization_id = _required(organization_id, "Organization ID")
        _validate_new_password(password)
        allowed = {"security_lead", "security_analyst", "developer", "auditor"}
        if role not in allowed:
            raise AuthenticationError("Requested membership role is not assignable.")
        user_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        encoded = hash_password(password)
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    "INSERT INTO users(id, email, password_hash, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (user_id, email, encoded, now),
                )
                connection.execute(
                    """INSERT INTO organization_memberships
                       (user_id, organization_id, role, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (user_id, organization_id, role, now),
                )
        except Exception as exc:
            if (
                "UNIQUE constraint failed: users.email" in str(exc)
                or getattr(exc, "sqlstate", None) == "23505"
            ):
                raise AuthenticationError("Unable to create account.") from exc
            raise
        self.database.audit(
            "auth.user_registered",
            {"user_id": user_id, "organization_id": organization_id, "role": role},
        )
        return {"user_id": user_id, "email": email, "role": role}

    def create_organization(self, name: str, admin_email: str) -> dict:
        name = _required(name, "Organization name")
        email = _normalize_email(admin_email)
        organizations = self.database.execute(
            "SELECT id FROM users WHERE email = ? AND is_active = 1", (email,)
        )
        if not organizations:
            raise AuthenticationError("An active user is required as organization admin.")
        user_id = organizations[0]["id"]
        organization_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO organizations(id, name, created_at) VALUES (?, ?, ?)",
                (organization_id, name, now),
            )
            connection.execute(
                """INSERT INTO organization_memberships
                   (user_id, organization_id, role, created_at)
                   VALUES (?, ?, 'org_admin', ?)""",
                (user_id, organization_id, now),
            )
        self.database.audit(
            "auth.organization_created",
            {"organization_id": organization_id, "admin_user_id": user_id},
        )
        return {"organization_id": organization_id, "admin_user_id": user_id}

    def login(self, email: str, password: str) -> dict:
        try:
            password_bytes = (
                len(password.encode("utf-8")) if isinstance(password, str) else 0
            )
        except UnicodeEncodeError:
            password_bytes = 0
        if not password_bytes or password_bytes > 1024:
            try:
                normalized = _normalize_email(email)
            except ValueError:
                normalized = "invalid"
            self.database.audit("auth.login_failed", {"email": normalized})
            raise AuthenticationError("Invalid email or password.")
        try:
            normalized = _normalize_email(email)
        except ValueError:
            normalized = "invalid"
        rows = self.database.execute(
            "SELECT id, email, password_hash, is_active FROM users WHERE email = ?",
            (normalized,),
        )
        user = rows[0] if rows else None
        password_hash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
        valid = verify_password(password, password_hash)
        if user is None or not valid or not user["is_active"]:
            self.database.audit("auth.login_failed", {"email": normalized})
            raise AuthenticationError("Invalid email or password.")
        if password_needs_rehash(password_hash):
            upgraded_hash = hash_password(password)
            with self.database.transaction() as connection:
                cursor = connection.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
                    (upgraded_hash, user["id"], password_hash),
                )
                if cursor.rowcount == 1:
                    self.database.audit_in_transaction(
                        connection,
                        "auth.password_hash_upgraded",
                        {"user_id": user["id"]},
                    )
        self.database.audit("auth.login_succeeded", {"user_id": user["id"]})
        return self._issue(user["id"])

    def refresh(self, token: str) -> dict:
        subject = self.sessions.get_subject(token)
        if subject is not None:
            active_user = self.database.execute(
                "SELECT 1 AS active FROM users WHERE id = ? AND is_active = 1",
                (subject,),
            )
            if not active_user:
                self.sessions.revoke_subject(subject)
                raise AuthenticationError("Refresh session is no longer valid.")
        try:
            rotated = self.sessions.rotate(token)
        except RefreshTokenReuseError:
            self.database.audit("auth.refresh_reuse_detected", {})
            raise AuthenticationError("Refresh session is no longer valid.") from None
        if rotated is None:
            raise AuthenticationError("Refresh session is no longer valid.")
        refresh_token, session = rotated
        self.database.audit(
            "auth.refresh_rotated", {"user_id": session.subject, "session_id": session.id}
        )
        return {
            "access_token": create_access_token(session.subject),
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    def logout(self, token: str) -> bool:
        return self.sessions.revoke(token)

    def principal(self, access_token: str) -> dict:
        claims = decode_access_token(access_token)
        rows = self.database.execute(
            "SELECT id, email, is_active, is_platform_admin FROM users WHERE id = ?",
            (claims["sub"],),
        )
        if not rows or not rows[0]["is_active"]:
            raise AuthenticationError("Invalid or inactive account.")
        user = rows[0]
        return {
            "id": user["id"],
            "email": user["email"],
            "is_platform_admin": bool(user["is_platform_admin"]),
        }

    def memberships(self, user_id: str) -> list[dict]:
        return self.database.execute(
            """SELECT m.organization_id, o.name AS organization, m.role
               FROM organization_memberships AS m
               JOIN organizations AS o ON o.id = m.organization_id
               WHERE m.user_id = ? AND o.is_active = 1
               ORDER BY o.name""",
            (user_id,),
        )

    def organization_exists(self, organization_id: str) -> bool:
        return bool(
            self.database.execute(
                "SELECT 1 AS found FROM organizations WHERE id = ? AND is_active = 1",
                (organization_id,),
            )
        )

    def record_authorization_denial(
        self,
        user_id: str,
        organization_id: str | None,
        reason: str,
    ) -> None:
        self.database.audit(
            "auth.authorization_denied",
            {
                "user_id": user_id,
                "organization_id": organization_id,
                "reason": reason,
            },
        )

    def _issue(self, user_id: str) -> dict:
        refresh, _ = self.sessions.create(user_id)
        return {
            "access_token": create_access_token(user_id),
            "refresh_token": refresh,
            "token_type": "bearer",
        }


def _normalize_email(email: str) -> str:
    if not isinstance(email, str):
        raise ValueError("Email address is required.")
    value = email.strip().casefold()
    if len(value) > 254 or value.count("@") != 1 or any(c.isspace() for c in value):
        raise ValueError("A valid email address is required.")
    local, domain = value.split("@")
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("A valid email address is required.")
    return value


def _required(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required.")
    return value.strip()


def _validate_new_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < 12:
        raise AuthenticationError("Password must contain at least 12 characters.")
    if len(password.encode("utf-8")) > 1024:
        raise AuthenticationError("Password exceeds the supported size limit.")
