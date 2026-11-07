"""Database-backed refresh-session storage."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from talaria.auth.sessions import (
    REFRESH_TOKEN_LIFETIME,
    generate_refresh_token,
    hash_refresh_token,
)
from talaria.database import Database


@dataclass(frozen=True, slots=True)
class RefreshSession:
    id: str
    family_id: str
    subject: str
    created_at: str
    expires_at: str
    revoked_at: str | None


class RefreshTokenReuseError(ValueError):
    """Raised when a rotated refresh token is presented again."""


class RefreshSessionStore:
    """Persist only hashes of refresh tokens and support revocation."""

    def __init__(self, database: Database):
        self.database = database

    def create(
        self,
        subject: str,
        lifetime: timedelta = REFRESH_TOKEN_LIFETIME,
    ) -> tuple[str, RefreshSession]:
        if not isinstance(subject, str) or not subject.strip():
            raise ValueError("Session subject cannot be empty.")
        expires = _expiry(lifetime)
        now = datetime.now(UTC).isoformat()
        session_id = str(uuid4())
        token = generate_refresh_token()
        token_hash = hash_refresh_token(token)

        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO refresh_sessions
                    (id, family_id, subject, token_hash, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, session_id, subject.strip(), token_hash, now, expires.isoformat()),
            )
        return token, RefreshSession(
            id=session_id,
            family_id=session_id,
            subject=subject.strip(),
            created_at=now,
            expires_at=expires.isoformat(),
            revoked_at=None,
        )

    def get_active(self, token: str) -> RefreshSession | None:
        token_hash = hash_refresh_token(token)
        now = datetime.now(UTC).isoformat()
        rows = self.database.execute(
            """
            SELECT id, family_id, subject, created_at, expires_at, revoked_at
            FROM refresh_sessions
            WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
            """,
            (token_hash, now),
        )
        return _to_session(rows[0]) if rows else None

    def get_subject(self, token: str) -> str | None:
        """Find the owner even after revocation so reuse can be detected."""
        token_hash = hash_refresh_token(token)
        rows = self.database.execute(
            "SELECT subject FROM refresh_sessions WHERE token_hash = ?",
            (token_hash,),
        )
        return rows[0]["subject"] if rows else None

    def rotate(
        self,
        token: str,
        lifetime: timedelta = REFRESH_TOKEN_LIFETIME,
    ) -> tuple[str, RefreshSession] | None:
        """Atomically replace an active token; revoke its family on reuse."""
        token_hash = hash_refresh_token(token)
        now = datetime.now(UTC)
        now_text = now.isoformat()
        reused = False
        result = None

        with self.database.transaction() as connection:
            if self.database.is_postgres:
                row = connection.execute(
                    """SELECT id, family_id, subject, expires_at, revoked_at,
                              replaced_by_id
                       FROM refresh_sessions
                       WHERE token_hash = ?
                       FOR UPDATE""",
                    (token_hash,),
                ).fetchone()
            else:
                row = connection.execute(
                    """SELECT id, family_id, subject, expires_at, revoked_at,
                              replaced_by_id
                       FROM refresh_sessions
                       WHERE token_hash = ?""",
                    (token_hash,),
                ).fetchone()

            if row is None or row["expires_at"] <= now_text:
                return None

            if row["revoked_at"] is not None:
                if row["replaced_by_id"] is not None:
                    connection.execute(
                        """
                        UPDATE refresh_sessions
                        SET revoked_at = COALESCE(revoked_at, ?),
                            compromised_at = COALESCE(compromised_at, ?)
                        WHERE family_id = ?
                        """,
                        (now_text, now_text, row["family_id"]),
                    )
                    reused = True
            else:
                expires = _expiry(lifetime, now)
                session_id = str(uuid4())
                replacement = generate_refresh_token()
                connection.execute(
                    """
                    INSERT INTO refresh_sessions
                        (id, family_id, subject, token_hash, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        row["family_id"],
                        row["subject"],
                        hash_refresh_token(replacement),
                        now_text,
                        expires.isoformat(),
                    ),
                )
                update = connection.execute(
                    """
                    UPDATE refresh_sessions
                    SET revoked_at = ?, replaced_by_id = ?
                    WHERE id = ? AND revoked_at IS NULL
                    """,
                    (now_text, session_id, row["id"]),
                )
                if update.rowcount != 1:
                    raise RuntimeError("Refresh session changed during rotation")
                result = (
                    replacement,
                    RefreshSession(
                        id=session_id,
                        family_id=row["family_id"],
                        subject=row["subject"],
                        created_at=now_text,
                        expires_at=expires.isoformat(),
                        revoked_at=None,
                    ),
                )

        if reused:
            raise RefreshTokenReuseError(
                "A previously rotated refresh token was reused; the session family was revoked."
            )
        return result

    def revoke(self, token: str) -> bool:
        token_hash = hash_refresh_token(token)
        revoked_at = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE refresh_sessions
                SET revoked_at = ?
                WHERE token_hash = ? AND revoked_at IS NULL
                """,
                (revoked_at, token_hash),
            )
            return cursor.rowcount == 1

    def revoke_subject(self, subject: str) -> int:
        if not isinstance(subject, str) or not subject.strip():
            raise ValueError("Session subject cannot be empty.")
        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE refresh_sessions
                SET revoked_at = ?
                WHERE subject = ? AND revoked_at IS NULL
                """,
                (datetime.now(UTC).isoformat(), subject.strip()),
            )
            return cursor.rowcount


def _expiry(lifetime: timedelta, now: datetime | None = None) -> datetime:
    if not isinstance(lifetime, timedelta) or lifetime.total_seconds() <= 0:
        raise ValueError("Refresh-token lifetime must be positive.")
    return (now or datetime.now(UTC)) + lifetime


def _to_session(row: dict) -> RefreshSession:
    return RefreshSession(
        id=row["id"],
        family_id=row["family_id"],
        subject=row["subject"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        revoked_at=row["revoked_at"],
    )
