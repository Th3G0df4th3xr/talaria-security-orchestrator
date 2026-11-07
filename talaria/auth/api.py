"""Authentication endpoints and request authorization dependencies."""

import hmac
import os
from dataclasses import dataclass
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from talaria.auth.approvals import ApprovalError, ApprovalRegistry
from talaria.auth.service import AuthenticationError, AuthService
from talaria.auth.tokens import TokenError
from talaria.config import database_path
from talaria.database import Database
from talaria.security.secrets import SecretFileError, read_secret_file

router = APIRouter(prefix="/auth", tags=["authentication"])
bearer_scheme = HTTPBearer(auto_error=False)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BootstrapInput(StrictModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=1024)
    organization_name: str = Field(min_length=1, max_length=200)


class LoginInput(StrictModel):
    email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class RefreshInput(StrictModel):
    refresh_token: str = Field(min_length=1, max_length=256)


class RegisterInput(StrictModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=1024)
    role: str


class OrganizationInput(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    admin_email: str = Field(min_length=5, max_length=254)


class ApprovalInput(StrictModel):
    action: Literal["github.create_branch", "github.create_pull_request"]
    resource: str = Field(min_length=1, max_length=300)


class ApprovalDecisionInput(StrictModel):
    approved: bool


@dataclass(frozen=True, slots=True)
class RequestContext:
    user: dict
    organization_id: str | None
    role: str | None


def _service() -> AuthService:
    return AuthService(Database(database_path(), initialize=False))


def _bootstrap_secret() -> str | None:
    secret_file = os.getenv("TALARIA_BOOTSTRAP_TOKEN_FILE")
    if secret_file:
        try:
            return read_secret_file(
                secret_file, label="bootstrap", allow_empty=True
            ) or None
        except SecretFileError:
            return None
    return os.getenv("TALARIA_BOOTSTRAP_TOKEN")


@router.post("/bootstrap", status_code=status.HTTP_201_CREATED)
def bootstrap(
    payload: BootstrapInput,
    bootstrap_token: str | None = Header(default=None, alias="X-Talaria-Bootstrap-Token"),
):
    expected = _bootstrap_secret()
    if not expected or not bootstrap_token or not hmac.compare_digest(bootstrap_token, expected):
        raise HTTPException(status_code=403, detail="Bootstrap is not authorized")
    try:
        created = _service().bootstrap(
            payload.email, payload.password, payload.organization_name
        )
    except (AuthenticationError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return created


@router.post("/login")
def login(payload: LoginInput):
    try:
        return _service().login(payload.email, payload.password)
    except (AuthenticationError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid email or password") from exc
    except TokenError as exc:
        raise HTTPException(status_code=503, detail="Authentication is not configured") from exc


@router.post("/refresh")
def refresh(payload: RefreshInput):
    try:
        return _service().refresh(payload.refresh_token)
    except (AuthenticationError, TokenError) as exc:
        raise HTTPException(status_code=401, detail="Refresh session is not valid") from exc


def current_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    organization_header: str | None = Header(default=None, alias="X-Organization-ID"),
) -> RequestContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Bearer access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    service = _service()
    try:
        user = service.principal(credentials.credentials)
    except (AuthenticationError, TokenError) as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    memberships = service.memberships(user["id"])
    if organization_header:
        membership = next(
            (item for item in memberships if item["organization_id"] == organization_header),
            None,
        )
        if membership is None:
            if not user["is_platform_admin"]:
                service.record_authorization_denial(
                    user["id"], organization_header, "organization_membership_required"
                )
                raise HTTPException(status_code=403, detail="Organization access denied")
            if not service.organization_exists(organization_header):
                raise HTTPException(status_code=404, detail="Organization not found")
    elif len(memberships) == 1:
        membership = memberships[0]
    elif len(memberships) > 1:
        membership = None
    else:
        membership = None

    if membership is None:
        return RequestContext(user, organization_header, None)
    return RequestContext(user, membership["organization_id"], membership["role"])


def require_roles(*roles: str):
    def dependency(context: RequestContext = Depends(current_context)) -> RequestContext:
        if context.user["is_platform_admin"] or context.role in roles:
            return context
        _service().record_authorization_denial(
            context.user["id"], context.organization_id, "role_required"
        )
        raise HTTPException(status_code=403, detail="Permission denied")

    return dependency


@router.post("/logout")
def logout(
    payload: RefreshInput,
):
    service = _service()
    session = service.sessions.get_active(payload.refresh_token)
    changed = service.logout(payload.refresh_token)
    if changed or session is not None:
        service.database.audit(
            "auth.logout",
            {
                "user_id": session.subject if session else None,
                "revoked": changed,
            },
        )
    return {"revoked": changed}


@router.post("/logout-all")
def logout_all(context: RequestContext = Depends(current_context)):
    service = _service()
    count = service.sessions.revoke_subject(context.user["id"])
    service.database.audit(
        "auth.logout_all", {"user_id": context.user["id"], "sessions_revoked": count}
    )
    return {"sessions_revoked": count}


@router.get("/me")
def me(context: RequestContext = Depends(current_context)):
    service = _service()
    return {
        **context.user,
        "organization_id": context.organization_id,
        "role": context.role,
        "memberships": service.memberships(context.user["id"]),
    }


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register_member(
    payload: RegisterInput,
    context: RequestContext = Depends(require_roles("org_admin")),
):
    if not context.organization_id:
        raise HTTPException(status_code=400, detail="Select an organization")
    try:
        return _service().register_member(
            payload.email,
            payload.password,
            context.organization_id,
            payload.role,
        )
    except (AuthenticationError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/organizations", status_code=status.HTTP_201_CREATED)
def create_organization(
    payload: OrganizationInput,
    context: RequestContext = Depends(current_context),
):
    if not context.user["is_platform_admin"]:
        raise HTTPException(status_code=403, detail="Platform administrator required")
    try:
        return _service().create_organization(payload.name, payload.admin_email)
    except (AuthenticationError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/approvals", status_code=status.HTTP_201_CREATED)
def request_approval(
    payload: ApprovalInput,
    context: RequestContext = Depends(
        require_roles("org_admin", "security_lead", "security_analyst")
    ),
):
    if not context.organization_id:
        raise HTTPException(status_code=400, detail="Select an organization")
    record = ApprovalRegistry(
        Database(database_path(), initialize=False), context.organization_id
    ).request(payload.action, payload.resource, context.user["id"])
    return record


@router.get("/approvals")
def list_approvals(
    limit: int = 100,
    context: RequestContext = Depends(
        require_roles("org_admin", "security_lead", "security_analyst", "auditor")
    ),
):
    if not context.organization_id:
        raise HTTPException(status_code=400, detail="Select an organization")
    try:
        return ApprovalRegistry(
            Database(database_path(), initialize=False), context.organization_id
        ).list(limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/approvals/{approval_id}/decision")
def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionInput,
    context: RequestContext = Depends(require_roles("org_admin", "security_lead")),
):
    if not context.organization_id:
        raise HTTPException(status_code=400, detail="Select an organization")
    try:
        return ApprovalRegistry(
            Database(database_path(), initialize=False), context.organization_id
        ).decide(approval_id, context.user["id"], payload.approved)
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
