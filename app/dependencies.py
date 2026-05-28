"""
FastAPI dependency functions for auth, tenant context, and DB sessions.
"""

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Organization, User
from app.services.auth import get_user_by_id, validate_api_token

# ─── Session-based auth ────────────────────────────────────────────────────────

def get_current_user_optional(
    request: Request, db: Session = Depends(get_db)
) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return get_user_by_id(db, user_id)


def get_current_user(
    request: Request, db: Session = Depends(get_db)
) -> User:
    user = get_current_user_optional(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/auth/login"},
        )
    return user


def get_current_superadmin(user: User = Depends(get_current_user)) -> User:
    if not user.is_superadmin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Super admin required")
    return user


# ─── Tenant context ────────────────────────────────────────────────────────────

def get_current_org(request: Request, db: Session = Depends(get_db)) -> Organization:
    org_id = request.session.get("org_id")
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/organizations/select"},
        )
    org = db.query(Organization).filter_by(id=org_id, is_active=True).first()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org


def get_current_user_and_org(
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
) -> tuple[User, Organization]:
    return user, org


# ─── API token auth ────────────────────────────────────────────────────────────

def get_api_auth(
    request: Request, db: Session = Depends(get_db)
) -> tuple[User | None, Organization | None]:
    """Validate Bearer API token for REST API endpoints."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raw_token = auth_header.removeprefix("Bearer ").strip()
    result = validate_api_token(db, raw_token)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token, org = result
    user = get_user_by_id(db, token.user_id) if token.user_id else None
    return user, org


# ─── Helper for redirect responses ─────────────────────────────────────────────

def redirect(url: str):
    from starlette.responses import RedirectResponse
    return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)


def get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting trusted proxy headers."""
    from app.config import settings
    trusted = {p.strip() for p in settings.TRUSTED_PROXIES.split(",") if p.strip()}
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        ips = [ip.strip() for ip in forwarded_for.split(",")]
        # Trust the leftmost non-trusted IP
        for ip in ips:
            if ip not in trusted:
                return ip
    return request.client.host if request.client else "unknown"
