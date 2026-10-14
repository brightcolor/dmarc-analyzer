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


def get_current_org_admin(
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> User:
    """Operator or administrator of the current organisation; everyone else gets 403."""
    from app.services.auth import get_user_role_in_org
    if user.is_superadmin or get_user_role_in_org(db, user.id, org.id) == "org_admin":
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Das dürfen nur Administratoren dieser Organisation. Bitte einen Administrator, es für dich zu "
               "erledigen oder dir die Rolle zu geben.",
    )


def require_role(minimum: str):
    """Dependency: the current user needs at least this role in the current organisation."""
    def dependency(
        user: User = Depends(get_current_user),
        org: Organization = Depends(get_current_org),
        db: Session = Depends(get_db),
    ) -> User:
        from app.services.auth import ROLE_LEVEL, ROLE_NAMES, role_level
        if role_level(db, user, org.id) >= ROLE_LEVEL[minimum]:
            return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Dafür brauchst du in dieser Organisation mindestens die Rolle {ROLE_NAMES[minimum]}. Bitte "
                   "einen Administrator, dir die Rolle zu geben oder es für dich zu erledigen.",
        )
    return dependency


get_current_analyst = require_role("analyst")
get_current_manager = require_role("manager")


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


def _is_trusted_proxy(address: str) -> bool:
    import ipaddress

    from app.config import settings
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in settings.trusted_proxy_networks)


def get_client_ip(request: Request) -> str:
    """
    Address of the client. X-Forwarded-For counts only when the connection comes from a trusted proxy
    (TRUSTED_PROXIES); the chain is read from the right, the first address that is no proxy is the client.
    """
    peer = request.client.host if request.client else None
    forwarded = request.headers.get("X-Forwarded-For", "")
    if peer and forwarded and _is_trusted_proxy(peer):
        chain = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
        for ip in reversed(chain):
            if not _is_trusted_proxy(ip):
                return ip
        if chain:
            return chain[0]
    return peer or "unbekannt"
