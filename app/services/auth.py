"""Authentication service."""
import logging

from sqlalchemy.orm import Session

from app.models import ApiToken, Organization, OrganizationMembership, User
from app.security import (
    generate_api_token,
    hash_api_token,
    hash_password,
    utcnow,
    verify_password,
)

logger = logging.getLogger(__name__)

ROLES = ["super_admin", "org_admin", "manager", "analyst", "read_only"]
ROLE_HIERARCHY = {r: i for i, r in enumerate(ROLES)}


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    user = db.query(User).filter_by(email=email.lower().strip()).first()
    if not user:
        return None
    if not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.last_login_at = utcnow()
    return user


def get_user_by_id(db: Session, user_id: str) -> User | None:
    return db.query(User).filter_by(id=user_id, is_active=True).first()


def create_user(
    db: Session,
    email: str,
    password: str,
    full_name: str | None = None,
    is_superadmin: bool = False,
) -> User:
    user = User(
        email=email.lower().strip(),
        password_hash=hash_password(password),
        full_name=full_name,
        is_superadmin=is_superadmin,
        email_verified=True,  # Admin-created users skip verification
    )
    db.add(user)
    db.flush()
    return user


def get_user_role_in_org(db: Session, user_id: str, org_id: str) -> str | None:
    membership = (
        db.query(OrganizationMembership)
        .filter_by(user_id=user_id, organization_id=org_id, is_active=True)
        .first()
    )
    return membership.role if membership else None


def can_access_org(db: Session, user: User, org_id: str) -> bool:
    if user.is_superadmin:
        return True
    return get_user_role_in_org(db, user.id, org_id) is not None


def require_role(user_role: str | None, minimum_role: str) -> bool:
    """Check that user_role meets minimum_role threshold."""
    if user_role is None:
        return False
    return ROLE_HIERARCHY.get(user_role, 999) <= ROLE_HIERARCHY.get(minimum_role, 999)


def get_user_orgs(db: Session, user_id: str) -> list[Organization]:
    memberships = (
        db.query(OrganizationMembership)
        .filter_by(user_id=user_id, is_active=True)
        .all()
    )
    org_ids = [m.organization_id for m in memberships]
    if not org_ids:
        return []
    return db.query(Organization).filter(Organization.id.in_(org_ids), Organization.is_active.is_(True)).all()


def validate_api_token(db: Session, raw_token: str) -> tuple[ApiToken, Organization] | None:
    """Validate a raw API token. Returns (token_obj, organization) or None."""
    if not raw_token or not raw_token.startswith("dmarc_"):
        return None
    token_hash = hash_api_token(raw_token)
    token = db.query(ApiToken).filter_by(token_hash=token_hash, is_active=True).first()
    if not token or not token.is_valid:
        return None
    org = db.query(Organization).filter_by(id=token.organization_id, is_active=True).first()
    if not org:
        return None
    token.last_used_at = utcnow()
    return token, org


def create_api_token(
    db: Session,
    organization_id: str,
    user_id: str,
    name: str,
    scopes: list[str] | None = None,
) -> tuple[str, ApiToken]:
    """Create a new API token. Returns (raw_token, ApiToken)."""
    import json
    raw, hashed = generate_api_token()
    token = ApiToken(
        organization_id=organization_id,
        user_id=user_id,
        name=name,
        token_hash=hashed,
        token_prefix=raw[:14],
        scopes=json.dumps(scopes or []),
        is_active=True,
    )
    db.add(token)
    db.flush()
    return raw, token
