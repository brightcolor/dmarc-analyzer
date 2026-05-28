"""Service for managing inbound mail addresses."""
import logging

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Domain, InboundMailAddress, Organization
from app.security import generate_inbound_token

logger = logging.getLogger(__name__)


def _build_address(prefix: str, token: str) -> str:
    return f"{prefix}{token}@{settings.SMTP_INBOUND_DOMAIN}"


def create_org_address(db: Session, org: Organization) -> InboundMailAddress:
    """Create an organisation-level inbound address."""
    token = generate_inbound_token(14)
    slug = org.slug[:12].replace("-", "")[:8]
    address = _build_address(f"org-{slug}-", token)

    addr = InboundMailAddress(
        organization_id=org.id,
        address=address,
        token=f"org-{slug}-{token}",
        status="active",
        purpose="org_report",
    )
    db.add(addr)
    db.flush()
    return addr


def create_domain_address(db: Session, org: Organization, domain: Domain) -> InboundMailAddress:
    """Create a domain-specific inbound address."""
    token = generate_inbound_token(10)
    # Sanitize domain name for use in local part
    safe_domain = domain.name.replace(".", "-").replace("_", "-")[:20]
    address = _build_address(f"dom-{safe_domain}-", token)

    addr = InboundMailAddress(
        organization_id=org.id,
        domain_id=domain.id,
        address=address,
        token=f"dom-{safe_domain}-{token}",
        status="active",
        purpose="domain_report",
    )
    db.add(addr)
    db.flush()
    return addr


def lookup_by_address(db: Session, address: str) -> InboundMailAddress | None:
    """Look up an inbound address by its full email address (case-insensitive)."""
    return db.query(InboundMailAddress).filter_by(address=address.lower()).first()


def disable_address(db: Session, addr: InboundMailAddress) -> None:
    from app.security import utcnow
    addr.status = "disabled"
    addr.disabled_at = utcnow()


def revoke_address(db: Session, addr: InboundMailAddress) -> None:
    from app.security import utcnow
    addr.status = "revoked"
    addr.revoked_at = utcnow()


def rotate_address(
    db: Session, old_addr: InboundMailAddress, keep_old: bool = True
) -> InboundMailAddress:
    """
    Rotate an inbound address by creating a new one and optionally
    disabling (not revoking) the old one so grace-period mail still works.
    """
    from app.security import utcnow
    org = db.query(Organization).get(old_addr.organization_id)
    domain = (
        db.query(Domain).get(old_addr.domain_id) if old_addr.domain_id else None
    )
    if domain:
        new_addr = create_domain_address(db, org, domain)
    else:
        new_addr = create_org_address(db, org)

    if keep_old:
        old_addr.status = "disabled"
        old_addr.disabled_at = utcnow()
    else:
        old_addr.status = "revoked"
        old_addr.revoked_at = utcnow()

    return new_addr


def validate_for_smtp(db: Session, address: str) -> tuple[bool, str, InboundMailAddress | None]:
    """
    Check whether an address can accept mail.
    Returns (accepted, rejection_reason, InboundMailAddress|None).
    """
    addr = lookup_by_address(db, address.lower())

    if addr is None:
        return False, "550 5.1.1 Recipient unknown", None

    if addr.status == "revoked":
        return False, "550 5.1.1 Recipient disabled", None

    if addr.status == "disabled":
        return False, "550 5.1.1 Recipient disabled", None

    if addr.status != "active":
        return False, "550 5.1.1 Recipient disabled", None

    # Check organisation
    org = db.query(Organization).filter_by(id=addr.organization_id).first()
    if not org or not org.is_active:
        return False, "550 5.7.1 Organization disabled", None

    # Check domain if bound
    if addr.domain_id:
        domain = db.query(Domain).filter_by(id=addr.domain_id).first()
        if domain and not domain.is_active:
            return False, "550 5.7.1 Domain disabled", None

    return True, "", addr
