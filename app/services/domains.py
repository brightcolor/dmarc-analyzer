"""Creating domains: one place for the name rules, the limit of the organisation and the report address."""
import re

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Domain, InboundMailAddress, Organization
from app.services.inbound_address import create_domain_address

# Labels of letters, digits and hyphens; names with umlauts arrive here already as xn-- (IDNA)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")

INVALID_NAME = ("Das ist kein gültiger Domainname. Erlaubt sind Buchstaben, Ziffern, Punkte und Bindestriche, "
                "etwa example.com; Umlaute wandelt die Anwendung selbst um.")


class DomainLimitReached(Exception):
    pass


def normalize_domain(value: str | None) -> str | None:
    """Domain in the form DMARC reports use (lower case, umlauts as xn--), or None when it is no domain."""
    name = (value or "").strip().lower().rstrip(".")
    if not name:
        return None
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return name if DOMAIN_RE.match(name) else None


def plan_limits() -> dict[str, int]:
    """Limits of the default plan for a new organisation."""
    return {
        "max_domains": settings.DEFAULT_PLAN_MAX_DOMAINS,
        "max_users": settings.DEFAULT_PLAN_MAX_USERS,
        "max_api_tokens": settings.DEFAULT_PLAN_MAX_API_TOKENS,
        "max_alert_rules": settings.DEFAULT_PLAN_MAX_ALERT_RULES,
        "max_inbound_addresses": settings.DEFAULT_PLAN_MAX_INBOUND_ADDRESSES,
        "report_retention_days": settings.DEFAULT_PLAN_REPORT_RETENTION_DAYS,
        "smtp_rate_limit_per_hour": settings.DEFAULT_PLAN_SMTP_RATE_LIMIT_PER_HOUR,
        "api_rate_limit_per_hour": settings.DEFAULT_PLAN_API_RATE_LIMIT_PER_HOUR,
    }


def report_address(db: Session, org: Organization, domain: Domain) -> InboundMailAddress:
    """The active report address of the domain; a domain without one gets one."""
    address = (
        db.query(InboundMailAddress)
        .filter_by(organization_id=org.id, domain_id=domain.id, status="active", purpose="domain_report")
        .order_by(InboundMailAddress.created_at)
        .first()
    )
    return address or create_domain_address(db, org, domain)


def create_domain(db: Session, org: Organization, name: str) -> tuple[Domain, InboundMailAddress, bool]:
    """Domain with its report address; an existing domain comes back unchanged (created False)."""
    domain = db.query(Domain).filter_by(organization_id=org.id, name=name).first()
    if domain is not None:
        return domain, report_address(db, org, domain), False
    if db.query(Domain).filter_by(organization_id=org.id).count() >= org.max_domains:
        raise DomainLimitReached(
            f"Diese Organisation darf höchstens {org.max_domains} Domains anlegen. Der Betreiber erhöht die Grenze "
            f"mit „python -m app.org_limits {org.slug} --max-domains <Anzahl>“."
        )
    domain = Domain(organization_id=org.id, name=name, is_active=True)
    db.add(domain)
    db.flush()
    return domain, create_domain_address(db, org, domain), True
