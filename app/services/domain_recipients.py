"""
Further recipients per domain: mail addresses that get the alerts of one domain, its weekly digest or both,
next to the channels and digest recipients of the organisation.
"""
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Domain, DomainRecipient
from app.services.notification import invalid_addresses


class RecipientError(ValueError):
    """The entry cannot be saved; the message says why and what to do."""


def recipients_for(db: Session, domain: Domain) -> list[DomainRecipient]:
    return db.query(DomainRecipient).filter_by(domain_id=domain.id).order_by(DomainRecipient.email).all()


def add_recipient(db: Session, domain: Domain, email: str, name: str = "", *, alerts: bool = True,
                  digest: bool = True) -> DomainRecipient:
    address = email.strip().lower()
    if not address:
        raise RecipientError("Trage eine E-Mail-Adresse ein.")
    if invalid_addresses([address]):
        raise RecipientError(f"„{email.strip()}“ ist keine gültige E-Mail-Adresse. Prüfe die Schreibweise.")
    if not (alerts or digest):
        raise RecipientError("Wähle Alarme, Wochenbericht oder beides; ohne Auswahl bekäme die Adresse nichts.")
    if db.query(DomainRecipient.id).filter_by(domain_id=domain.id, email=address).first():
        raise RecipientError(f"{address} steht schon bei {domain.name}. Ändere dort, was die Adresse bekommt.")
    count = db.query(DomainRecipient).filter_by(domain_id=domain.id).count()
    if count >= settings.DOMAIN_RECIPIENTS_MAX:
        raise RecipientError(
            f"{domain.name} hat schon {count} weitere Empfänger, mehr erlaubt die Einstellung "
            f"DOMAIN_RECIPIENTS_MAX nicht. Entferne einen Empfänger oder bitte den Betreiber, die Grenze anzuheben."
        )
    recipient = DomainRecipient(
        organization_id=domain.organization_id, domain_id=domain.id, email=address,
        name=name.strip()[:200] or None, alerts=alerts, digest=digest,
    )
    db.add(recipient)
    db.flush()
    return recipient


def update_recipient(recipient: DomainRecipient, *, alerts: bool, digest: bool) -> None:
    if not (alerts or digest):
        raise RecipientError("Wähle Alarme, Wochenbericht oder beides. Soll die Adresse nichts mehr bekommen, "
                             "entferne sie.")
    recipient.alerts = alerts
    recipient.digest = digest


def alert_addresses(db: Session, domain_id: str | None) -> list[str]:
    """Addresses that get the alerts of this domain; none for events without a domain."""
    if not domain_id:
        return []
    rows = (db.query(DomainRecipient.email).join(Domain, Domain.id == DomainRecipient.domain_id)
            .filter(DomainRecipient.domain_id == domain_id, DomainRecipient.alerts.is_(True),
                    Domain.is_active.is_(True))
            .order_by(DomainRecipient.email).all())
    return [email for (email,) in rows]


def still_wants_alerts(db: Session, domain_id: str | None, address: str) -> bool:
    return address in alert_addresses(db, domain_id)
