"""
Weekly digest: the DMARC results of one organisation over the last DIGEST_PERIOD_DAYS, sent by mail.

The scheduler looks every DIGEST_CHECK_INTERVAL_SECONDS for organisations whose digest is due:
once a week on DIGEST_WEEKDAY from DIGEST_HOUR in DISPLAY_TIMEZONE. The period counts the reports
that arrived in it (import time), the same basis the dashboard uses for recent activity.

Further recipients of a domain get their own digest at the same time, limited to their domains: one mail
per address, covering every domain the address is entered for.
"""
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    AlertEvent,
    DmarcRecord,
    DmarcReport,
    Domain,
    DomainRecipient,
    Organization,
    OrganizationMembership,
    SourceIp,
    User,
)
from app.security import utcnow
from app.services import report_formats
from app.services.mailer import (
    MailDeliveryError,
    MailNotConfigured,
    mail_configured,
    not_configured_reason,
    send_mail,
)
from app.services.notification import parse_addresses
from app.services.recommendation import Recommendation, get_recommendations_for_domain

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
# Recommendations of severity info that still belong in the digest
NOTABLE_INFO_CODES = ("READY_FOR_QUARANTINE", "READY_FOR_REJECT")


class DigestError(Exception):
    """The digest could not be sent; the message says why and what to do."""


@dataclass
class Recipient:
    address: str
    name: str | None = None
    listed: bool = False  # True: entered as digest recipient, False: administrator of the organisation
    domains: list[str] | None = None  # further recipient of these domains; the digest covers only them


@dataclass
class DomainLine:
    name: str
    total: int
    failed: int

    @property
    def rate(self) -> float | None:
        return (self.total - self.failed) / self.total * 100 if self.total else None


@dataclass
class SourceLine:
    ip: str
    name: str | None
    total: int
    failed: int
    classification: str


@dataclass
class Advice:
    domain: str
    recommendation: Recommendation


@dataclass
class DigestData:
    organization: Organization
    start: datetime
    end: datetime
    total: int = 0
    failed: int = 0
    previous_total: int = 0
    previous_failed: int = 0
    reports: int = 0
    reporters: int = 0
    formats: list[tuple[str, int]] = field(default_factory=list)
    domains: list[DomainLine] = field(default_factory=list)
    failing_sources: list[SourceLine] = field(default_factory=list)
    new_sources: list[SourceLine] = field(default_factory=list)
    new_source_count: int = 0
    open_alert_count: int = 0
    open_alerts: list[AlertEvent] = field(default_factory=list)
    advice: list[Advice] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)  # domain names; empty for the whole organisation

    @property
    def passed(self) -> int:
        return self.total - self.failed

    @property
    def rate(self) -> float | None:
        return self.passed / self.total * 100 if self.total else None

    @property
    def previous_rate(self) -> float | None:
        if not self.previous_total:
            return None
        return (self.previous_total - self.previous_failed) / self.previous_total * 100

    @property
    def rate_change(self) -> float | None:
        if self.rate is None or self.previous_rate is None:
            return None
        return self.rate - self.previous_rate

    @property
    def days(self) -> int:
        return round((self.end - self.start).total_seconds() / 86_400)


@dataclass
class DigestResult:
    sent: list[str]
    failed: list[str]


# Data --------------------------------------------------------------------------------

def _failed_sum():
    return func.coalesce(func.sum(case((DmarcRecord.dmarc_pass, 0), else_=DmarcRecord.count)), 0)


def _period_records(db: Session, org_id: str, start: datetime, end: datetime, *columns,
                    domain_ids: list[str] | None = None):
    query = (
        db.query(*columns)
        .select_from(DmarcRecord)
        .join(DmarcReport, DmarcRecord.report_id == DmarcReport.id)
        .filter(DmarcReport.organization_id == org_id, DmarcReport.created_at >= start, DmarcReport.created_at < end)
    )
    return query.filter(DmarcReport.domain_id.in_(domain_ids)) if domain_ids is not None else query


def _totals(db: Session, org_id: str, start: datetime, end: datetime,
            domain_ids: list[str] | None = None) -> tuple[int, int]:
    total, failed = _period_records(
        db, org_id, start, end, func.coalesce(func.sum(DmarcRecord.count), 0), _failed_sum(), domain_ids=domain_ids,
    ).one()
    return int(total), int(failed)


def build_digest(db: Session, org: Organization, end: datetime | None = None,
                 domain_ids: list[str] | None = None) -> DigestData:
    """Collect the numbers for the digest of the period that ends at end; domain_ids limits it to those domains."""
    end = end or utcnow()
    length = timedelta(days=settings.DIGEST_PERIOD_DAYS)
    start = end - length
    limit = settings.DIGEST_LIST_LIMIT
    data = DigestData(organization=org, start=start, end=end)
    scoped = domain_ids is not None

    data.total, data.failed = _totals(db, org.id, start, end, domain_ids)
    data.previous_total, data.previous_failed = _totals(db, org.id, start - length, start, domain_ids)

    in_period = (DmarcReport.organization_id == org.id, DmarcReport.created_at >= start, DmarcReport.created_at < end)
    if scoped:
        in_period = (*in_period, DmarcReport.domain_id.in_(domain_ids))
    data.reports, data.reporters = db.query(
        func.count(DmarcReport.id), func.count(func.distinct(DmarcReport.reporting_org))
    ).filter(*in_period).one()
    format_rows = db.query(DmarcReport.report_format, func.count(DmarcReport.id)).filter(*in_period) \
        .group_by(DmarcReport.report_format).all()
    data.formats = sorted(
        ((report_formats.format_info(fmt).label, count) for fmt, count in format_rows), key=lambda item: -item[1]
    )

    per_domain = {
        domain_id: (int(total or 0), int(failed or 0))
        for domain_id, total, failed in _period_records(
            db, org.id, start, end, DmarcReport.domain_id, func.sum(DmarcRecord.count), _failed_sum(),
            domain_ids=domain_ids,
        ).group_by(DmarcReport.domain_id).all()
    }
    domain_query = db.query(Domain).filter_by(organization_id=org.id, is_active=True)
    if scoped:
        domain_query = domain_query.filter(Domain.id.in_(domain_ids))
    domains = domain_query.order_by(Domain.name).all()
    if scoped:
        data.scope = [d.name for d in domains]
    data.domains = sorted(
        (DomainLine(d.name, *per_domain.get(d.id, (0, 0))) for d in domains), key=lambda line: -line.total
    )

    failed_sum = _failed_sum()
    source_rows = (
        _period_records(db, org.id, start, end, DmarcRecord.source_ip, func.sum(DmarcRecord.count), failed_sum,
                        domain_ids=domain_ids)
        .group_by(DmarcRecord.source_ip)
        .having(failed_sum > 0)
        .order_by(failed_sum.desc(), DmarcRecord.source_ip)
        .limit(limit)
        .all()
    )
    known = {
        s.ip_address: s
        for s in db.query(SourceIp).filter(
            SourceIp.organization_id == org.id, SourceIp.ip_address.in_([ip for ip, _, _ in source_rows])
        )
    }
    data.failing_sources = [
        SourceLine(ip, _source_name(known.get(ip)), int(total), int(failed),
                   known[ip].classification if ip in known else "unknown")
        for ip, total, failed in source_rows
    ]

    new_query = db.query(SourceIp).filter(
        SourceIp.organization_id == org.id, SourceIp.first_seen_at >= start, SourceIp.first_seen_at < end
    )
    if scoped:
        # Sources are kept per organisation; count those that sent for these domains in the period
        seen = _period_records(db, org.id, start, end, DmarcRecord.source_ip, domain_ids=domain_ids).distinct()
        new_query = new_query.filter(SourceIp.ip_address.in_(seen.scalar_subquery()))
    data.new_source_count = new_query.count()
    data.new_sources = [
        SourceLine(s.ip_address, _source_name(s), s.total_messages, s.fail_count, s.classification)
        for s in new_query.order_by(SourceIp.total_messages.desc(), SourceIp.ip_address).limit(limit)
    ]

    open_alerts = db.query(AlertEvent).filter_by(organization_id=org.id, status="open")
    if scoped:
        open_alerts = open_alerts.filter(AlertEvent.domain_id.in_(domain_ids))
    data.open_alert_count = open_alerts.count()
    data.open_alerts = open_alerts.order_by(AlertEvent.created_at.desc()).limit(limit).all()

    advice = [
        Advice(domain.name, rec)
        for domain in domains
        for rec in get_recommendations_for_domain(db, org.id, domain.id)
        if rec.severity != "info" or rec.code in NOTABLE_INFO_CODES
    ]
    advice.sort(key=lambda a: (SEVERITY_ORDER.get(a.recommendation.severity, 9), a.domain))
    data.advice = advice[:limit]
    return data


def _source_name(source: SourceIp | None) -> str | None:
    from app.services.senders import sender_label

    return sender_label(source) if source is not None else None


# Recipients and schedule ---------------------------------------------------------------

def first_name(full_name: str | None) -> str | None:
    parts = (full_name or "").split()
    return parts[0] if parts else None


def digest_recipients(db: Session, org: Organization) -> list[Recipient]:
    """Entered recipients; without any, the active administrators of the organisation."""
    listed = parse_addresses(org.digest_recipients)
    if listed:
        return [Recipient(address, listed=True) for address in listed]
    admins = (
        db.query(User)
        .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
        .filter(
            OrganizationMembership.organization_id == org.id,
            OrganizationMembership.role == "org_admin",
            OrganizationMembership.is_active.is_(True),
            User.is_active.is_(True),
        )
        .order_by(User.email)
        .all()
    )
    return [Recipient(user.email, first_name(user.full_name)) for user in admins]


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def last_slot(now: datetime) -> datetime:
    """Most recent scheduled send time at or before now, in UTC."""
    local = _as_utc(now).astimezone(ZoneInfo(settings.DISPLAY_TIMEZONE))
    days_back = (local.weekday() - settings.DIGEST_WEEKDAY) % 7
    slot = (local - timedelta(days=days_back)).replace(hour=settings.DIGEST_HOUR, minute=0, second=0, microsecond=0)
    if slot > local:
        slot -= timedelta(days=7)
    return slot.astimezone(UTC)


def next_slot(now: datetime) -> datetime:
    """Next scheduled send time after now, in UTC."""
    local = last_slot(now).astimezone(ZoneInfo(settings.DISPLAY_TIMEZONE))
    return (local + timedelta(days=7)).astimezone(UTC)


def digest_due(org: Organization, now: datetime) -> bool:
    if not (org.is_active and org.digest_enabled):
        return False
    reference = org.digest_last_sent_at or org.created_at
    return reference is None or _as_utc(reference) < last_slot(now)


def domain_digest_groups(db: Session, org: Organization) -> dict[str, list[DomainRecipient]]:
    """Further recipients with the weekly digest switched on, grouped by address; only active domains."""
    rows = (
        db.query(DomainRecipient)
        .join(Domain, Domain.id == DomainRecipient.domain_id)
        .filter(DomainRecipient.organization_id == org.id, DomainRecipient.digest.is_(True),
                Domain.is_active.is_(True))
        .order_by(DomainRecipient.email)
        .all()
    )
    groups: dict[str, list[DomainRecipient]] = defaultdict(list)
    for row in rows:
        groups[row.email].append(row)
    return dict(groups)


def domain_digest_due(rows: list[DomainRecipient], now: datetime) -> bool:
    slot = last_slot(now)
    for row in rows:
        reference = row.digest_last_sent_at or row.created_at
        if reference is None or _as_utc(reference) < slot:
            return True
    return False


def send_domain_digest(db: Session, org: Organization, rows: list[DomainRecipient],
                       now: datetime | None = None) -> None:
    """The digest of the given domains to one further recipient. Raises DigestError."""
    from app.services.mail_render import render_digest_mail

    now = now or utcnow()
    if not mail_configured():
        raise DigestError(not_configured_reason())
    data = build_digest(db, org, now, domain_ids=[row.domain_id for row in rows])
    recipient = Recipient(rows[0].email, next((row.name for row in rows if row.name), None), listed=True,
                          domains=data.scope)
    subject, text, html = render_digest_mail(data, recipient)
    try:
        send_mail([recipient.address], subject, text, html)
    except (MailDeliveryError, MailNotConfigured) as exc:
        raise DigestError(f"Der Wochenbericht an {recipient.address} ging nicht raus: {exc}") from exc
    for row in rows:
        row.digest_last_sent_at = now
    logger.info("Weekly digest for %s sent to a further recipient of %d domains", org.slug, len(rows))


# Sending --------------------------------------------------------------------------------

def send_digest(db: Session, org: Organization, now: datetime | None = None,
                recipients: list[Recipient] | None = None) -> DigestResult:
    """Send the digest to each recipient in a mail of its own. Raises DigestError when nobody got it."""
    from app.services.mail_render import render_digest_mail

    now = now or utcnow()
    if not mail_configured():
        raise DigestError(not_configured_reason())
    recipients = digest_recipients(db, org) if recipients is None else recipients
    if not recipients:
        raise DigestError("Für den Wochenbericht gibt es keinen Empfänger. Trage Adressen ein oder gib einem "
                          "Mitglied die Rolle Administrator.")

    data = build_digest(db, org, now)
    result = DigestResult(sent=[], failed=[])
    for recipient in recipients:
        subject, text, html = render_digest_mail(data, recipient)
        try:
            send_mail([recipient.address], subject, text, html)
        except (MailDeliveryError, MailNotConfigured) as exc:
            result.failed.append(f"{recipient.address}: {exc}")
        else:
            result.sent.append(recipient.address)
    if result.sent:
        org.digest_last_sent_at = now
        logger.info("Weekly digest for %s sent to %d recipients", org.slug, len(result.sent))
    if not result.sent:
        raise DigestError("Der Wochenbericht ging an niemanden raus. " + " ".join(result.failed))
    return result


def send_due_digests(db: Session, now: datetime | None = None) -> int:
    """Send every digest that is due; returns the number of organisations that got theirs."""
    now = now or utcnow()
    if not mail_configured():
        logger.debug("Mail delivery not configured, weekly digests wait")
        return 0
    sent = 0
    orgs = db.query(Organization).filter_by(is_active=True).order_by(Organization.name).all()
    for org in orgs:
        if not db.query(Domain.id).filter_by(organization_id=org.id).first():
            continue
        if digest_due(org, now):
            try:
                send_digest(db, org, now)
            except DigestError as exc:
                db.rollback()
                logger.warning("Weekly digest for %s not sent: %s", org.slug, exc)
            else:
                db.commit()
                sent += 1
        # Further recipients of single domains follow their own switch, also when the organisation's is off
        for rows in domain_digest_groups(db, org).values():
            if not domain_digest_due(rows, now):
                continue
            try:
                send_domain_digest(db, org, rows, now)
            except DigestError as exc:
                db.rollback()
                logger.warning("Weekly digest for %s not sent: %s", org.slug, exc)
                continue
            db.commit()
    return sent
