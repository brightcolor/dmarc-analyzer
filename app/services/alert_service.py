"""
Alert evaluation service.

Rules are checked after each import and periodically by the scheduler. Every event queues one
notification per channel and per further recipient of its domain; the scheduler sends them.
Evaluation never blocks SMTP or imports.
"""
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    AlertEvent,
    AlertRule,
    DmarcRecord,
    DmarcReport,
    Domain,
    ImportJob,
    NotificationChannel,
    NotificationDelivery,
    SmtpInboundRejection,
    SourceIp,
)
from app.security import utcnow
from app.services.domain_recipients import alert_addresses

logger = logging.getLogger(__name__)

ALERT_TYPES = {
    "new_unknown_source": "Neue unbekannte Versandquelle",
    "high_volume_source": "Neue Quelle mit vielen Nachrichten",
    "new_source_dmarc_fail": "Neue Quelle mit DMARC-Fehlern",
    "dmarc_fail_rate": "DMARC-Fehlerquote über der Schwelle",
    "spf_fail_rate": "Viele Nachrichten ohne passendes SPF",
    "dkim_fail_rate": "Viele Nachrichten ohne passendes DKIM",
    "volume_spike": "Versandmenge steigt plötzlich",
    "volume_drop": "Versandmenge fällt plötzlich",
    "reports_missing": "Berichte bleiben aus",
    "import_failed": "Import fehlgeschlagen",
    "policy_tighten_ready": "Domain bereit für eine strengere Policy",
    "smtp_invalid_recipient": "Viele Mails an unbekannte Adressen",
    "smtp_rate_limit": "Grenze für eingehende Mails erreicht",
}

# These types count server-wide mail traffic; only the operator may create them
OPERATOR_ALERT_TYPES = {"smtp_invalid_recipient", "smtp_rate_limit"}

# A rule for all domains checks each active domain on its own for these types, so every alert names its domain
# and reaches the further recipients of that domain
PER_DOMAIN_TYPES = {
    "dmarc_fail_rate", "spf_fail_rate", "dkim_fail_rate", "volume_spike", "volume_drop", "reports_missing",
    "new_unknown_source", "high_volume_source", "new_source_dmarc_fail",
}

# An event in one of these states blocks a second event for the same rule and subject
ACTIVE_STATUSES = ("open", "acknowledged")

# SMTP code the recipient check uses for rate limits
RATE_LIMIT_CODE = "421"


@dataclass
class Finding:
    title: str
    description: str
    domain_id: str | None = None
    source_ip: str | None = None
    metrics: dict = field(default_factory=dict)


def alert_type_hints() -> dict[str, str]:
    """What each type checks and what its threshold means, with the defaults from the settings."""
    s = settings
    return {
        "new_unknown_source": "Quellen, die im Zeitraum zum ersten Mal auftauchen und noch nicht eingestuft sind. "
                              "Ohne Schwelle.",
        "high_volume_source": "Neue Quellen, die schon viele Nachrichten verschickt haben. Schwelle: Anzahl "
                              f"Nachrichten, Vorgabe {_num(s.ALERT_DEFAULT_HIGH_VOLUME)}.",
        "new_source_dmarc_fail": "Neue Quellen mit Nachrichten, die DMARC nicht bestehen. Schwelle: Anzahl "
                                 f"Nachrichten, Vorgabe {_num(s.ALERT_DEFAULT_NEW_SOURCE_FAILURES)}.",
        "dmarc_fail_rate": "Anteil der Nachrichten im Zeitraum, die DMARC nicht bestehen. Schwelle in Prozent, "
                           f"Vorgabe {_num(s.ALERT_DEFAULT_FAIL_RATE)} %.",
        "spf_fail_rate": "Anteil der Nachrichten ohne zur Domain passendes SPF. Schwelle in Prozent, Vorgabe "
                         f"{_num(s.ALERT_DEFAULT_AUTH_FAIL_RATE)} %.",
        "dkim_fail_rate": "Anteil der Nachrichten ohne zur Domain passendes DKIM. Schwelle in Prozent, Vorgabe "
                          f"{_num(s.ALERT_DEFAULT_AUTH_FAIL_RATE)} %.",
        "volume_spike": "Nachrichten im Zeitraum im Vergleich zum Durchschnitt der "
                        f"{s.ALERT_VOLUME_BASELINE_WINDOWS} Zeiträume davor. Schwelle: Anstieg in Prozent, Vorgabe "
                        f"{_num(s.ALERT_DEFAULT_VOLUME_SPIKE)} %.",
        "volume_drop": "Nachrichten im Zeitraum im Vergleich zum Durchschnitt der "
                       f"{s.ALERT_VOLUME_BASELINE_WINDOWS} Zeiträume davor. Schwelle: Rückgang in Prozent, Vorgabe "
                       f"{_num(s.ALERT_DEFAULT_VOLUME_DROP)} %.",
        "reports_missing": "Schlägt an, wenn im Zeitraum kein Bericht ankam. Ohne Schwelle; ein Zeitraum von 2880 "
                           "Minuten deckt zwei Tage ab.",
        "import_failed": "Dateien, die sich im Zeitraum nicht importieren ließen. Schwelle: Anzahl, Vorgabe "
                         f"{_num(s.ALERT_DEFAULT_IMPORT_FAILURES)}.",
        "policy_tighten_ready": "Domains, deren Zahlen eine strengere Policy tragen. Ohne Schwelle.",
        "smtp_invalid_recipient": "Mails an unbekannte Empfangsadressen, auf dem ganzen Server. Schwelle: Anzahl, "
                                  f"Vorgabe {_num(s.ALERT_DEFAULT_INVALID_RECIPIENTS)}.",
        "smtp_rate_limit": "Treffer der Grenze für eingehende Mails, auf dem ganzen Server. Schwelle: Anzahl, Vorgabe "
                           f"{_num(s.ALERT_DEFAULT_RATE_LIMIT_HITS)}.",
    }


# Helpers ------------------------------------------------------------------------

def _num(value: float | int) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f"{value:,.1f}".replace(",", " ").replace(".", ",").replace(" ", ".")
    return f"{int(value):,}".replace(",", ".")


def _window_text(minutes: int) -> str:
    if minutes % 1440 == 0:
        days = minutes // 1440
        return "24 Stunden" if days == 1 else f"{days} Tagen"
    if minutes % 60 == 0:
        hours = minutes // 60
        return "einer Stunde" if hours == 1 else f"{hours} Stunden"
    return f"{minutes} Minuten"


def _domain_label(db: Session, domain_id: str | None) -> str:
    if not domain_id:
        return ""
    domain = db.query(Domain).filter_by(id=domain_id).first()
    return f" für {domain.name}" if domain else ""


def _records(db: Session, rule: AlertRule, start: datetime, end: datetime) -> list[DmarcRecord]:
    query = (
        db.query(DmarcRecord)
        .join(DmarcReport)
        .filter(DmarcReport.organization_id == rule.organization_id)
        .filter(DmarcReport.created_at >= start, DmarcReport.created_at < end)
    )
    if rule.domain_id:
        query = query.filter(DmarcReport.domain_id == rule.domain_id)
    return query.all()


def _new_sources(db: Session, rule: AlertRule, start: datetime, now: datetime) -> list[SourceIp]:
    query = db.query(SourceIp).filter(
        SourceIp.organization_id == rule.organization_id,
        SourceIp.first_seen_at >= start,
        SourceIp.first_seen_at <= now,
    )
    if rule.domain_id:
        seen = {r.source_ip for r in _records(db, rule, start, now + timedelta(seconds=1))}
        return [s for s in query.all() if s.ip_address in seen]
    return query.all()


def _threshold(rule: AlertRule, default: float) -> float:
    return rule.threshold if rule.threshold is not None else default


# Evaluators: one per alert type, each returns what it found ------------------------------

def _eval_dmarc_fail_rate(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
    records = _records(db, rule, now - timedelta(minutes=rule.time_window_minutes), now + timedelta(seconds=1))
    total = sum(r.count for r in records)
    if not total or total < rule.min_message_count:
        return []
    failed = sum(r.count for r in records if not r.dmarc_pass)
    rate = failed / total * 100
    threshold = _threshold(rule, settings.ALERT_DEFAULT_FAIL_RATE)
    if rate < threshold:
        return []
    window = _window_text(rule.time_window_minutes)
    return [Finding(
        title=f"{_num(rate)} % scheitern an DMARC{_domain_label(db, rule.domain_id)}",
        description=(f"{_num(failed)} von {_num(total)} Nachrichten der letzten {window} bestehen DMARC nicht "
                     f"(Schwelle {_num(threshold)} %). Prüfe die fehlschlagenden Quellen."),
        domain_id=rule.domain_id,
        metrics={"rate": round(rate, 2), "failed": failed, "total": total, "threshold": threshold},
    )]


def _eval_auth_fail_rate(mechanism: str) -> Callable[[Session, AlertRule, datetime], list[Finding]]:
    attribute = f"{mechanism}_aligned"
    label = mechanism.upper()

    def evaluate(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
        records = _records(db, rule, now - timedelta(minutes=rule.time_window_minutes), now + timedelta(seconds=1))
        total = sum(r.count for r in records)
        if not total or total < rule.min_message_count:
            return []
        without = sum(r.count for r in records if not getattr(r, attribute))
        rate = without / total * 100
        threshold = _threshold(rule, settings.ALERT_DEFAULT_AUTH_FAIL_RATE)
        if rate < threshold:
            return []
        return [Finding(
            title=f"{_num(rate)} % ohne passendes {label}{_domain_label(db, rule.domain_id)}",
            description=(f"{_num(without)} von {_num(total)} Nachrichten der letzten "
                         f"{_window_text(rule.time_window_minutes)} haben kein zur Domain passendes {label} "
                         f"(Schwelle {_num(threshold)} %)."),
            domain_id=rule.domain_id,
            metrics={"rate": round(rate, 2), "without": without, "total": total, "threshold": threshold},
        )]

    return evaluate


def _volumes(db: Session, rule: AlertRule, now: datetime) -> tuple[int, float | None]:
    """Messages in the current window and the average of the previous windows (None without history)."""
    length = timedelta(minutes=rule.time_window_minutes)
    current = sum(r.count for r in _records(db, rule, now - length, now + timedelta(seconds=1)))
    history = []
    for index in range(1, settings.ALERT_VOLUME_BASELINE_WINDOWS + 1):
        end = now - length * index
        history.append(sum(r.count for r in _records(db, rule, end - length, end)))
    if not any(history):
        return current, None
    return current, sum(history) / len(history)


def _eval_volume_spike(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
    current, baseline = _volumes(db, rule, now)
    threshold = _threshold(rule, settings.ALERT_DEFAULT_VOLUME_SPIKE)
    if baseline is None or current < rule.min_message_count or current < baseline * (1 + threshold / 100):
        return []
    return [Finding(
        title=f"Versandmenge gestiegen auf {_num(current)} Nachrichten{_domain_label(db, rule.domain_id)}",
        description=(f"In den letzten {_window_text(rule.time_window_minutes)} kamen {_num(current)} Nachrichten, "
                     f"im Durchschnitt davor {_num(round(baseline))}. Prüfe, ob eine neue Quelle oder ein "
                     "Missbrauch dahintersteckt."),
        domain_id=rule.domain_id,
        metrics={"current": current, "baseline": round(baseline, 1), "threshold": threshold},
    )]


def _eval_volume_drop(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
    current, baseline = _volumes(db, rule, now)
    threshold = _threshold(rule, settings.ALERT_DEFAULT_VOLUME_DROP)
    if baseline is None or baseline < rule.min_message_count or current > baseline * (1 - threshold / 100):
        return []
    return [Finding(
        title=f"Versandmenge gefallen auf {_num(current)} Nachrichten{_domain_label(db, rule.domain_id)}",
        description=(f"In den letzten {_window_text(rule.time_window_minutes)} kamen {_num(current)} Nachrichten, "
                     f"im Durchschnitt davor {_num(round(baseline))}. Prüfe, ob ein Versanddienst ausgefallen ist "
                     "oder Berichte ausbleiben."),
        domain_id=rule.domain_id,
        metrics={"current": current, "baseline": round(baseline, 1), "threshold": threshold},
    )]


def _eval_reports_missing(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
    since = now - timedelta(minutes=rule.time_window_minutes)
    query = db.query(DmarcReport.id).filter_by(organization_id=rule.organization_id)
    if rule.domain_id:
        query = query.filter_by(domain_id=rule.domain_id)
    if query.filter(DmarcReport.created_at >= since).first():
        return []
    if getattr(rule, "for_each_domain", False) and not query.first():
        # Checked as one of all domains: a domain that never had a report has nothing that stays away
        return []
    window = _window_text(rule.time_window_minutes)
    return [Finding(
        title=f"Seit {window} keine Berichte{_domain_label(db, rule.domain_id)}",
        description=("Es kam kein neuer DMARC-Bericht an. Prüfe, ob der DMARC-Eintrag die Empfangsadresse als rua "
                     "enthält und die Empfangsdomain Mails annimmt."),
        domain_id=rule.domain_id,
        metrics={"window_minutes": rule.time_window_minutes},
    )]


def _source_title(src: SourceIp) -> str:
    from app.services.senders import load_catalog

    name = load_catalog().name(src.sender_key)
    return f"{src.ip_address} ({name})" if name else src.ip_address


def _eval_new_unknown_source(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
    start = now - timedelta(minutes=rule.time_window_minutes)
    sources = _new_sources(db, rule, start, now)
    if settings.SCHEDULER_ENABLED:
        # The scheduler names the sender first; a decision about the sender may already cover the address
        sources = [src for src in sources if src.enriched_at is not None]
    return [
        Finding(
            title=f"Neue unbekannte Quelle {_source_title(src)}",
            description=(f"{src.ip_address} verschickt Mails für deine Domains und ist noch nicht eingestuft. Bisher "
                         f"{_num(src.total_messages)} Nachrichten, davon {_num(src.pass_rate or 0)} % bestanden. "
                         + ("Gehört der Dienst zu dir, gib ihn unter „Absender“ frei."
                            if src.sender_key else "Stufe sie unter „Quellen“ ein.")),
            domain_id=rule.domain_id,
            source_ip=src.ip_address,
            metrics={"ip": src.ip_address, "total": src.total_messages, "pass_rate": src.pass_rate,
                     "sender": src.sender_key},
        )
        for src in sources
        if src.classification == "unknown"
    ]


def _eval_high_volume_source(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
    start = now - timedelta(minutes=rule.time_window_minutes)
    threshold = _threshold(rule, settings.ALERT_DEFAULT_HIGH_VOLUME)
    return [
        Finding(
            title=f"Neue Quelle {_source_title(src)} mit {_num(src.total_messages)} Nachrichten",
            description=(f"{src.ip_address} ist neu und hat schon {_num(src.total_messages)} Nachrichten für deine "
                         f"Domains verschickt (Schwelle {_num(threshold)})."),
            domain_id=rule.domain_id,
            source_ip=src.ip_address,
            metrics={"ip": src.ip_address, "total": src.total_messages, "threshold": threshold},
        )
        for src in _new_sources(db, rule, start, now)
        if src.total_messages >= threshold
    ]


def _eval_new_source_dmarc_fail(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
    start = now - timedelta(minutes=rule.time_window_minutes)
    minimum = _threshold(rule, settings.ALERT_DEFAULT_NEW_SOURCE_FAILURES)
    return [
        Finding(
            title=f"Neue Quelle {_source_title(src)} scheitert an DMARC",
            description=(f"{_num(src.fail_count)} von {_num(src.total_messages)} Nachrichten dieser neuen Quelle "
                         "bestehen DMARC nicht. Ist sie ein eigener Versanddienst, fehlt ihr SPF oder DKIM."),
            domain_id=rule.domain_id,
            source_ip=src.ip_address,
            metrics={"ip": src.ip_address, "failed": src.fail_count, "total": src.total_messages},
        )
        for src in _new_sources(db, rule, start, now)
        if src.fail_count >= minimum
    ]


def _eval_import_failed(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
    since = now - timedelta(minutes=rule.time_window_minutes)
    query = db.query(func.count(ImportJob.id)).filter(
        ImportJob.organization_id == rule.organization_id,
        ImportJob.status == "failed",
        ImportJob.created_at >= since,
    )
    count = query.scalar() or 0
    threshold = _threshold(rule, settings.ALERT_DEFAULT_IMPORT_FAILURES)
    if count < threshold:
        return []
    return [Finding(
        title=f"{_num(count)} {'Import' if count == 1 else 'Importe'} fehlgeschlagen",
        description=(f"In den letzten {_window_text(rule.time_window_minutes)} ließen sich {_num(count)} Dateien "
                     "nicht importieren. Die Gründe stehen unter Berichte → Importe."),
        metrics={"count": count, "threshold": threshold},
    )]


def _eval_policy_tighten_ready(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
    from app.services.recommendation import get_recommendations_for_domain

    domains = db.query(Domain).filter_by(organization_id=rule.organization_id, is_active=True)
    if rule.domain_id:
        domains = domains.filter_by(id=rule.domain_id)
    findings = []
    for domain in domains.all():
        for rec in get_recommendations_for_domain(db, rule.organization_id, domain.id):
            if rec.code in ("READY_FOR_QUARANTINE", "READY_FOR_REJECT"):
                target = "quarantine" if rec.code == "READY_FOR_QUARANTINE" else "reject"
                findings.append(Finding(
                    title=f"{domain.name} ist bereit für p={target}",
                    description=rec.description,
                    domain_id=domain.id,
                    metrics={"recommendation": rec.code},
                ))
    return findings


def _eval_smtp_rejections(rate_limit: bool) -> Callable[[Session, AlertRule, datetime], list[Finding]]:
    def evaluate(db: Session, rule: AlertRule, now: datetime) -> list[Finding]:
        since = now - timedelta(minutes=rule.time_window_minutes)
        query = db.query(func.count(SmtpInboundRejection.id)).filter(SmtpInboundRejection.created_at >= since)
        if rate_limit:
            query = query.filter(SmtpInboundRejection.rejection_code == RATE_LIMIT_CODE)
            threshold = _threshold(rule, settings.ALERT_DEFAULT_RATE_LIMIT_HITS)
        else:
            query = query.filter(SmtpInboundRejection.rejection_code.like("5%"))
            threshold = _threshold(rule, settings.ALERT_DEFAULT_INVALID_RECIPIENTS)
        count = query.scalar() or 0
        if count < threshold:
            return []
        window = _window_text(rule.time_window_minutes)
        if rate_limit:
            title = f"{_num(count)}-mal Grenze für eingehende Mails erreicht"
            description = (f"In den letzten {window} hat der Mailempfang {_num(count)} Verbindungen wegen der Grenze "
                           "je Absender oder Adresse vertröstet. Ein Absender schickt mehr als erwartet.")
        else:
            title = f"{_num(count)} Mails an unbekannte Adressen abgelehnt"
            description = (f"In den letzten {window} hat der Mailempfang {_num(count)} Mails an Adressen abgelehnt, "
                           "die es nicht gibt. Das deutet auf einen falschen rua-Eintrag oder ein Abtasten hin.")
        return [Finding(title=title, description=description, metrics={"count": count, "threshold": threshold})]

    return evaluate


EVALUATORS: dict[str, Callable[[Session, AlertRule, datetime], list[Finding]]] = {
    "dmarc_fail_rate": _eval_dmarc_fail_rate,
    "spf_fail_rate": _eval_auth_fail_rate("spf"),
    "dkim_fail_rate": _eval_auth_fail_rate("dkim"),
    "volume_spike": _eval_volume_spike,
    "volume_drop": _eval_volume_drop,
    "reports_missing": _eval_reports_missing,
    "new_unknown_source": _eval_new_unknown_source,
    "high_volume_source": _eval_high_volume_source,
    "new_source_dmarc_fail": _eval_new_source_dmarc_fail,
    "import_failed": _eval_import_failed,
    "policy_tighten_ready": _eval_policy_tighten_ready,
    "smtp_invalid_recipient": _eval_smtp_rejections(rate_limit=False),
    "smtp_rate_limit": _eval_smtp_rejections(rate_limit=True),
}


# Rules ------------------------------------------------------------------------------

class _DomainView:
    """A rule for all domains as it applies to one of them: same settings, this domain."""

    for_each_domain = True

    def __init__(self, rule: AlertRule, domain_id: str) -> None:
        self._rule = rule
        self.domain_id = domain_id

    def __getattr__(self, name: str):
        return getattr(self._rule, name)


def _findings(db: Session, rule: AlertRule, evaluator, now: datetime) -> list[Finding]:
    if rule.domain_id or rule.alert_type not in PER_DOMAIN_TYPES:
        return evaluator(db, rule, now)
    domain_ids = [d for (d,) in db.query(Domain.id).filter_by(organization_id=rule.organization_id, is_active=True)
                  .order_by(Domain.name)]
    return [finding for domain_id in domain_ids for finding in evaluator(db, _DomainView(rule, domain_id), now)]


def _same_subject(query, finding: Finding):
    query = query.filter(AlertEvent.domain_id == finding.domain_id) if finding.domain_id else \
        query.filter(AlertEvent.domain_id.is_(None))
    return query.filter(AlertEvent.source_ip == finding.source_ip) if finding.source_ip else \
        query.filter(AlertEvent.source_ip.is_(None))


def _is_duplicate(db: Session, rule: AlertRule, finding: Finding) -> bool:
    query = db.query(AlertEvent.id).filter(
        AlertEvent.rule_id == rule.id,
        AlertEvent.status.in_(ACTIVE_STATUSES),
    )
    return _same_subject(query, finding).first() is not None


def _in_pause(db: Session, rule: AlertRule, finding: Finding, now: datetime) -> bool:
    """The rule raised an event for the same domain and source within its pause."""
    if not rule.cooldown_minutes:
        return False
    since = now - timedelta(minutes=rule.cooldown_minutes)
    query = db.query(AlertEvent.id).filter(AlertEvent.rule_id == rule.id, AlertEvent.created_at > since)
    return _same_subject(query, finding).first() is not None


def evaluate_rules_for_org(db: Session, org_id: str, now: datetime | None = None) -> list[AlertEvent]:
    """Check all active rules of an organisation and raise events for new findings."""
    now = now or utcnow()
    fired: list[AlertEvent] = []
    rules = db.query(AlertRule).filter_by(organization_id=org_id, is_active=True).all()
    for rule in rules:
        evaluator = EVALUATORS.get(rule.alert_type)
        if evaluator is None:
            logger.warning("Rule %s has unknown alert type %s", rule.id, rule.alert_type)
            continue
        try:
            findings = _findings(db, rule, evaluator, now)
        except Exception:
            logger.exception("Error evaluating rule %s", rule.id)
            continue
        events = [
            raise_event(
                db, org_id=org_id, rule=rule, alert_type=rule.alert_type, severity=rule.severity,
                title=f.title, description=f.description, domain_id=f.domain_id, source_ip=f.source_ip,
                metrics=f.metrics, now=now,
            )
            for f in findings
            if not _is_duplicate(db, rule, f) and not _in_pause(db, rule, f, now)
        ]
        if events:
            rule.last_triggered_at = now
            rule.next_allowed_at = now + timedelta(minutes=rule.cooldown_minutes)
            fired.extend(events)
    db.flush()
    return fired


def evaluate_after_import(db: Session, org_id: str) -> None:
    """Check the rules right after an import. A problem here never undoes the import itself."""
    try:
        with db.begin_nested():
            evaluate_rules_for_org(db, org_id)
    except Exception:
        logger.exception("Alert evaluation after import failed for organisation %s", org_id)


# Events and their notifications -----------------------------------------------------------

def _channel_ids_for(db: Session, org_id: str, rule: AlertRule | None) -> list[str]:
    active = db.query(NotificationChannel.id).filter_by(organization_id=org_id, is_active=True)
    if rule is None:
        # Events from the system itself go to every active channel
        return [cid for (cid,) in active.all()]
    try:
        wanted = set(json.loads(rule.notification_channel_ids or "[]"))
    except (TypeError, ValueError):
        wanted = set()
    return [cid for (cid,) in active.all() if cid in wanted]


def raise_event(
    db: Session,
    *,
    org_id: str,
    alert_type: str,
    severity: str,
    title: str,
    description: str = "",
    rule: AlertRule | None = None,
    domain_id: str | None = None,
    source_ip: str | None = None,
    metrics: dict | None = None,
    report_id: str | None = None,
    smtp_message_id: str | None = None,
    now: datetime | None = None,
) -> AlertEvent:
    """Store an event and queue one notification per channel and per further recipient of its domain."""
    event = AlertEvent(
        organization_id=org_id,
        domain_id=domain_id,
        rule_id=rule.id if rule else None,
        alert_type=alert_type,
        severity=severity,
        title=title[:500],
        description=description,
        metrics=json.dumps(metrics or {}),
        source_ip=source_ip,
        report_id=report_id,
        smtp_message_id=smtp_message_id,
        status="open",
    )
    if now is not None:
        event.created_at = now
    db.add(event)
    db.flush()
    for channel_id in _channel_ids_for(db, org_id, rule):
        db.add(NotificationDelivery(alert_event_id=event.id, channel_id=channel_id, status="pending"))
    for address in alert_addresses(db, domain_id):
        db.add(NotificationDelivery(alert_event_id=event.id, recipient=address, status="pending"))
    db.flush()
    return event


def create_system_alert(
    db: Session,
    *,
    org_id: str,
    alert_type: str,
    title: str,
    severity: str = "warning",
    description: str = "",
    domain_id: str | None = None,
    metrics: dict | None = None,
    source_ip: str | None = None,
    report_id: str | None = None,
    smtp_message_id: str | None = None,
) -> AlertEvent:
    """Event raised by the application itself (import, mail reception), sent to every active channel."""
    return raise_event(
        db, org_id=org_id, alert_type=alert_type, severity=severity, title=title, description=description,
        domain_id=domain_id, metrics=metrics, source_ip=source_ip, report_id=report_id,
        smtp_message_id=smtp_message_id,
    )

