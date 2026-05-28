"""
Alert evaluation service.
Checks alert rules and creates AlertEvent records.
Never blocks SMTP ingestion or import processing.
"""
import json
import logging
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import (
    AlertEvent,
    AlertRule,
    DmarcRecord,
    DmarcReport,
    Domain,
    SourceIp,
)
from app.security import utcnow

logger = logging.getLogger(__name__)

ALERT_TYPES = {
    "new_unknown_source": "New unknown sending source detected",
    "high_volume_source": "New high-volume sending source",
    "new_source_dmarc_fail": "New source with DMARC failures",
    "dmarc_fail_rate": "DMARC fail rate above threshold",
    "spf_fail_rate": "SPF fail rate spike",
    "dkim_fail_rate": "DKIM fail rate spike",
    "volume_spike": "Sudden volume increase",
    "volume_drop": "Sudden volume decrease",
    "reports_missing": "No reports received",
    "import_failed": "Import failure",
    "policy_tighten_ready": "Domain ready for stricter policy",
    "smtp_invalid_recipient": "Many invalid recipient attempts",
    "smtp_rate_limit": "SMTP rate limit triggered",
}


def _can_fire(rule: AlertRule) -> bool:
    if not rule.is_active:
        return False
    if rule.next_allowed_at and rule.next_allowed_at > utcnow():
        return False
    return True


def _mark_fired(db: Session, rule: AlertRule) -> None:
    now = utcnow()
    rule.last_triggered_at = now
    rule.next_allowed_at = now + timedelta(minutes=rule.cooldown_minutes)


def _create_event(
    db: Session,
    *,
    org_id: str,
    domain_id: str | None = None,
    rule: AlertRule | None = None,
    alert_type: str,
    severity: str,
    title: str,
    description: str = "",
    metrics: dict | None = None,
    source_ip: str | None = None,
    report_id: str | None = None,
) -> AlertEvent:
    event = AlertEvent(
        organization_id=org_id,
        domain_id=domain_id,
        rule_id=rule.id if rule else None,
        alert_type=alert_type,
        severity=severity,
        title=title,
        description=description,
        metrics=json.dumps(metrics or {}),
        source_ip=source_ip,
        report_id=report_id,
        status="open",
    )
    db.add(event)
    db.flush()
    return event


def evaluate_rules_for_org(db: Session, org_id: str) -> list[AlertEvent]:
    """Evaluate all active alert rules for an organisation. Returns fired events."""
    fired: list[AlertEvent] = []
    rules = (
        db.query(AlertRule)
        .filter_by(organization_id=org_id, is_active=True)
        .all()
    )
    for rule in rules:
        if not _can_fire(rule):
            continue
        try:
            events = _evaluate_rule(db, rule)
            fired.extend(events)
            if events:
                _mark_fired(db, rule)
        except Exception as exc:
            logger.exception("Error evaluating rule %s: %s", rule.id, exc)
    return fired


def _evaluate_rule(db: Session, rule: AlertRule) -> list[AlertEvent]:
    now = utcnow()
    window_start = now - timedelta(minutes=rule.time_window_minutes)
    org_id = rule.organization_id
    domain_id = rule.domain_id

    base_q = (
        db.query(DmarcRecord)
        .join(DmarcReport)
        .filter(DmarcReport.organization_id == org_id)
        .filter(DmarcReport.created_at >= window_start)
    )
    if domain_id:
        base_q = base_q.filter(DmarcReport.domain_id == domain_id)

    atype = rule.alert_type
    events = []

    if atype == "dmarc_fail_rate":
        records = base_q.all()
        total = sum(r.count for r in records)
        if total < rule.min_message_count:
            return []
        fail = sum(r.count for r in records if not r.dmarc_pass)
        fail_rate = fail / total * 100 if total > 0 else 0
        threshold = rule.threshold or 10.0
        if fail_rate >= threshold:
            domain_name = _domain_name(db, domain_id)
            events.append(_create_event(
                db, org_id=org_id, domain_id=domain_id, rule=rule,
                alert_type=atype, severity=rule.severity,
                title=f"DMARC fail rate {fail_rate:.1f}% exceeds threshold {threshold}%",
                description=f"{fail} of {total} messages failed DMARC in the last {rule.time_window_minutes} minutes.",
                metrics={"fail_rate": fail_rate, "threshold": threshold, "total": total, "fail": fail},
            ))

    elif atype == "reports_missing":
        # Alert if no reports received within time_window_minutes
        q = db.query(DmarcReport).filter_by(organization_id=org_id)
        if domain_id:
            q = q.filter_by(domain_id=domain_id)
        recent = q.filter(DmarcReport.created_at >= window_start).first()
        if not recent:
            domain_name = _domain_name(db, domain_id)
            label = f" for domain {domain_name}" if domain_name else ""
            events.append(_create_event(
                db, org_id=org_id, domain_id=domain_id, rule=rule,
                alert_type=atype, severity=rule.severity,
                title=f"No DMARC reports received{label} in {rule.time_window_minutes} minutes",
                description="Reports may have stopped. Check inbound address configuration and DNS record.",
            ))

    elif atype == "new_unknown_source":
        # Find source IPs first seen after window_start
        new_srcs = (
            db.query(SourceIp)
            .filter_by(organization_id=org_id, classification="unknown")
            .filter(SourceIp.first_seen_at >= window_start)
            .all()
        )
        for src in new_srcs:
            events.append(_create_event(
                db, org_id=org_id, domain_id=domain_id, rule=rule,
                alert_type=atype, severity=rule.severity,
                title=f"New unknown source: {src.ip_address}",
                description=f"First seen at {src.first_seen_at}. Pass rate: {src.pass_rate}%.",
                source_ip=src.ip_address,
                metrics={"ip": src.ip_address, "total_messages": src.total_messages},
            ))

    elif atype == "smtp_invalid_recipient":
        from app.models import SmtpInboundRejection
        count = (
            db.query(func.count(SmtpInboundRejection.id))
            .filter(SmtpInboundRejection.created_at >= window_start)
            .scalar()
            or 0
        )
        threshold = int(rule.threshold or 20)
        if count >= threshold:
            events.append(_create_event(
                db, org_id=org_id, rule=rule,
                alert_type=atype, severity=rule.severity,
                title=f"{count} invalid SMTP recipient attempts in {rule.time_window_minutes} minutes",
                description="This may indicate a misconfigured sender or a probing attempt.",
                metrics={"count": count, "threshold": threshold},
            ))

    return events


def _domain_name(db: Session, domain_id: str | None) -> str | None:
    if not domain_id:
        return None
    d = db.query(Domain).filter_by(id=domain_id).first()
    return d.name if d else None


def create_system_alert(
    db: Session,
    *,
    org_id: str,
    domain_id: str | None = None,
    alert_type: str,
    severity: str = "warning",
    title: str,
    description: str = "",
    metrics: dict | None = None,
    source_ip: str | None = None,
    report_id: str | None = None,
) -> AlertEvent:
    """
    Create a system-generated alert (not tied to a rule).
    Used by import service, SMTP handler, etc.
    """
    return _create_event(
        db,
        org_id=org_id,
        domain_id=domain_id,
        alert_type=alert_type,
        severity=severity,
        title=title,
        description=description,
        metrics=metrics,
        source_ip=source_ip,
        report_id=report_id,
    )
