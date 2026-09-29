"""Server-side dashboard aggregation queries."""
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    AlertEvent,
    DmarcRecord,
    DmarcReport,
    Domain,
    ImportJob,
    SmtpInboundMessage,
    SmtpInboundRejection,
    SourceIp,
)


def get_dashboard_stats(db: Session, org_id: str) -> dict:
    now = datetime.now(UTC)
    thirty_days_ago = now - timedelta(days=settings.UI_CHART_DAYS)
    seven_days_ago = now - timedelta(days=settings.RECOMMENDATION_STALE_REPORT_DAYS)

    # Core counts
    domain_count = db.query(func.count(Domain.id)).filter_by(organization_id=org_id, is_active=True).scalar() or 0
    report_count = db.query(func.count(DmarcReport.id)).filter_by(organization_id=org_id).scalar() or 0

    # Message stats (30 days)
    stats_30d = (
        db.query(
            func.sum(DmarcRecord.count).label("total"),
            func.sum(
                case((DmarcRecord.dmarc_pass.is_(True), DmarcRecord.count), else_=0)
            ).label("pass"),
        )
        .join(DmarcReport)
        .filter(
            DmarcReport.organization_id == org_id,
            DmarcReport.created_at >= thirty_days_ago,
        )
        .first()
    )
    total_msgs = int(stats_30d.total or 0)
    pass_msgs = int(getattr(stats_30d, "pass") or 0)
    fail_msgs = total_msgs - pass_msgs
    pass_rate = round(pass_msgs / total_msgs * 100, 1) if total_msgs > 0 else None

    # SPF / DKIM pass rates (30d)
    spf_pass = (
        db.query(func.sum(DmarcRecord.count))
        .join(DmarcReport)
        .filter(
            DmarcReport.organization_id == org_id,
            DmarcReport.created_at >= thirty_days_ago,
            DmarcRecord.spf_aligned.is_(True),
        )
        .scalar() or 0
    )
    dkim_pass = (
        db.query(func.sum(DmarcRecord.count))
        .join(DmarcReport)
        .filter(
            DmarcReport.organization_id == org_id,
            DmarcReport.created_at >= thirty_days_ago,
            DmarcRecord.dkim_aligned.is_(True),
        )
        .scalar() or 0
    )

    # Unknown sources
    unknown_ips = (
        db.query(func.count(SourceIp.id))
        .filter_by(organization_id=org_id, classification="unknown")
        .scalar() or 0
    )
    suspicious_ips = (
        db.query(func.count(SourceIp.id))
        .filter_by(organization_id=org_id, classification="suspicious")
        .scalar() or 0
    )

    # Active alerts
    active_alerts = (
        db.query(func.count(AlertEvent.id))
        .filter_by(organization_id=org_id, status="open")
        .scalar() or 0
    )

    # Recent imports (last 10)
    recent_imports = (
        db.query(ImportJob)
        .filter_by(organization_id=org_id)
        .order_by(ImportJob.created_at.desc())
        .limit(settings.UI_RECENT_LIMIT)
        .all()
    )

    # Recent SMTP messages (last 5)
    recent_smtp = (
        db.query(SmtpInboundMessage)
        .filter_by(organization_id=org_id)
        .order_by(SmtpInboundMessage.received_at.desc())
        .limit(settings.UI_RECENT_LIMIT)
        .all()
    )

    # SMTP rejections last 24h
    rejections_24h = (
        db.query(func.count(SmtpInboundRejection.id))
        .filter(SmtpInboundRejection.created_at >= now - timedelta(hours=24))
        .scalar() or 0
    )

    # Import errors (last 7 days)
    import_errors = (
        db.query(func.count(ImportJob.id))
        .filter_by(organization_id=org_id, status="failed")
        .filter(ImportJob.created_at >= seven_days_ago)
        .scalar() or 0
    )

    # Domains without recent reports (7 days)
    domains_no_reports = []
    all_domains = db.query(Domain).filter_by(organization_id=org_id, is_active=True).all()
    for d in all_domains:
        recent = (
            db.query(DmarcReport.id)
            .filter_by(organization_id=org_id, domain_id=d.id)
            .filter(DmarcReport.created_at >= seven_days_ago)
            .first()
        )
        if not recent:
            domains_no_reports.append(d)

    return {
        "domain_count": domain_count,
        "report_count": report_count,
        "total_messages_30d": total_msgs,
        "pass_messages_30d": pass_msgs,
        "fail_messages_30d": fail_msgs,
        "pass_rate_30d": pass_rate,
        "spf_pass_30d": int(spf_pass),
        "dkim_pass_30d": int(dkim_pass),
        "unknown_ips": unknown_ips,
        "suspicious_ips": suspicious_ips,
        "active_alerts": active_alerts,
        "recent_imports": recent_imports,
        "recent_smtp": recent_smtp,
        "rejections_24h": rejections_24h,
        "import_errors_7d": import_errors,
        "domains_no_reports": domains_no_reports,
    }


def get_pass_fail_over_time(db: Session, org_id: str, domain_id: str | None = None, days: int = 30) -> list[dict]:
    """Daily DMARC pass/fail message counts by the day the reported traffic happened (UTC)."""
    since = datetime.now(UTC) - timedelta(days=days)
    day_of = func.coalesce(DmarcReport.period_begin, DmarcReport.created_at)

    reports_q = db.query(DmarcReport).filter(DmarcReport.organization_id == org_id, day_of >= since)
    if domain_id:
        reports_q = reports_q.filter(DmarcReport.domain_id == domain_id)

    by_day: dict[str, dict] = defaultdict(lambda: {"pass": 0, "fail": 0})
    for rpt in reports_q.all():
        moment = rpt.period_begin or rpt.created_at
        if moment is None:
            continue
        if moment.tzinfo is not None:
            moment = moment.astimezone(UTC)
        day = moment.strftime("%Y-%m-%d")
        by_day[day]["pass"] += rpt.pass_count or 0
        by_day[day]["fail"] += rpt.fail_count or 0

    return [{"date": d, "pass": v["pass"], "fail": v["fail"]} for d, v in sorted(by_day.items())]


def get_disposition_counts(db: Session, org_id: str, days: int = 30) -> dict[str, int]:
    """Messages per receiver disposition (none, pass, quarantine, reject) in the last `days` days."""
    since = datetime.now(UTC) - timedelta(days=days)
    rows = (
        db.query(DmarcRecord.disposition, func.sum(DmarcRecord.count))
        .join(DmarcReport)
        .filter(DmarcReport.organization_id == org_id, DmarcReport.created_at >= since)
        .group_by(DmarcRecord.disposition)
        .all()
    )
    return {disposition or "none": int(total or 0) for disposition, total in rows}


def get_top_source_ips(db: Session, org_id: str, limit: int = 10) -> list[dict]:
    rows = (
        db.query(SourceIp)
        .filter_by(organization_id=org_id)
        .order_by(SourceIp.total_messages.desc())
        .limit(limit)
        .all()
    )
    from app.services.senders import sender_label

    return [
        {
            "id": s.id,
            "ip": s.ip_address,
            "sender": sender_label(s),
            "total": s.total_messages,
            "pass_rate": s.pass_rate,
            "classification": s.classification,
        }
        for s in rows
    ]
