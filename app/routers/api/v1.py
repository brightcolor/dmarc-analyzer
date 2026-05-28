"""
REST API v1 — authenticated with Bearer API tokens.
"""
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_api_auth
from app.models import AlertEvent, Domain, DmarcRecord, DmarcReport, InboundMailAddress, Organization, SourceIp, User
from app.version import APP_NAME, VERSION

router = APIRouter(prefix="/api/v1", tags=["api_v1"])


def _org_or_403(api_auth) -> Organization:
    _, org = api_auth
    if not org:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return org


@router.get("/health")
def health():
    return {"status": "ok", "version": VERSION, "app": APP_NAME}


@router.get("/version")
def version():
    return {"version": VERSION, "app": APP_NAME}


@router.get("/me")
def me(
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    _, org = api_auth
    return {
        "organization": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
        }
    }


@router.get("/domains")
def list_domains(
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    org = _org_or_403(api_auth)
    domains = db.query(Domain).filter_by(organization_id=org.id, is_active=True).all()
    return [
        {
            "id": d.id,
            "name": d.name,
            "policy": d.dmarc_policy,
            "last_report_at": d.last_report_at.isoformat() if d.last_report_at else None,
        }
        for d in domains
    ]


@router.get("/domains/{domain_id}/stats")
def domain_stats(
    domain_id: str,
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    org = _org_or_403(api_auth)
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)

    from app.services.dashboard import get_pass_fail_over_time
    chart = get_pass_fail_over_time(db, org.id, domain_id=domain_id, days=days)
    return {"domain": domain.name, "stats": chart}


@router.get("/reports")
def list_reports(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    domain_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    org = _org_or_403(api_auth)
    q = db.query(DmarcReport).filter_by(organization_id=org.id).order_by(DmarcReport.created_at.desc())
    if domain_id:
        q = q.filter_by(domain_id=domain_id)

    total = q.count()
    reports = q.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "results": [
            {
                "id": r.id,
                "report_id": r.report_id,
                "domain": r.policy_domain,
                "period_begin": r.period_begin.isoformat() if r.period_begin else None,
                "period_end": r.period_end.isoformat() if r.period_end else None,
                "total_messages": r.total_messages,
                "pass_count": r.pass_count,
                "fail_count": r.fail_count,
                "pass_rate": r.pass_rate,
                "reporting_org": r.reporting_org,
                "created_at": r.created_at.isoformat(),
            }
            for r in reports
        ],
    }


@router.get("/source-ips")
def list_source_ips(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    classification: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    org = _org_or_403(api_auth)
    q = db.query(SourceIp).filter_by(organization_id=org.id).order_by(SourceIp.total_messages.desc())
    if classification:
        q = q.filter_by(classification=classification)

    total = q.count()
    ips = q.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "results": [
            {
                "id": s.id,
                "ip": s.ip_address,
                "classification": s.classification,
                "total_messages": s.total_messages,
                "pass_rate": s.pass_rate,
                "first_seen": s.first_seen_at.isoformat() if s.first_seen_at else None,
                "last_seen": s.last_seen_at.isoformat() if s.last_seen_at else None,
            }
            for s in ips
        ],
    }


@router.get("/alerts/events")
def list_alert_events(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    event_status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    org = _org_or_403(api_auth)
    q = db.query(AlertEvent).filter_by(organization_id=org.id).order_by(AlertEvent.created_at.desc())
    if event_status:
        q = q.filter_by(status=event_status)

    total = q.count()
    events = q.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "results": [
            {
                "id": e.id,
                "type": e.alert_type,
                "severity": e.severity,
                "title": e.title,
                "status": e.status,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }


@router.post("/alerts/events/{event_id}/acknowledge")
def ack_event(
    event_id: str,
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    org = _org_or_403(api_auth)
    event = db.query(AlertEvent).filter_by(id=event_id, organization_id=org.id).first()
    if not event:
        raise HTTPException(status_code=404)
    from app.security import utcnow
    event.status = "acknowledged"
    event.acknowledged_at = utcnow()
    db.commit()
    return {"status": "acknowledged"}


@router.get("/inbound-addresses")
def list_inbound_addresses(
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    org = _org_or_403(api_auth)
    addrs = db.query(InboundMailAddress).filter_by(organization_id=org.id).all()
    return [
        {
            "id": a.id,
            "address": a.address,
            "status": a.status,
            "purpose": a.purpose,
            "domain_id": a.domain_id,
        }
        for a in addrs
    ]


@router.get("/smtp/status")
def smtp_status_api(api_auth=Depends(get_api_auth)):
    from app.config import settings
    return {
        "enabled": settings.SMTP_INBOUND_ENABLED,
        "domain": settings.SMTP_INBOUND_DOMAIN,
        "port": settings.SMTP_INBOUND_PORT,
        "tls": settings.SMTP_INBOUND_TLS_ENABLED,
    }
