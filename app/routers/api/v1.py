"""
REST API v1 — authenticated with Bearer API tokens.
"""
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.dependencies import get_api_auth, get_client_ip
from app.models import (
    AlertEvent,
    DmarcFailureReport,
    DmarcReport,
    Domain,
    InboundMailAddress,
    Organization,
    SourceIp,
    TlsReport,
    TlsReportPolicy,
)
from app.services.audit import log_action
from app.services.dns_check import run_check, stored_result
from app.services.domains import INVALID_NAME, DomainLimitReached, create_domain, normalize_domain
from app.services.senders import load_catalog
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
            "dns_status": d.dns_status,
            "dns_checked_at": d.dns_checked_at.isoformat() if d.dns_checked_at else None,
        }
        for d in domains
    ]


class DomainIn(BaseModel):
    name: str


def _require_role(db: Session, api_auth, minimum: str, what: str) -> None:
    """The account behind a token needs the same role as in the web interface."""
    user, org = api_auth
    if user is None:
        return
    from app.services.auth import ROLE_LEVEL, ROLE_NAMES, role_level
    if role_level(db, user, org.id) < ROLE_LEVEL[minimum]:
        raise HTTPException(status_code=403, detail=f"{what} dürfen Konten ab der Rolle {ROLE_NAMES[minimum]}. "
                            "Lege das Token mit einem solchen Konto an.")


@router.post("/domains", status_code=201)
def create_domain_api(
    payload: DomainIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    """Create a domain with its report address; an existing domain comes back with status 200."""
    org = _org_or_403(api_auth)
    _require_role(db, api_auth, "manager", "Domains anlegen")
    name = normalize_domain(payload.name)
    if not name:
        raise HTTPException(status_code=400, detail=INVALID_NAME)
    try:
        domain, address, created = create_domain(db, org, name)
    except DomainLimitReached as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if created:
        user = api_auth[0]
        log_action(db, "domain.create", org_id=org.id, user_id=user.id if user else None, resource_type="domain",
                   resource_id=domain.id, new_value={"name": name, "via": "api"}, ip_address=get_client_ip(request))
    db.commit()
    if not created:
        response.status_code = 200
    return {
        "id": domain.id,
        "name": domain.name,
        "is_active": domain.is_active,
        "created": created,
        "inbound_address": address.address,
        "rua": f"mailto:{address.address}",
    }


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


def _dns_check_json(domain: Domain) -> dict:
    result = stored_result(domain)
    return {
        "domain": domain.name,
        "status": domain.dns_status,
        "checked_at": domain.dns_checked_at.isoformat() if domain.dns_checked_at else None,
        "checks": [asdict(check) for check in result.checks] if result else [],
    }


@router.get("/domains/{domain_id}/dns-check")
def domain_dns_check(
    domain_id: str,
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    """Result of the last DNS check of a domain; status is null while it was never checked."""
    org = _org_or_403(api_auth)
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)
    return _dns_check_json(domain)


@router.post("/domains/{domain_id}/dns-check")
def run_domain_dns_check(
    domain_id: str,
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    """Check the DNS of a domain now, for example right after changing a record."""
    org = _org_or_403(api_auth)
    _require_role(db, api_auth, "analyst", "Die DNS-Prüfung starten")
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)
    run_check(db, domain)
    db.commit()
    return _dns_check_json(domain)


@router.get("/reports")
def list_reports(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    domain_id: str | None = Query(None),
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
                "report_format": r.report_format,
                "format_evidence": r.format_evidence.split(",") if r.format_evidence else [],
                "policy": {
                    "p": r.policy_p, "sp": r.policy_sp, "np": r.policy_np, "pct": r.policy_pct,
                    "testing": r.policy_testing, "discovery_method": r.policy_discovery_method,
                },
                "created_at": r.created_at.isoformat(),
            }
            for r in reports
        ],
    }


@router.get("/failure-reports")
def list_failure_reports(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    domain_id: str | None = Query(None),
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    """Failure reports (ruf), newest first. The header of the reported mail stays in the web interface."""
    org = _org_or_403(api_auth)
    q = db.query(DmarcFailureReport).filter_by(organization_id=org.id).order_by(DmarcFailureReport.created_at.desc())
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
                "domain": r.reported_domain,
                "domain_id": r.domain_id,
                "source_ip": r.source_ip,
                "auth_failure": r.failed_checks,
                "identity_alignment": r.identity_alignment,
                "delivery_result": r.delivery_result,
                "arrival_date": r.arrival_date.isoformat() if r.arrival_date else None,
                "incidents": r.incidents,
                "header_from": r.header_from,
                "dkim_domain": r.dkim_domain,
                "dkim_selector": r.dkim_selector,
                "reporter": r.reporter,
                "created_at": r.created_at.isoformat(),
            }
            for r in reports
        ],
    }


@router.get("/tls-reports")
def list_tls_reports(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    domain_id: str | None = Query(None),
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    """TLS reports (TLS-RPT, RFC 8460), newest first, with their policies and failure details."""
    org = _org_or_403(api_auth)
    q = (db.query(TlsReport).options(selectinload(TlsReport.policies).selectinload(TlsReportPolicy.failures))
         .filter_by(organization_id=org.id).order_by(TlsReport.created_at.desc()))
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
                "domain_id": r.domain_id,
                "organization_name": r.organization_name,
                "contact_info": r.contact_info,
                "period_begin": r.period_begin.isoformat() if r.period_begin else None,
                "period_end": r.period_end.isoformat() if r.period_end else None,
                "successful_sessions": r.successful_sessions,
                "failed_sessions": r.failed_sessions,
                "failure_details_omitted": r.failure_details_omitted,
                "policies": [
                    {
                        "policy_type": p.policy_type,
                        "policy_domain": p.policy_domain,
                        "policy_string": p.policy_lines,
                        "mx_host": p.mx_host_list,
                        "successful_sessions": p.successful_sessions,
                        "failed_sessions": p.failed_sessions,
                        "failure_details": [
                            {
                                "result_type": f.result_type,
                                "sending_mta_ip": f.sending_mta_ip,
                                "receiving_mx_hostname": f.receiving_mx_hostname,
                                "receiving_mx_helo": f.receiving_mx_helo,
                                "receiving_ip": f.receiving_ip,
                                "failed_sessions": f.failed_sessions,
                                "failure_reason_code": f.failure_reason_code,
                                "additional_information": f.additional_information,
                            }
                            for f in p.failures
                        ],
                    }
                    for p in r.policies
                ],
                "created_at": r.created_at.isoformat(),
            }
            for r in reports
        ],
    }


@router.get("/source-ips")
def list_source_ips(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    classification: str | None = Query(None),
    db: Session = Depends(get_db),
    api_auth=Depends(get_api_auth),
):
    org = _org_or_403(api_auth)
    q = db.query(SourceIp).filter_by(organization_id=org.id).order_by(SourceIp.total_messages.desc())
    if classification:
        q = q.filter_by(classification=classification)

    total = q.count()
    ips = q.offset((page - 1) * per_page).limit(per_page).all()
    catalog = load_catalog()
    return {
        "total": total,
        "results": [
            {
                "id": s.id,
                "ip": s.ip_address,
                "classification": s.classification,
                "sender": s.sender_key,
                "sender_name": catalog.name(s.sender_key),
                "reverse_dns": s.reverse_dns,
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
    event_status: str | None = Query(None),
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
    token_user = api_auth[0]
    if token_user is not None:
        from app.services.auth import ROLE_LEVEL, role_level
        if role_level(db, token_user, org.id) < ROLE_LEVEL["analyst"]:
            raise HTTPException(status_code=403, detail="Das Token gehört zu einem Konto mit Lesezugriff. Alarme "
                                "bestätigen dürfen Konten ab der Rolle Analyst.")
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
