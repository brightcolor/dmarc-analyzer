from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session, selectinload

from app.config import settings
from app.database import get_db
from app.dependencies import get_client_ip, get_current_manager, get_current_org, get_current_user
from app.models import Domain, Organization, TlsReport, TlsReportPolicy, User
from app.services.audit import log_action
from app.templates_config import flash, templates

router = APIRouter(prefix="/tls-reports", tags=["tls-reports"])

# Filter by outcome: reports with failed sessions or without
OUTCOME_FILTERS = ("failed", "clean")


def _own_report(db: Session, org: Organization, report_id: str) -> TlsReport:
    report = (db.query(TlsReport).options(selectinload(TlsReport.policies).selectinload(TlsReportPolicy.failures))
              .filter_by(id=report_id, organization_id=org.id).first())
    if not report:
        raise HTTPException(status_code=404)
    return report


@router.get("", response_class=HTMLResponse)
def tls_report_list(
    request: Request,
    page: int = Query(1, ge=1),
    domain_id: str | None = Query(None),
    search: str | None = Query(None),
    outcome: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(TlsReport).filter_by(organization_id=org.id)
    if domain_id:
        q = q.filter_by(domain_id=domain_id)
    if search and search.strip():
        term = f"%{search.strip()}%"
        q = q.filter(or_(TlsReport.policy_domain.ilike(term), TlsReport.organization_name.ilike(term),
                         TlsReport.contact_info.ilike(term)))
    if outcome == "failed":
        q = q.filter(TlsReport.failed_sessions > 0)
    elif outcome == "clean":
        q = q.filter(TlsReport.failed_sessions == 0)

    total = q.count()
    reports = (q.order_by(TlsReport.created_at.desc())
               .offset((page - 1) * settings.UI_PAGE_SIZE).limit(settings.UI_PAGE_SIZE).all())
    pages = (total + settings.UI_PAGE_SIZE - 1) // settings.UI_PAGE_SIZE
    domains = db.query(Domain).filter_by(organization_id=org.id, is_active=True).order_by(Domain.name).all()

    return templates.TemplateResponse(request, "tls_reports/index.html", {
        "user": user, "org": org,
        "reports": reports, "total": total, "page": page, "pages": pages,
        "domains": domains, "selected_domain_id": domain_id, "search": (search or "").strip(),
        "selected_outcome": outcome if outcome in OUTCOME_FILTERS else "",
        "retention_days": org.report_retention_days,
        "page_title": "TLS-Berichte",
    })


@router.get("/{report_id}", response_class=HTMLResponse)
def tls_report_detail(
    request: Request,
    report_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    report = _own_report(db, org, report_id)
    return templates.TemplateResponse(request, "tls_reports/detail.html", {
        "user": user, "org": org, "report": report,
        "retention_days": org.report_retention_days,
        "page_title": f"TLS-Bericht für {report.policy_domain or 'unbekannte Domain'}",
    })


@router.post("/{report_id}/delete")
def delete_tls_report(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    report = _own_report(db, org, report_id)
    log_action(db, "tls_report.delete", org_id=org.id, user_id=user.id, resource_type="tls_report",
               resource_id=report.id, old_value={"domain": report.policy_domain, "report_id": report.report_id,
                                                 "reporter": report.organization_name},
               ip_address=get_client_ip(request))
    db.delete(report)
    db.commit()
    flash(request, "ok", "TLS-Bericht gelöscht", "Der Bericht mit seinen Richtlinien und Fehlerangaben ist entfernt.")
    return RedirectResponse(url="/tls-reports", status_code=303)
