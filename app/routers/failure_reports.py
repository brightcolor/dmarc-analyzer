from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_client_ip, get_current_manager, get_current_org, get_current_user
from app.models import DmarcFailureReport, Domain, Organization, User
from app.services.audit import log_action
from app.templates_config import flash, templates

router = APIRouter(prefix="/failure-reports", tags=["failure-reports"])

# Checks a report can name in Auth-Failure (RFC 6591, 3.1)
CHECK_FILTERS = ("dmarc", "dkim", "spf")


def _own_report(db: Session, org: Organization, report_id: str) -> DmarcFailureReport:
    report = db.query(DmarcFailureReport).filter_by(id=report_id, organization_id=org.id).first()
    if not report:
        raise HTTPException(status_code=404)
    return report


@router.get("", response_class=HTMLResponse)
def failure_report_list(
    request: Request,
    page: int = Query(1, ge=1),
    domain_id: str | None = Query(None),
    search: str | None = Query(None),
    check: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(DmarcFailureReport).filter_by(organization_id=org.id)
    if domain_id:
        q = q.filter_by(domain_id=domain_id)
    if search and search.strip():
        term = f"%{search.strip()}%"
        q = q.filter(or_(DmarcFailureReport.reported_domain.ilike(term), DmarcFailureReport.source_ip.ilike(term),
                         DmarcFailureReport.header_from.ilike(term)))
    if check in CHECK_FILTERS:
        q = q.filter(DmarcFailureReport.auth_failure.ilike(f"%{check}%"))

    total = q.count()
    reports = (q.order_by(DmarcFailureReport.created_at.desc())
               .offset((page - 1) * settings.UI_PAGE_SIZE).limit(settings.UI_PAGE_SIZE).all())
    pages = (total + settings.UI_PAGE_SIZE - 1) // settings.UI_PAGE_SIZE
    domains = db.query(Domain).filter_by(organization_id=org.id, is_active=True).order_by(Domain.name).all()

    return templates.TemplateResponse(request, "failure_reports/index.html", {
        "user": user, "org": org,
        "reports": reports, "total": total, "page": page, "pages": pages,
        "domains": domains, "selected_domain_id": domain_id, "search": (search or "").strip(),
        "selected_check": check if check in CHECK_FILTERS else "",
        "retention_days": min(org.report_retention_days, settings.FAILURE_REPORT_RETENTION_DAYS),
        "page_title": "Fehlerberichte",
    })


@router.get("/{report_id}", response_class=HTMLResponse)
def failure_report_detail(
    request: Request,
    report_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    report = _own_report(db, org, report_id)
    return templates.TemplateResponse(request, "failure_reports/detail.html", {
        "user": user, "org": org, "report": report,
        "retention_days": min(org.report_retention_days, settings.FAILURE_REPORT_RETENTION_DAYS),
        "page_title": f"Fehlerbericht für {report.reported_domain or 'unbekannte Domain'}",
    })


@router.post("/{report_id}/delete")
def delete_failure_report(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    report = _own_report(db, org, report_id)
    log_action(db, "failure_report.delete", org_id=org.id, user_id=user.id, resource_type="failure_report",
               resource_id=report.id, old_value={"domain": report.reported_domain, "source_ip": report.source_ip},
               ip_address=get_client_ip(request))
    db.delete(report)
    db.commit()
    flash(request, "ok", "Fehlerbericht gelöscht", "Der Bericht und die gespeicherten Kopfzeilen sind entfernt.")
    return RedirectResponse(url="/failure-reports", status_code=303)
