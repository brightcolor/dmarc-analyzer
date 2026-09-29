from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session, selectinload

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_org, get_current_user
from app.models import DmarcRecord, DmarcReport, Domain, Organization, User
from app.services.dmarc_parser import FORMAT_RFC7489, FORMAT_RFC9990
from app.templates_config import templates

router = APIRouter(prefix="/reports", tags=["reports"])

FORMAT_FILTERS = {FORMAT_RFC7489, FORMAT_RFC9990, "unknown"}


def _paginate(q, page: int, per_page: int):
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, (total + per_page - 1) // per_page


@router.get("", response_class=HTMLResponse)
def report_list(
    request: Request,
    page: int = Query(1, ge=1),
    domain_id: str | None = Query(None),
    search: str | None = Query(None),
    report_format: str | None = Query(None, alias="format"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(DmarcReport).filter_by(organization_id=org.id).order_by(DmarcReport.created_at.desc())
    if domain_id:
        q = q.filter_by(domain_id=domain_id)
    if search:
        q = q.filter(DmarcReport.policy_domain.ilike(f"%{search}%"))
    if report_format in FORMAT_FILTERS:
        if report_format == "unknown":
            q = q.filter(DmarcReport.report_format.is_(None))
        else:
            q = q.filter(DmarcReport.report_format == report_format)

    reports, total, pages = _paginate(q, page, settings.UI_PAGE_SIZE)
    domains = db.query(Domain).filter_by(organization_id=org.id, is_active=True).order_by(Domain.name).all()

    return templates.TemplateResponse(request, "reports/index.html", {
        "user": user, "org": org,
        "reports": reports, "total": total, "page": page, "pages": pages,
        "domains": domains, "selected_domain_id": domain_id, "search": search or "",
        "selected_format": report_format if report_format in FORMAT_FILTERS else "",
        "page_title": "Berichte",
    })


@router.get("/{report_id}", response_class=HTMLResponse)
def report_detail(
    request: Request,
    report_id: str,
    page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    report = db.query(DmarcReport).filter_by(id=report_id, organization_id=org.id).first()
    if not report:
        raise HTTPException(status_code=404)

    records_q = (
        db.query(DmarcRecord)
        .filter_by(report_id=report_id, organization_id=org.id)
        .options(selectinload(DmarcRecord.auth_results))
        .order_by(DmarcRecord.count.desc())
    )
    records, total_records, pages = _paginate(records_q, page, settings.UI_RECORDS_PAGE_SIZE)
    domain = None
    if report.domain_id:
        domain = db.query(Domain).filter_by(id=report.domain_id, organization_id=org.id).first()

    return templates.TemplateResponse(request, "reports/detail.html", {
        "user": user, "org": org,
        "report": report, "domain": domain,
        "records": records, "total_records": total_records,
        "page": page, "pages": pages,
        "page_title": f"Bericht von {report.reporting_org or 'unbekanntem Absender'}",
    })
