
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_org, get_current_user
from app.models import DmarcRecord, DmarcReport, Domain, Organization, User
from app.templates_config import templates

router = APIRouter(prefix="/reports", tags=["reports"])


def _paginate(q, page: int, per_page: int = 25):
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, (total + per_page - 1) // per_page


@router.get("", response_class=HTMLResponse)
def report_list(
    request: Request,
    page: int = Query(1, ge=1),
    domain_id: str | None = Query(None),
    search: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = (
        db.query(DmarcReport)
        .filter_by(organization_id=org.id)
        .order_by(DmarcReport.created_at.desc())
    )
    if domain_id:
        q = q.filter_by(domain_id=domain_id)
    if search:
        q = q.filter(DmarcReport.policy_domain.ilike(f"%{search}%"))

    reports, total, pages = _paginate(q, page)
    domains = db.query(Domain).filter_by(organization_id=org.id, is_active=True).all()

    return templates.TemplateResponse("reports/index.html", {
        "request": request, "user": user, "org": org,
        "reports": reports, "total": total, "page": page, "pages": pages,
        "domains": domains, "selected_domain_id": domain_id, "search": search or "",
        "page_title": "DMARC Reports",
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

    per_page = 50
    records_q = db.query(DmarcRecord).filter_by(report_id=report_id).order_by(
        DmarcRecord.count.desc()
    )
    total_records = records_q.count()
    records = records_q.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total_records + per_page - 1) // per_page

    domain = db.query(Domain).filter_by(id=report.domain_id).first() if report.domain_id else None

    return templates.TemplateResponse("reports/detail.html", {
        "request": request, "user": user, "org": org,
        "report": report, "domain": domain,
        "records": records, "total_records": total_records,
        "page": page, "pages": pages,
        "page_title": f"Report: {report.report_id[:30]}",
    })
