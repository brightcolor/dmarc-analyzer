from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_org, get_current_user
from app.models import DmarcReport, ImportError, ImportJob, Organization, User
from app.templates_config import templates

router = APIRouter(prefix="/imports", tags=["imports"])

STATUS_FILTERS = ("completed", "failed", "processing", "pending")


@router.get("", response_class=HTMLResponse)
def import_list(
    request: Request,
    page: int = Query(1, ge=1),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(ImportJob).filter_by(organization_id=org.id).order_by(ImportJob.created_at.desc())
    if status in STATUS_FILTERS:
        q = q.filter_by(status=status)

    per_page = settings.UI_PAGE_SIZE
    total = q.count()
    jobs = q.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page

    return templates.TemplateResponse(request, "imports/index.html", {
        "user": user, "org": org,
        "jobs": jobs, "total": total, "page": page, "pages": pages,
        "status_filter": status if status in STATUS_FILTERS else "", "status_filters": STATUS_FILTERS,
        "page_title": "Importe",
    })


@router.get("/{job_id}", response_class=HTMLResponse)
def import_detail(
    request: Request,
    job_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    job = db.query(ImportJob).filter_by(id=job_id, organization_id=org.id).first()
    if not job:
        raise HTTPException(status_code=404)

    errors = db.query(ImportError).filter_by(job_id=job_id).all()
    reports = (
        db.query(DmarcReport)
        .filter_by(import_job_id=job_id, organization_id=org.id)
        .order_by(DmarcReport.period_end.desc())
        .limit(settings.UI_PAGE_SIZE)
        .all()
    )
    return templates.TemplateResponse(request, "imports/detail.html", {
        "user": user, "org": org,
        "job": job, "errors": errors, "reports": reports,
        "page_title": job.file_name or "Import",
    })
