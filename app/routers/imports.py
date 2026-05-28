from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, get_current_org
from app.models import ImportError, ImportJob, Organization, User
from app.templates_config import templates

router = APIRouter(prefix="/imports", tags=["imports"])


@router.get("", response_class=HTMLResponse)
def import_list(
    request: Request,
    page: int = Query(1, ge=1),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(ImportJob).filter_by(organization_id=org.id).order_by(ImportJob.created_at.desc())
    if status:
        q = q.filter_by(status=status)

    per_page = 25
    total = q.count()
    jobs = q.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page

    return templates.TemplateResponse("imports/index.html", {
        "request": request, "user": user, "org": org,
        "jobs": jobs, "total": total, "page": page, "pages": pages,
        "status_filter": status, "page_title": "Import Jobs",
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

    return templates.TemplateResponse("imports/detail.html", {
        "request": request, "user": user, "org": org,
        "job": job, "errors": errors, "page_title": f"Import Job",
    })
