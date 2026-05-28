from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_org, get_current_user
from app.models import Organization, User
from app.services.dashboard import get_dashboard_stats, get_pass_fail_over_time, get_top_source_ips
from app.templates_config import templates

router = APIRouter(tags=["dashboard"])


@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    stats = get_dashboard_stats(db, org.id)
    chart_data = get_pass_fail_over_time(db, org.id, days=30)
    top_ips = get_top_source_ips(db, org.id, limit=8)

    return templates.TemplateResponse("dashboard/index.html", {
        "request": request,
        "user": user,
        "org": org,
        "stats": stats,
        "chart_data": chart_data,
        "top_ips": top_ips,
        "page_title": "Dashboard",
    })
