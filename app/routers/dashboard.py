from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_org, get_current_user
from app.models import Organization, User
from app.services.charts import day_chart
from app.services.dashboard import (
    get_dashboard_stats,
    get_disposition_counts,
    get_pass_fail_over_time,
    get_top_source_ips,
)
from app.services.report_formats import format_counts
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
    days = settings.UI_CHART_DAYS
    stats = get_dashboard_stats(db, org.id)
    chart = day_chart(get_pass_fail_over_time(db, org.id, days=days), days, datetime.now(UTC).date())
    since = datetime.now(UTC) - timedelta(days=days)

    return templates.TemplateResponse(request, "dashboard/index.html", {
        "user": user,
        "org": org,
        "stats": stats,
        "chart": chart,
        "chart_days": days,
        "top_ips": get_top_source_ips(db, org.id, limit=settings.UI_RECENT_LIMIT),
        "formats": format_counts(db, org.id, since=since),
        "dispositions": get_disposition_counts(db, org.id, days=days),
        "page_title": "Übersicht",
    })
