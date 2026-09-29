from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_org, get_current_user
from app.models import Organization, User
from app.services.report_formats import EVIDENCE_TEXT, format_counts, reporter_formats
from app.templates_config import templates

router = APIRouter(prefix="/hilfe", tags=["help"])


@router.get("/dmarc-formate", response_class=HTMLResponse)
def dmarc_formats(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    return templates.TemplateResponse(request, "help/dmarc_formats.html", {
        "user": user, "org": org,
        "reporters": reporter_formats(db, org.id),
        "formats": format_counts(db, org.id),
        "evidence_text": EVIDENCE_TEXT,
        "page_title": "DMARC-Formate",
    })
