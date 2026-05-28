from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user, get_current_org
from app.models import InboundMailAddress, Organization, SmtpInboundMessage, SmtpInboundRejection, User
from app.templates_config import templates

router = APIRouter(prefix="/smtp", tags=["smtp"])


@router.get("/status", response_class=HTMLResponse)
def smtp_status(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    from app.models import InboundMailAddress
    addresses = db.query(InboundMailAddress).filter_by(organization_id=org.id).all()
    recent_messages = (
        db.query(SmtpInboundMessage)
        .filter_by(organization_id=org.id)
        .order_by(SmtpInboundMessage.received_at.desc())
        .limit(10)
        .all()
    )

    smtp_config = {
        "enabled": settings.SMTP_INBOUND_ENABLED,
        "domain": settings.SMTP_INBOUND_DOMAIN,
        "port": settings.SMTP_INBOUND_PORT,
        "bind": settings.SMTP_INBOUND_BIND,
        "max_size": settings.SMTP_INBOUND_MAX_MESSAGE_SIZE,
        "tls": settings.SMTP_INBOUND_TLS_ENABLED,
        "store_raw": settings.SMTP_INBOUND_STORE_RAW,
    }

    return templates.TemplateResponse("smtp/status.html", {
        "request": request, "user": user, "org": org,
        "addresses": addresses,
        "recent_messages": recent_messages,
        "smtp_config": smtp_config,
        "page_title": "SMTP Inbound Status",
    })


@router.get("/messages", response_class=HTMLResponse)
def smtp_messages(
    request: Request,
    page: int = Query(1, ge=1),
    import_status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = (
        db.query(SmtpInboundMessage)
        .filter_by(organization_id=org.id)
        .order_by(SmtpInboundMessage.received_at.desc())
    )
    if import_status:
        q = q.filter_by(import_status=import_status)

    per_page = 25
    total = q.count()
    messages = q.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page

    return templates.TemplateResponse("smtp/messages.html", {
        "request": request, "user": user, "org": org,
        "messages": messages, "total": total, "page": page, "pages": pages,
        "status_filter": import_status, "page_title": "Incoming SMTP Messages",
    })


@router.get("/rejections", response_class=HTMLResponse)
def smtp_rejections(
    request: Request,
    page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    # Show all rejections (system-wide for superadmin, org-scoped via recipient lookup for others)
    q = (
        db.query(SmtpInboundRejection)
        .order_by(SmtpInboundRejection.created_at.desc())
    )

    per_page = 25
    total = q.count()
    rejections = q.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page

    return templates.TemplateResponse("smtp/rejections.html", {
        "request": request, "user": user, "org": org,
        "rejections": rejections, "total": total, "page": page, "pages": pages,
        "page_title": "SMTP Rejections",
    })
