from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_org, get_current_superadmin, get_current_user
from app.models import (
    InboundMailAddress,
    Organization,
    SmtpInboundMessage,
    SmtpInboundRejection,
    User,
)
from app.templates_config import templates

router = APIRouter(prefix="/smtp", tags=["smtp"])

MESSAGE_STATUSES = ("completed", "processing", "quarantine", "failed")


@router.get("/status", response_class=HTMLResponse)
def smtp_status(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    addresses = db.query(InboundMailAddress).filter_by(organization_id=org.id).order_by(
        InboundMailAddress.created_at).all()
    recent_messages = (
        db.query(SmtpInboundMessage)
        .filter_by(organization_id=org.id)
        .order_by(SmtpInboundMessage.received_at.desc())
        .limit(settings.UI_RECENT_LIMIT)
        .all()
    )
    smtp_config = {
        "enabled": settings.SMTP_INBOUND_ENABLED,
        "domain": settings.SMTP_INBOUND_DOMAIN,
        "port": settings.SMTP_INBOUND_PORT,
        "max_size": settings.SMTP_INBOUND_MAX_MESSAGE_SIZE,
        "tls": settings.SMTP_INBOUND_TLS_ENABLED,
        "store_raw": settings.SMTP_INBOUND_STORE_RAW,
        "raw_retention_days": settings.SMTP_INBOUND_RAW_RETENTION_DAYS,
    }
    return templates.TemplateResponse(request, "smtp/status.html", {
        "user": user, "org": org,
        "addresses": addresses, "recent_messages": recent_messages, "smtp_config": smtp_config,
        "page_title": "Empfang",
    })


@router.get("/messages", response_class=HTMLResponse)
def smtp_messages(
    request: Request,
    page: int = Query(1, ge=1),
    import_status: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(SmtpInboundMessage).filter_by(organization_id=org.id).order_by(
        SmtpInboundMessage.received_at.desc())
    if import_status in MESSAGE_STATUSES:
        q = q.filter_by(import_status=import_status)

    per_page = settings.UI_PAGE_SIZE
    total = q.count()
    messages = q.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page

    return templates.TemplateResponse(request, "smtp/messages.html", {
        "user": user, "org": org,
        "messages": messages, "total": total, "page": page, "pages": pages,
        "status_filter": import_status if import_status in MESSAGE_STATUSES else "",
        "statuses": MESSAGE_STATUSES, "page_title": "Eingegangene Mails",
    })


@router.get("/rejections", response_class=HTMLResponse)
def smtp_rejections(
    request: Request,
    page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_superadmin),
    org: Organization = Depends(get_current_org),
):
    # Rejected recipients belong to no organisation; only the operator sees them
    q = db.query(SmtpInboundRejection).order_by(SmtpInboundRejection.created_at.desc())

    per_page = settings.UI_PAGE_SIZE
    total = q.count()
    rejections = q.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page

    return templates.TemplateResponse(request, "smtp/rejections.html", {
        "user": user, "org": org,
        "rejections": rejections, "total": total, "page": page, "pages": pages,
        "page_title": "Abgelehnte Empfänger",
    })
