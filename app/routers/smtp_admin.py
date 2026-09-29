from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_org, get_current_superadmin, get_current_user
from app.models import (
    DmarcFailureReport,
    InboundMailAddress,
    Organization,
    SchedulerRun,
    SmtpInboundMessage,
    SmtpInboundRejection,
    TlsReport,
    User,
)
from app.scheduler import JOBS
from app.services.mailer import describe_backend, mail_configured
from app.templates_config import templates

router = APIRouter(prefix="/smtp", tags=["smtp"])

MESSAGE_STATUSES = ("completed", "processing", "quarantine", "failed")


def _report_links(db: Session, org: Organization, messages: list[SmtpInboundMessage]) -> dict[str, tuple[str, str]]:
    """Failure or TLS report of each received mail that carried one, as address and text for a link."""
    ids = [message.id for message in messages]
    if not ids:
        return {}
    links = {}
    for model, path, label in ((TlsReport, "/tls-reports", "TLS-Bericht ansehen"),
                               (DmarcFailureReport, "/failure-reports", "Fehlerbericht ansehen")):
        rows = db.query(model.smtp_message_id, model.id).filter(
            model.organization_id == org.id, model.smtp_message_id.in_(ids),
        ).all()
        links.update({message_id: (f"{path}/{report_id}", label) for message_id, report_id in rows})
    return links


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
    jobs, mail = [], None
    if user.is_superadmin:
        runs = {run.name: run for run in db.query(SchedulerRun).all()}
        jobs = [{"label": job.label, "interval": job.interval(), "run": runs.get(job.name)} for job in JOBS]
        mail = {
            "configured": mail_configured(),
            "backend": describe_backend(),
            "sender": settings.MAIL_FROM,
        }
    return templates.TemplateResponse(request, "smtp/status.html", {
        "user": user, "org": org,
        "addresses": addresses, "recent_messages": recent_messages, "smtp_config": smtp_config,
        "report_links": _report_links(db, org, recent_messages),
        "jobs": jobs, "scheduler_enabled": settings.SCHEDULER_ENABLED, "mail": mail,
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
        "report_links": _report_links(db, org, messages),
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
