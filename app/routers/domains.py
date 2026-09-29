from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_client_ip, get_current_manager, get_current_org, get_current_user
from app.models import DmarcReport, Domain, DomainRecipient, InboundMailAddress, Organization, User
from app.services.audit import log_action
from app.services.charts import day_chart
from app.services.dashboard import get_pass_fail_over_time
from app.services.dmarc_record import suggest_dmarc_record
from app.services.domain_recipients import RecipientError, add_recipient, recipients_for, update_recipient
from app.services.domains import INVALID_NAME, DomainLimitReached, create_domain, normalize_domain
from app.services.inbound_address import create_domain_address
from app.services.mailer import mail_configured
from app.services.recommendation import get_recommendations_for_domain
from app.services.report_formats import reporter_formats
from app.templates_config import flash, templates

router = APIRouter(prefix="/domains", tags=["domains"])


def _paginate(q, page: int, per_page: int):
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, (total + per_page - 1) // per_page


@router.get("", response_class=HTMLResponse)
def domain_list(
    request: Request,
    page: int = Query(1, ge=1),
    search: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(Domain).filter_by(organization_id=org.id)
    if search:
        q = q.filter(Domain.name.ilike(f"%{search}%"))
    q = q.order_by(Domain.name)
    domains, total, pages = _paginate(q, page, settings.UI_PAGE_SIZE)

    return templates.TemplateResponse(request, "domains/index.html", {
        "user": user, "org": org,
        "domains": domains, "total": total, "page": page, "pages": pages,
        "search": search or "", "page_title": "Domains",
    })


@router.get("/new", response_class=HTMLResponse)
def domain_new_form(
    request: Request,
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    return _form(request, user, org)


def _form(request: Request, user: User, org: Organization, name: str = "", error: str | None = None):
    return templates.TemplateResponse(request, "domains/form.html", {
        "user": user, "org": org, "name": name, "error": error, "page_title": "Domain anlegen",
    }, status_code=400 if error else 200)


@router.post("/new")
def domain_create(
    request: Request,
    name: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    typed = name.strip()
    name = normalize_domain(typed)
    if not name:
        return _form(request, user, org, typed, INVALID_NAME)

    if db.query(Domain).filter_by(organization_id=org.id, name=name).first():
        return _form(request, user, org, name, f"Die Domain {name} ist bereits angelegt. Du findest sie in der Liste.")

    try:
        domain, _, _ = create_domain(db, org, name)
    except DomainLimitReached:
        return _form(request, user, org, name, f"Diese Organisation darf höchstens {org.max_domains} Domains "
                     "anlegen. Bitte den Betreiber, die Grenze zu erhöhen.")

    log_action(
        db, "domain.create", org_id=org.id, user_id=user.id,
        resource_type="domain", resource_id=domain.id,
        new_value={"name": name},
        ip_address=get_client_ip(request),
    )
    db.commit()
    return RedirectResponse(url=f"/domains/{domain.id}", status_code=303)


@router.get("/{domain_id}", response_class=HTMLResponse)
def domain_detail(
    request: Request,
    domain_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)

    # Inbound addresses for this domain
    addresses = db.query(InboundMailAddress).filter_by(
        organization_id=org.id, domain_id=domain_id
    ).all()

    recs = get_recommendations_for_domain(db, org.id, domain_id)

    days = settings.UI_CHART_DAYS
    chart = day_chart(get_pass_fail_over_time(db, org.id, domain_id=domain_id, days=days), days,
                      datetime.now(UTC).date())

    recent_reports = (
        db.query(DmarcReport)
        .filter_by(organization_id=org.id, domain_id=domain_id)
        .order_by(DmarcReport.period_end.desc(), DmarcReport.created_at.desc())
        .limit(settings.UI_RECENT_LIMIT)
        .all()
    )
    report_count = db.query(DmarcReport).filter_by(organization_id=org.id, domain_id=domain_id).count()

    # DMARC record suggestion
    rua_addr = next(
        (a.address for a in addresses if a.status == "active" and a.purpose == "domain_report"),
        None,
    )
    if not rua_addr:
        # Fall back to org-level address
        org_addr = db.query(InboundMailAddress).filter_by(
            organization_id=org.id, status="active", purpose="org_report"
        ).filter(InboundMailAddress.domain_id.is_(None)).first()
        if org_addr:
            rua_addr = org_addr.address

    suggested_record = suggest_dmarc_record(domain, rua_addr) if rua_addr else None

    # External DMARC destination verification record
    ext_verify_record = None
    if rua_addr and "@" in rua_addr:
        rua_domain = rua_addr.split("@")[1]
        if rua_domain != domain.name:
            ext_verify_record = f"{domain.name}._report._dmarc.{rua_domain}"

    return templates.TemplateResponse(request, "domains/detail.html", {
        "user": user, "org": org, "domain": domain,
        "addresses": addresses, "recommendations": recs,
        "chart": chart, "chart_days": days, "recent_reports": recent_reports, "report_count": report_count,
        "reporters": reporter_formats(db, org.id, domain_id=domain_id),
        "suggested_record": suggested_record,
        "ext_verify_record": ext_verify_record,
        "rua_addr": rua_addr,
        "rua_domain": rua_addr.split("@")[1] if rua_addr and "@" in rua_addr else None,
        "recipients": recipients_for(db, domain), "recipients_max": settings.DOMAIN_RECIPIENTS_MAX,
        "mail_ready": mail_configured(),
        "page_title": domain.name,
    })


@router.post("/{domain_id}/toggle")
def domain_toggle(
    request: Request,
    domain_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)
    domain.is_active = not domain.is_active
    log_action(
        db, "domain.toggle", org_id=org.id, user_id=user.id,
        resource_type="domain", resource_id=domain.id,
        new_value={"is_active": domain.is_active},
    )
    db.commit()
    return RedirectResponse(url=f"/domains/{domain_id}", status_code=303)


@router.post("/{domain_id}/add-address")
def domain_add_address(
    request: Request,
    domain_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)
    create_domain_address(db, org, domain)
    db.commit()
    return RedirectResponse(url=f"/domains/{domain_id}", status_code=303)


# Further recipients of the domain ------------------------------------------------------

def _own_domain(db: Session, org: Organization, domain_id: str) -> Domain:
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)
    return domain


def _what(alerts: bool, digest: bool) -> str:
    if alerts and digest:
        return "die Alarme und den Wochenbericht"
    return "die Alarme" if alerts else "den Wochenbericht"


def _back(domain_id: str) -> RedirectResponse:
    return RedirectResponse(url=f"/domains/{domain_id}#empfaenger", status_code=303)


@router.post("/{domain_id}/recipients")
def domain_add_recipient(
    request: Request,
    domain_id: str,
    email: str = Form(""),
    name: str = Form(""),
    alerts: str = Form(""),
    digest: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    domain = _own_domain(db, org, domain_id)
    try:
        recipient = add_recipient(db, domain, email, name, alerts=bool(alerts), digest=bool(digest))
    except RecipientError as exc:
        flash(request, "bad", "Empfänger nicht eingetragen", str(exc))
        return _back(domain_id)
    log_action(db, "domain_recipient.add", org_id=org.id, user_id=user.id, resource_type="domain",
               resource_id=domain.id, new_value={"email": recipient.email, "alerts": recipient.alerts,
                                                 "digest": recipient.digest}, ip_address=get_client_ip(request))
    db.commit()
    flash(request, "ok", "Empfänger eingetragen",
          f"{recipient.email} bekommt ab jetzt {_what(recipient.alerts, recipient.digest)} für {domain.name}.")
    return _back(domain_id)


def _own_recipient(db: Session, domain: Domain, recipient_id: str) -> DomainRecipient:
    recipient = db.query(DomainRecipient).filter_by(id=recipient_id, domain_id=domain.id).first()
    if not recipient:
        raise HTTPException(status_code=404)
    return recipient


@router.post("/{domain_id}/recipients/{recipient_id}")
def domain_update_recipient(
    request: Request,
    domain_id: str,
    recipient_id: str,
    alerts: str = Form(""),
    digest: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    domain = _own_domain(db, org, domain_id)
    recipient = _own_recipient(db, domain, recipient_id)
    try:
        update_recipient(recipient, alerts=bool(alerts), digest=bool(digest))
    except RecipientError as exc:
        flash(request, "bad", "Nicht gespeichert", str(exc))
        return _back(domain_id)
    log_action(db, "domain_recipient.update", org_id=org.id, user_id=user.id, resource_type="domain",
               resource_id=domain.id, new_value={"email": recipient.email, "alerts": recipient.alerts,
                                                 "digest": recipient.digest}, ip_address=get_client_ip(request))
    db.commit()
    flash(request, "ok", "Gespeichert",
          f"{recipient.email} bekommt {_what(recipient.alerts, recipient.digest)} für {domain.name}.")
    return _back(domain_id)


@router.post("/{domain_id}/recipients/{recipient_id}/delete")
def domain_delete_recipient(
    request: Request,
    domain_id: str,
    recipient_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    domain = _own_domain(db, org, domain_id)
    recipient = _own_recipient(db, domain, recipient_id)
    log_action(db, "domain_recipient.delete", org_id=org.id, user_id=user.id, resource_type="domain",
               resource_id=domain.id, old_value={"email": recipient.email}, ip_address=get_client_ip(request))
    db.delete(recipient)
    db.commit()
    flash(request, "ok", "Empfänger entfernt", f"{recipient.email} bekommt nichts mehr für {domain.name}.")
    return _back(domain_id)
