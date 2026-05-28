import json
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, get_current_org
from app.models import AlertEvent, AlertRule, Domain, NotificationChannel, Organization, User
from app.security import utcnow
from app.services.alert_service import ALERT_TYPES
from app.templates_config import templates

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/rules", response_class=HTMLResponse)
def alert_rules(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    rules = db.query(AlertRule).filter_by(organization_id=org.id).order_by(AlertRule.created_at.desc()).all()
    domains = db.query(Domain).filter_by(organization_id=org.id, is_active=True).all()
    channels = db.query(NotificationChannel).filter_by(organization_id=org.id, is_active=True).all()
    return templates.TemplateResponse("alerts/rules.html", {
        "request": request, "user": user, "org": org,
        "rules": rules, "domains": domains, "channels": channels,
        "alert_types": ALERT_TYPES, "page_title": "Alert Rules",
    })


@router.post("/rules/new")
def create_alert_rule(
    request: Request,
    name: str = Form(...),
    alert_type: str = Form(...),
    domain_id: Optional[str] = Form(None),
    threshold: Optional[float] = Form(None),
    time_window_minutes: int = Form(60),
    cooldown_minutes: int = Form(60),
    severity: str = Form("warning"),
    channel_ids: Optional[list[str]] = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    rule = AlertRule(
        organization_id=org.id,
        domain_id=domain_id or None,
        name=name,
        alert_type=alert_type,
        threshold=threshold,
        time_window_minutes=time_window_minutes,
        cooldown_minutes=cooldown_minutes,
        severity=severity,
        is_active=True,
        notification_channel_ids=json.dumps(channel_ids or []),
    )
    db.add(rule)
    db.commit()
    return RedirectResponse(url="/alerts/rules", status_code=303)


@router.post("/rules/{rule_id}/toggle")
def toggle_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    rule = db.query(AlertRule).filter_by(id=rule_id, organization_id=org.id).first()
    if not rule:
        raise HTTPException(status_code=404)
    rule.is_active = not rule.is_active
    db.commit()
    return RedirectResponse(url="/alerts/rules", status_code=303)


@router.get("/events", response_class=HTMLResponse)
def alert_events(
    request: Request,
    page: int = Query(1, ge=1),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(AlertEvent).filter_by(organization_id=org.id).order_by(AlertEvent.created_at.desc())
    if status:
        q = q.filter_by(status=status)
    if severity:
        q = q.filter_by(severity=severity)

    per_page = 25
    total = q.count()
    events = q.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page

    return templates.TemplateResponse("alerts/events.html", {
        "request": request, "user": user, "org": org,
        "events": events, "total": total, "page": page, "pages": pages,
        "status_filter": status, "severity_filter": severity,
        "page_title": "Alert Events",
    })


@router.post("/events/{event_id}/acknowledge")
def acknowledge_event(
    event_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    event = db.query(AlertEvent).filter_by(id=event_id, organization_id=org.id).first()
    if not event:
        raise HTTPException(status_code=404)
    event.status = "acknowledged"
    event.acknowledged_at = utcnow()
    event.acknowledged_by = user.id
    db.commit()
    return RedirectResponse(url="/alerts/events", status_code=303)


@router.post("/events/{event_id}/resolve")
def resolve_event(
    event_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    event = db.query(AlertEvent).filter_by(id=event_id, organization_id=org.id).first()
    if not event:
        raise HTTPException(status_code=404)
    event.status = "resolved"
    event.resolved_at = utcnow()
    event.resolved_by = user.id
    db.commit()
    return RedirectResponse(url="/alerts/events", status_code=303)


@router.get("/channels", response_class=HTMLResponse)
def notification_channels(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    channels = db.query(NotificationChannel).filter_by(organization_id=org.id).all()
    return templates.TemplateResponse("alerts/channels.html", {
        "request": request, "user": user, "org": org,
        "channels": channels, "page_title": "Notification Channels",
    })


@router.post("/channels/new")
def create_channel(
    request: Request,
    name: str = Form(...),
    channel_type: str = Form(...),
    config_json: str = Form("{}"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    try:
        config = json.loads(config_json)
    except json.JSONDecodeError:
        config = {}

    channel = NotificationChannel(
        organization_id=org.id,
        name=name,
        channel_type=channel_type,
        config=json.dumps(config),
        is_active=True,
    )
    db.add(channel)
    db.commit()
    return RedirectResponse(url="/alerts/channels", status_code=303)
