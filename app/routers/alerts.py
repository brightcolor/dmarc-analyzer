import json

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_org, get_current_user
from app.models import AlertEvent, AlertRule, Domain, NotificationChannel, Organization, User
from app.security import utcnow
from app.services.alert_service import ALERT_TYPES
from app.templates_config import templates

router = APIRouter(prefix="/alerts", tags=["alerts"])

SEVERITIES = ("info", "warning", "critical")
EVENT_STATUSES = ("open", "acknowledged", "resolved")
CHANNEL_TYPES = {"webhook": "Webhook", "ntfy": "ntfy", "slack": "Slack-kompatibler Webhook"}


def _rules_page(request: Request, db: Session, user: User, org: Organization, error: str | None = None,
                status_code: int = 200):
    rules = db.query(AlertRule).filter_by(organization_id=org.id).order_by(AlertRule.created_at.desc()).all()
    domains = db.query(Domain).filter_by(organization_id=org.id, is_active=True).order_by(Domain.name).all()
    channels = db.query(NotificationChannel).filter_by(organization_id=org.id, is_active=True).all()
    return templates.TemplateResponse(request, "alerts/rules.html", {
        "user": user, "org": org, "error": error,
        "rules": rules, "domains": domains, "channels": channels,
        "alert_types": ALERT_TYPES, "severities": SEVERITIES, "page_title": "Alarmregeln",
    }, status_code=status_code)


def _channels_page(request: Request, db: Session, user: User, org: Organization, error: str | None = None,
                   status_code: int = 200):
    channels = db.query(NotificationChannel).filter_by(organization_id=org.id).all()
    return templates.TemplateResponse(request, "alerts/channels.html", {
        "user": user, "org": org, "error": error,
        "channels": channels, "channel_types": CHANNEL_TYPES, "page_title": "Benachrichtigungskanäle",
    }, status_code=status_code)


@router.get("/rules", response_class=HTMLResponse)
def alert_rules(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    return _rules_page(request, db, user, org)


@router.post("/rules/new")
def create_alert_rule(
    request: Request,
    name: str = Form(...),
    alert_type: str = Form(...),
    domain_id: str | None = Form(None),
    threshold: str = Form(""),
    time_window_minutes: str = Form("60"),
    cooldown_minutes: str = Form("60"),
    severity: str = Form("warning"),
    channel_ids: list[str] | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    try:
        threshold_value = float(threshold.replace(",", ".")) if threshold.strip() else None
        window = int(time_window_minutes)
        cooldown = int(cooldown_minutes)
    except ValueError:
        return _rules_page(request, db, user, org, "Schwelle, Zeitraum und Pause müssen Zahlen sein, etwa 10 oder "
                           "60. Die Schwelle darf leer bleiben.", 400)
    if window < 1 or cooldown < 0 or (threshold_value is not None and threshold_value < 0):
        return _rules_page(request, db, user, org, "Zeitraum muss mindestens 1 Minute sein, Pause und Schwelle "
                           "dürfen nicht negativ sein.", 400)
    if alert_type not in ALERT_TYPES:
        return _rules_page(request, db, user, org, "Diese Art von Alarm gibt es nicht. Wähle eine aus der Liste.", 400)
    if severity not in SEVERITIES:
        return _rules_page(request, db, user, org, "Wähle als Schwere Hinweis, Warnung oder kritisch.", 400)
    if domain_id and not db.query(Domain.id).filter_by(id=domain_id, organization_id=org.id).first():
        return _rules_page(request, db, user, org, "Die gewählte Domain gehört nicht zu dieser Organisation.", 400)
    own_channels = {c.id for c in db.query(NotificationChannel.id).filter_by(organization_id=org.id)}
    if any(cid not in own_channels for cid in channel_ids or []):
        return _rules_page(request, db, user, org, "Ein gewählter Kanal gehört nicht zu dieser Organisation.", 400)

    rule = AlertRule(
        organization_id=org.id,
        domain_id=domain_id or None,
        name=name.strip()[:255] or ALERT_TYPES[alert_type],
        alert_type=alert_type,
        threshold=threshold_value,
        time_window_minutes=window,
        cooldown_minutes=cooldown,
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
    status: str | None = Query(None),
    severity: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(AlertEvent).filter_by(organization_id=org.id).order_by(AlertEvent.created_at.desc())
    if status in EVENT_STATUSES:
        q = q.filter_by(status=status)
    if severity in SEVERITIES:
        q = q.filter_by(severity=severity)

    per_page = settings.UI_PAGE_SIZE
    total = q.count()
    events = q.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page

    return templates.TemplateResponse(request, "alerts/events.html", {
        "user": user, "org": org,
        "events": events, "total": total, "page": page, "pages": pages,
        "status_filter": status if status in EVENT_STATUSES else "",
        "severity_filter": severity if severity in SEVERITIES else "",
        "statuses": EVENT_STATUSES, "severities": SEVERITIES,
        "page_title": "Alarme",
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
    return _channels_page(request, db, user, org)


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
    if channel_type not in CHANNEL_TYPES:
        return _channels_page(request, db, user, org, "Diese Kanalart gibt es nicht. Wähle Webhook, ntfy oder "
                              "Slack-kompatibler Webhook.", 400)
    try:
        config = json.loads(config_json or "{}")
    except json.JSONDecodeError as exc:
        return _channels_page(request, db, user, org, "Die Einstellungen sind kein gültiges JSON "
                              f"(Zeile {exc.lineno}, Spalte {exc.colno}). Nutze die Beispiele unter dem Feld.", 400)
    if not isinstance(config, dict) or not str(config.get("url", "")).startswith(("https://", "http://")):
        return _channels_page(request, db, user, org, "In den Einstellungen fehlt die Adresse des Kanals, etwa "
                              '{"url": "https://ntfy.example/alarme"}.', 400)

    channel = NotificationChannel(
        organization_id=org.id,
        name=name.strip()[:255] or CHANNEL_TYPES[channel_type],
        channel_type=channel_type,
        config=json.dumps(config),
        is_active=True,
    )
    db.add(channel)
    db.commit()
    return RedirectResponse(url="/alerts/channels", status_code=303)
