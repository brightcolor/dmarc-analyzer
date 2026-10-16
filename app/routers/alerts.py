import json

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session, selectinload

from app.config import settings
from app.database import get_db
from app.dependencies import (
    get_client_ip,
    get_current_analyst,
    get_current_manager,
    get_current_org,
    get_current_org_admin,
    get_current_user,
)
from app.models import AlertEvent, AlertRule, Domain, NotificationChannel, NotificationDelivery, Organization, User
from app.security import utcnow
from app.services import alert_details, alert_list
from app.services.alert_service import ALERT_TYPES, OPERATOR_ALERT_TYPES, alert_type_hints
from app.services.audit import log_action
from app.services.auth import get_user_role_in_org
from app.services.digest import (
    DigestError,
    Recipient,
    build_digest,
    digest_recipients,
    first_name,
    next_slot,
    send_digest,
)
from app.services.mail_render import render_digest_mail
from app.services.mailer import MailDeliveryError, MailNotConfigured, mail_configured
from app.services.notification import (
    CHANNEL_TYPES,
    ChannelError,
    build_channel_config,
    channel_summary,
    invalid_addresses,
    parse_addresses,
    send_event,
    test_event,
)
from app.services.org_settings import plain_number
from app.templates_config import _format_date as format_date
from app.templates_config import flash, templates

router = APIRouter(prefix="/alerts", tags=["alerts"])

SEVERITIES = ("info", "warning", "critical")
EVENT_STATUSES = ("open", "acknowledged", "resolved")
WEEKDAYS = ("Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag")


def _can_manage(db: Session, user: User, org: Organization) -> bool:
    """Operator or administrator of the organisation: may change channels and the digest."""
    return user.is_superadmin or get_user_role_in_org(db, user.id, org.id) == "org_admin"


def _alert_types_for(user: User) -> dict[str, str]:
    """Types this user may choose; the server-wide mail types belong to the operator."""
    if user.is_superadmin:
        return ALERT_TYPES
    return {key: label for key, label in ALERT_TYPES.items() if key not in OPERATOR_ALERT_TYPES}


# Rules ---------------------------------------------------------------------------------

RULE_DEFAULTS = {"name": "", "alert_type": "", "domain_id": "", "threshold": "", "time_window_minutes": "60",
                 "cooldown_minutes": "60", "severity": "warning", "channel_ids": []}


class RuleFormError(ValueError):
    pass


def _rule_form(rule: AlertRule) -> dict:
    return {
        "name": rule.name, "alert_type": rule.alert_type, "domain_id": rule.domain_id or "",
        "threshold": plain_number(rule.threshold),
        "time_window_minutes": str(rule.time_window_minutes), "cooldown_minutes": str(rule.cooldown_minutes),
        "severity": rule.severity, "channel_ids": json.loads(rule.notification_channel_ids or "[]"),
    }


def _rule_values(db: Session, org: Organization, form: dict) -> dict:
    """Checked column values for a rule; the alert type is checked by the caller."""
    try:
        threshold = float(form["threshold"].replace(",", ".")) if form["threshold"].strip() else None
        window = int(form["time_window_minutes"])
        cooldown = int(form["cooldown_minutes"])
    except ValueError:
        raise RuleFormError("Schwelle, Zeitraum und Pause müssen Zahlen sein, etwa 10 oder 60. Die Schwelle darf "
                            "leer bleiben.") from None
    if window < 1 or cooldown < 0 or (threshold is not None and threshold < 0):
        raise RuleFormError("Zeitraum muss mindestens 1 Minute sein, Pause und Schwelle dürfen nicht negativ sein.")
    if form["severity"] not in SEVERITIES:
        raise RuleFormError("Wähle als Schwere Hinweis, Warnung oder kritisch.")
    domain_id = form["domain_id"] or None
    if domain_id and not db.query(Domain.id).filter_by(id=domain_id, organization_id=org.id).first():
        raise RuleFormError("Die gewählte Domain gehört nicht zu dieser Organisation.")
    own_channels = {c.id for c in db.query(NotificationChannel.id).filter_by(organization_id=org.id)}
    if any(cid not in own_channels for cid in form["channel_ids"]):
        raise RuleFormError("Ein gewählter Kanal gehört nicht zu dieser Organisation.")
    return {
        "domain_id": domain_id, "threshold": threshold, "time_window_minutes": window,
        "cooldown_minutes": cooldown, "severity": form["severity"],
        "notification_channel_ids": json.dumps(form["channel_ids"]),
    }


def _rule_snapshot(rule: AlertRule) -> dict:
    return {key: getattr(rule, key) for key in ("name", "domain_id", "threshold", "time_window_minutes",
                                                "cooldown_minutes", "severity", "notification_channel_ids")}


def _own_rule(db: Session, org: Organization, rule_id: str) -> AlertRule:
    rule = db.query(AlertRule).filter_by(id=rule_id, organization_id=org.id).first()
    if not rule:
        raise HTTPException(status_code=404)
    return rule


def _editable_rule(db: Session, user: User, org: Organization, rule_id: str) -> AlertRule:
    """Rules of the server-wide mail types stay with the operator, like creating them."""
    rule = _own_rule(db, org, rule_id)
    if rule.alert_type not in _alert_types_for(user):
        raise HTTPException(status_code=403, detail="Regeln dieser Art ändert nur der Betreiber.")
    return rule


def _rule_choices(db: Session, org: Organization) -> dict:
    return {
        "domains": db.query(Domain).filter_by(organization_id=org.id, is_active=True).order_by(Domain.name).all(),
        "channels": db.query(NotificationChannel).filter_by(organization_id=org.id, is_active=True).all(),
        "channel_types": CHANNEL_TYPES, "severities": SEVERITIES, "alert_types": ALERT_TYPES,
    }


def _rules_page(request: Request, db: Session, user: User, org: Organization, error: str | None = None,
                status_code: int = 200, form: dict | None = None):
    rules = db.query(AlertRule).filter_by(organization_id=org.id).order_by(AlertRule.created_at.desc()).all()
    alert_types = _alert_types_for(user)
    return templates.TemplateResponse(request, "alerts/rules.html", {
        "user": user, "org": org, "error": error, "rules": rules, **_rule_choices(db, org),
        "form": form or RULE_DEFAULTS, "choosable_types": alert_types,
        "type_hints": {key: hint for key, hint in alert_type_hints().items() if key in alert_types},
        "eval_minutes": max(settings.ALERT_EVAL_INTERVAL_SECONDS // 60, 1),
        "page_title": "Alarmregeln",
    }, status_code=status_code)


def _rule_edit_page(request: Request, db: Session, user: User, org: Organization, rule: AlertRule,
                    form: dict, error: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(request, "alerts/rule_edit.html", {
        "user": user, "org": org, "error": error, "rule": rule, "form": form, **_rule_choices(db, org),
        "type_hint": alert_type_hints().get(rule.alert_type),
        "page_title": f"Regel „{rule.name}“ bearbeiten",
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
    name: str = Form(""),
    alert_type: str = Form(""),
    domain_id: str | None = Form(None),
    threshold: str = Form(""),
    time_window_minutes: str = Form("60"),
    cooldown_minutes: str = Form("60"),
    severity: str = Form("warning"),
    channel_ids: list[str] | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    form = {"name": name, "alert_type": alert_type, "domain_id": domain_id or "", "threshold": threshold,
            "time_window_minutes": time_window_minutes, "cooldown_minutes": cooldown_minutes,
            "severity": severity, "channel_ids": channel_ids or []}
    if alert_type not in _alert_types_for(user):
        return _rules_page(request, db, user, org, "Diese Art von Alarm steht dir nicht zur Wahl. Wähle eine aus der "
                           "Liste.", 400, form)
    try:
        values = _rule_values(db, org, form)
    except RuleFormError as exc:
        return _rules_page(request, db, user, org, str(exc), 400, form)

    rule = AlertRule(organization_id=org.id, name=name.strip()[:255] or ALERT_TYPES[alert_type],
                     alert_type=alert_type, is_active=True, **values)
    db.add(rule)
    db.flush()
    log_action(db, "rule.create", org_id=org.id, user_id=user.id, resource_type="alert_rule", resource_id=rule.id,
               new_value={"alert_type": alert_type, **_rule_snapshot(rule)}, ip_address=get_client_ip(request))
    db.commit()
    flash(request, "ok", "Regel angelegt", f"„{rule.name}“ wird ab jetzt geprüft, nach jedem Import und "
          f"alle {max(settings.ALERT_EVAL_INTERVAL_SECONDS // 60, 1)} Minuten.")
    return RedirectResponse(url="/alerts/rules", status_code=303)


@router.get("/rules/{rule_id}/edit", response_class=HTMLResponse)
def edit_rule_page(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    rule = _editable_rule(db, user, org, rule_id)
    return _rule_edit_page(request, db, user, org, rule, _rule_form(rule))


@router.post("/rules/{rule_id}/edit")
def update_rule(
    rule_id: str,
    request: Request,
    name: str = Form(""),
    domain_id: str | None = Form(None),
    threshold: str = Form(""),
    time_window_minutes: str = Form("60"),
    cooldown_minutes: str = Form("60"),
    severity: str = Form("warning"),
    channel_ids: list[str] | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    rule = _editable_rule(db, user, org, rule_id)
    form = {"name": name, "alert_type": rule.alert_type, "domain_id": domain_id or "", "threshold": threshold,
            "time_window_minutes": time_window_minutes, "cooldown_minutes": cooldown_minutes,
            "severity": severity, "channel_ids": channel_ids or []}
    try:
        values = _rule_values(db, org, form)
    except RuleFormError as exc:
        return _rule_edit_page(request, db, user, org, rule, form, str(exc), 400)

    before = _rule_snapshot(rule)
    rule.name = name.strip()[:255] or ALERT_TYPES.get(rule.alert_type, rule.name)
    for key, value in values.items():
        setattr(rule, key, value)
    log_action(db, "rule.update", org_id=org.id, user_id=user.id, resource_type="alert_rule", resource_id=rule.id,
               old_value=before, new_value=_rule_snapshot(rule), ip_address=get_client_ip(request))
    db.commit()
    flash(request, "ok", "Regel gespeichert", f"„{rule.name}“ gilt ab der nächsten Prüfung mit den neuen Werten.")
    return RedirectResponse(url="/alerts/rules", status_code=303)


@router.post("/rules/{rule_id}/toggle")
def toggle_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    rule = _own_rule(db, org, rule_id)
    rule.is_active = not rule.is_active
    db.commit()
    return RedirectResponse(url="/alerts/rules", status_code=303)


@router.post("/rules/{rule_id}/delete")
def delete_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_manager),
    org: Organization = Depends(get_current_org),
):
    rule = _editable_rule(db, user, org, rule_id)
    # Alarms stay in the history without their rule; the ORM cascade on AlertRule.events would delete them
    db.query(AlertEvent).filter_by(rule_id=rule.id, organization_id=org.id).update(
        {AlertEvent.rule_id: None}, synchronize_session=False)
    db.expire(rule, ["events"])
    log_action(db, "rule.delete", org_id=org.id, user_id=user.id, resource_type="alert_rule", resource_id=rule.id,
               old_value={"alert_type": rule.alert_type, **_rule_snapshot(rule)}, ip_address=get_client_ip(request))
    db.delete(rule)
    db.commit()
    flash(request, "ok", "Regel gelöscht", f"„{rule.name}“ wird nicht mehr geprüft. Ihre Alarme bleiben im Verlauf.")
    return RedirectResponse(url="/alerts/rules", status_code=303)


# Events --------------------------------------------------------------------------------

@router.get("/events", response_class=HTMLResponse)
def alert_events(
    request: Request,
    page: int = Query(1, ge=1),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    view: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    status = status if status in EVENT_STATUSES else None
    severity = severity if severity in SEVERITIES else None
    single = view == "single"
    rows, truncated = alert_list.load_rows(db, org.id, status, severity, ALERT_TYPES)
    per_page = settings.UI_PAGE_SIZE
    if single:
        items = rows
    else:
        items = alert_list.group_rows(rows, ALERT_TYPES)
    total_items = len(items)
    pages = (total_items + per_page - 1) // per_page
    shown = items[(page - 1) * per_page:page * per_page]
    deliveries = {}
    if single:
        ids = [r.event.id for r in shown]
        for delivery in (db.query(NotificationDelivery).options(selectinload(NotificationDelivery.channel))
                         .filter(NotificationDelivery.alert_event_id.in_(ids)) if ids else []):
            deliveries.setdefault(delivery.alert_event_id, []).append(delivery)

    return templates.TemplateResponse(request, "alerts/events.html", {
        "user": user, "org": org,
        "items": shown, "single": single, "total": len(rows), "page": page, "pages": pages,
        "truncated": truncated, "limit": settings.UI_ALERT_GROUP_LIMIT,
        "status_filter": status or "", "severity_filter": severity or "",
        "statuses": EVENT_STATUSES, "severities": SEVERITIES, "deliveries": deliveries,
        "view_single": single,
        "page_title": "Alarme",
    })


@router.post("/events/bulk")
def bulk_events(
    request: Request,
    alert_type: str = Form(""),
    domain: str = Form(""),
    action: str = Form(""),
    status: str = Form(""),
    severity: str = Form(""),
    next: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst),
    org: Organization = Depends(get_current_org),
):
    """Mark every alert of one group as seen or as resolved."""
    if action not in ("acknowledge", "resolve") or alert_type not in ALERT_TYPES:
        raise HTTPException(status_code=400, detail="Diese Sammelaktion gibt es nicht. Wähle „Alle gesehen“ oder "
                            "„Alle erledigt“ in der Gruppe.")
    source_status = status if status in EVENT_STATUSES else None
    events = alert_list.members(db, org.id, alert_type, domain, source_status,
                                severity if severity in SEVERITIES else None, ALERT_TYPES)
    wanted = "acknowledged" if action == "acknowledge" else "resolved"
    now = utcnow()
    changed = 0
    for event in events:
        if event.status == wanted or (action == "acknowledge" and event.status != "open"):
            continue
        event.status = wanted
        if action == "acknowledge":
            event.acknowledged_at, event.acknowledged_by = now, user.id
        else:
            event.resolved_at, event.resolved_by = now, user.id
        changed += 1
    log_action(db, f"alert.bulk_{action}", org_id=org.id, user_id=user.id, resource_type="alert_group",
               new_value={"alert_type": alert_type, "domain": domain, "count": changed},
               ip_address=get_client_ip(request))
    db.commit()
    flash(request, "ok", f"{changed} Alarme {'als gesehen markiert' if action == 'acknowledge' else 'erledigt'}",
          "Der Verlauf behält sie; filtere nach Status „erledigt“, um sie wiederzufinden." if changed else "")
    return RedirectResponse(url=_safe_events_url(next), status_code=303)


def _safe_events_url(target: str) -> str:
    """Back to the alert list or one alert; any other target leads to the list."""
    return target if target.startswith("/alerts/events") and not target.startswith("//") else "/alerts/events"


@router.get("/events/{event_id}", response_class=HTMLResponse)
def alert_event_detail(
    event_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    event = db.query(AlertEvent).filter_by(id=event_id, organization_id=org.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Diesen Alarm gibt es nicht oder er gehört zu einer anderen "
                            "Organisation. Öffne ihn über die Liste der Alarme.")
    rule = db.query(AlertRule).filter_by(id=event.rule_id, organization_id=org.id).first() if event.rule_id else None
    domain = db.query(Domain).filter_by(id=event.domain_id, organization_id=org.id).first() if event.domain_id else None
    try:
        metrics = json.loads(event.metrics or "{}")
    except ValueError:
        metrics = {}
    return templates.TemplateResponse(request, "alerts/event.html", {
        "user": user, "org": org, "event": event, "rule": rule, "domain": domain, "metrics": metrics,
        "type_label": ALERT_TYPES.get(event.alert_type, event.alert_type),
        "breakdown": alert_details.build(db, event, rule), "result_text": alert_details.result_text,
        "page_title": "Alarm",
    })


@router.post("/events/{event_id}/acknowledge")
def acknowledge_event(
    event_id: str,
    request: Request,
    next: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst),
    org: Organization = Depends(get_current_org),
):
    event = db.query(AlertEvent).filter_by(id=event_id, organization_id=org.id).first()
    if not event:
        raise HTTPException(status_code=404)
    event.status = "acknowledged"
    event.acknowledged_at = utcnow()
    event.acknowledged_by = user.id
    db.commit()
    return RedirectResponse(url=_safe_events_url(next), status_code=303)


@router.post("/events/{event_id}/resolve")
def resolve_event(
    event_id: str,
    request: Request,
    next: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst),
    org: Organization = Depends(get_current_org),
):
    event = db.query(AlertEvent).filter_by(id=event_id, organization_id=org.id).first()
    if not event:
        raise HTTPException(status_code=404)
    event.status = "resolved"
    event.resolved_at = utcnow()
    event.resolved_by = user.id
    db.commit()
    return RedirectResponse(url=_safe_events_url(next), status_code=303)


# Channels ------------------------------------------------------------------------------

def _last_deliveries(db: Session, channel_ids: list[str]) -> dict[str, NotificationDelivery]:
    latest: dict[str, NotificationDelivery] = {}
    if not channel_ids:
        return latest
    deliveries = (
        db.query(NotificationDelivery)
        .filter(NotificationDelivery.channel_id.in_(channel_ids), NotificationDelivery.status != "pending")
        .order_by(NotificationDelivery.created_at.desc())
        .limit(len(channel_ids) * 20)
        .all()
    )
    for delivery in deliveries:
        latest.setdefault(delivery.channel_id, delivery)
    return latest


def _channels_page(request: Request, db: Session, user: User, org: Organization, error: str | None = None,
                   values: dict | None = None, status_code: int = 200):
    channels = db.query(NotificationChannel).filter_by(organization_id=org.id) \
        .order_by(NotificationChannel.created_at).all()
    return templates.TemplateResponse(request, "alerts/channels.html", {
        "user": user, "org": org, "error": error, "values": values or {},
        "channels": channels, "channel_types": CHANNEL_TYPES,
        "summaries": {c.id: channel_summary(c) for c in channels},
        "last_deliveries": _last_deliveries(db, [c.id for c in channels]),
        "mail_ready": mail_configured(), "ntfy_default": settings.NTFY_DEFAULT_URL,
        "can_manage": _can_manage(db, user, org),
        "page_title": "Benachrichtigungskanäle",
    }, status_code=status_code)


def _own_channel(db: Session, org: Organization, channel_id: str) -> NotificationChannel:
    channel = db.query(NotificationChannel).filter_by(id=channel_id, organization_id=org.id).first()
    if not channel:
        raise HTTPException(status_code=404)
    return channel


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
    name: str = Form(""),
    channel_type: str = Form(""),
    url: str = Form(""),
    topic: str = Form(""),
    token: str = Form(""),
    recipients: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    values = {"name": name, "channel_type": channel_type, "url": url, "topic": topic, "recipients": recipients}
    try:
        config = build_channel_config(channel_type, url=url, topic=topic, token=token, recipients=recipients)
    except ChannelError as exc:
        return _channels_page(request, db, user, org, str(exc), values, 400)

    channel = NotificationChannel(
        organization_id=org.id,
        name=name.strip()[:255] or CHANNEL_TYPES[channel_type],
        channel_type=channel_type,
        config=json.dumps(config),
        is_active=True,
    )
    db.add(channel)
    db.flush()
    log_action(db, "channel.create", org_id=org.id, user_id=user.id, resource_type="notification_channel",
               resource_id=channel.id, new_value={"name": channel.name, "type": channel_type},
               ip_address=get_client_ip(request))
    db.commit()
    flash(request, "ok", "Kanal angelegt", f"Schick mit „Testen“ eine Probenachricht an „{channel.name}“.")
    return RedirectResponse(url="/alerts/channels", status_code=303)


@router.post("/channels/{channel_id}/test")
def test_channel(
    channel_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    channel = _own_channel(db, org, channel_id)
    try:
        send_event(test_event(channel), channel)
    except (ChannelError, MailNotConfigured, MailDeliveryError) as exc:
        flash(request, "bad", f"Die Testnachricht an „{channel.name}“ kam nicht an", str(exc))
    else:
        flash(request, "ok", "Testnachricht verschickt", f"Prüfe, ob sie bei „{channel.name}“ angekommen ist.")
    return RedirectResponse(url="/alerts/channels", status_code=303)


@router.post("/channels/{channel_id}/toggle")
def toggle_channel(
    channel_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    channel = _own_channel(db, org, channel_id)
    channel.is_active = not channel.is_active
    db.commit()
    return RedirectResponse(url="/alerts/channels", status_code=303)


@router.post("/channels/{channel_id}/delete")
def delete_channel(
    channel_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    channel = _own_channel(db, org, channel_id)
    db.query(NotificationDelivery).filter_by(channel_id=channel.id).delete(synchronize_session=False)
    log_action(db, "channel.delete", org_id=org.id, user_id=user.id, resource_type="notification_channel",
               resource_id=channel.id, old_value={"name": channel.name, "type": channel.channel_type},
               ip_address=get_client_ip(request))
    db.delete(channel)
    db.commit()
    flash(request, "ok", "Kanal gelöscht", f"„{channel.name}“ bekommt keine Alarme mehr.")
    return RedirectResponse(url="/alerts/channels", status_code=303)


# Weekly digest -------------------------------------------------------------------------

def _digest_page(request: Request, db: Session, user: User, org: Organization, error: str | None = None,
                 recipients_text: str | None = None, status_code: int = 200):
    now = utcnow()
    return templates.TemplateResponse(request, "alerts/digest.html", {
        "user": user, "org": org, "error": error,
        "recipients_text": (org.digest_recipients or "") if recipients_text is None else recipients_text,
        "recipients": digest_recipients(db, org),
        "mail_ready": mail_configured(),
        "next_send": next_slot(now) if org.digest_enabled else None,
        "weekday": WEEKDAYS[settings.DIGEST_WEEKDAY], "hour": settings.DIGEST_HOUR,
        "period_days": settings.DIGEST_PERIOD_DAYS,
        "can_manage": _can_manage(db, user, org),
        "page_title": "Wochenbericht",
    }, status_code=status_code)


@router.get("/digest", response_class=HTMLResponse)
def digest_settings(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    return _digest_page(request, db, user, org)


@router.post("/digest")
def save_digest_settings(
    request: Request,
    enabled: str | None = Form(None),
    recipients: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    addresses = parse_addresses(recipients)
    wrong = invalid_addresses(addresses)
    if wrong:
        return _digest_page(request, db, user, org, "Diese Adressen sehen nicht wie Mailadressen aus: "
                            f"{', '.join(wrong)}. Trage eine Adresse je Zeile ein.", recipients, 400)
    org.digest_enabled = enabled is not None
    org.digest_recipients = "\n".join(addresses) or None
    log_action(db, "digest.update", org_id=org.id, user_id=user.id, resource_type="organization",
               resource_id=org.id, new_value={"enabled": org.digest_enabled, "recipients": len(addresses)},
               ip_address=get_client_ip(request))
    db.commit()
    if org.digest_enabled:
        flash(request, "ok", "Wochenbericht gespeichert",
              f"Der nächste Bericht geht am {WEEKDAYS[settings.DIGEST_WEEKDAY]}, "
              f"{format_date(next_slot(utcnow()))}, ab {settings.DIGEST_HOUR} Uhr raus.")
    else:
        flash(request, "ok", "Wochenbericht ausgeschaltet", "Du kannst ihn hier jederzeit wieder einschalten.")
    return RedirectResponse(url="/alerts/digest", status_code=303)


@router.get("/digest/preview", response_class=HTMLResponse)
def preview_digest(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    recipient = Recipient(user.email, first_name(user.full_name))
    _, _, html = render_digest_mail(build_digest(db, org), recipient)
    return HTMLResponse(html)


@router.post("/digest/send")
def send_digest_now(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    try:
        result = send_digest(db, org)
    except DigestError as exc:
        db.rollback()
        flash(request, "bad", "Der Wochenbericht wurde nicht verschickt", str(exc))
        return RedirectResponse(url="/alerts/digest", status_code=303)
    db.commit()
    text = f"Er ging an {', '.join(result.sent)}."
    if result.failed:
        text += " Nicht zugestellt: " + " ".join(result.failed)
    flash(request, "warn" if result.failed else "ok", "Wochenbericht verschickt", text)
    return RedirectResponse(url="/alerts/digest", status_code=303)
