"""
Notification delivery: sends queued alert notifications over the channels of an organisation.

Alert evaluation queues one NotificationDelivery per channel; the scheduler calls dispatch_pending.
A failed delivery is tried again after a growing pause, up to NOTIFICATION_RETRY_MAX times.
Every failure stores a reason the user can act on.
"""
import ipaddress
import json
import logging
import re
import socket
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AlertEvent, NotificationChannel, NotificationDelivery
from app.security import utcnow
from app.services.mailer import MailDeliveryError, MailNotConfigured, send_mail

logger = logging.getLogger(__name__)

CHANNEL_TYPES = {
    "email": "E-Mail",
    "webhook": "Webhook (JSON)",
    "ntfy": "ntfy",
    "slack": "Slack oder Mattermost",
}

SEVERITY_LABELS = {"info": "Hinweis", "warning": "Warnung", "critical": "Kritisch"}
# ntfy priorities 1 (min) to 5 (max)
NTFY_PRIORITY = {"info": 2, "warning": 3, "critical": 5}
# Palette of the bright color workbench: lime, yellow, pink
SLACK_COLORS = {"info": "#bfd535", "warning": "#fed329", "critical": "#d61f7a"}

EMAIL_PATTERN = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")
TOPIC_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class ChannelError(Exception):
    """Delivery or configuration problem, with a reason for the user."""


# Channel configuration -------------------------------------------------------------

def parse_addresses(text: str | None) -> list[str]:
    """Mail addresses from a text with one address per line or separated by comma or semicolon."""
    return [a.strip() for a in re.split(r"[\s,;]+", text or "") if a.strip()]


def invalid_addresses(addresses: list[str]) -> list[str]:
    return [a for a in addresses if not EMAIL_PATTERN.match(a)]


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def target_problem(url: str) -> str | None:
    """Why a notification may not go to this address, or None. Internal networks stay closed to channels."""
    if not settings.NOTIFICATION_BLOCK_PRIVATE_TARGETS:
        return None
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return "Die Adresse enthält keinen Hostnamen."
    if host in settings.notification_allowed_internal_hosts:
        return None
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if _is_ip_literal(host):
            addresses = [host]
        else:
            addresses = [str(info[4][0]) for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    except ValueError:
        return "Die Portangabe in der Adresse ist ungültig."
    except OSError:
        return f"Der Name {host} lässt sich nicht auflösen. Prüfe die Adresse."
    for value in addresses:
        address = ipaddress.ip_address(value.split("%")[0])
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global:
            if _is_ip_literal(host):
                where = f"{host} ist eine interne Adresse"
            else:
                where = f"{host} zeigt auf die interne Adresse {address}"
            return (f"{where}. Benachrichtigungen gehen nur an öffentliche Adressen; der Betreiber kann den Namen "
                    "in NOTIFICATION_ALLOWED_INTERNAL_HOSTS freigeben.")
    return None


def _http_url(value: str, field: str) -> str:
    value = (value or "").strip()
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ChannelError(f"{field} muss mit http:// oder https:// beginnen, etwa https://hooks.example.org/alarme.")
    problem = target_problem(value)
    if problem:
        raise ChannelError(problem)
    return value


def build_channel_config(channel_type: str, *, url: str = "", topic: str = "", token: str = "",
                         recipients: str = "") -> dict:
    """Configuration for a channel from the form fields. Raises ChannelError with a German reason."""
    if channel_type == "email":
        addresses = parse_addresses(recipients)
        if not addresses:
            raise ChannelError("Trage mindestens eine Empfängeradresse ein, eine je Zeile.")
        wrong = invalid_addresses(addresses)
        if wrong:
            raise ChannelError(f"Diese Adressen sehen nicht wie Mailadressen aus: {', '.join(wrong)}.")
        return {"to": addresses}
    if channel_type in ("webhook", "slack"):
        return {"url": _http_url(url, "Die Adresse")}
    if channel_type == "ntfy":
        topic = topic.strip()
        if not TOPIC_PATTERN.match(topic):
            raise ChannelError("Das ntfy-Thema darf nur Buchstaben, Ziffern, - und _ enthalten, höchstens 64 Zeichen.")
        config = {"topic": topic}
        if url.strip():
            config["url"] = _http_url(url, "Der ntfy-Server").rstrip("/")
        else:
            _http_url(settings.NTFY_DEFAULT_URL, "Der ntfy-Server aus NTFY_DEFAULT_URL")
        if token.strip():
            config["token"] = token.strip()
        return config
    raise ChannelError(f"Diese Kanalart gibt es nicht. Wähle {', '.join(CHANNEL_TYPES.values())}.")


def channel_config(channel: NotificationChannel) -> dict:
    try:
        config = json.loads(channel.config or "{}")
    except (TypeError, ValueError):
        return {}
    return config if isinstance(config, dict) else {}


def channel_summary(channel: NotificationChannel) -> str:
    """Target of a channel for lists; hides tokens and the secret part of webhook addresses."""
    config = channel_config(channel)
    if channel.channel_type == "email":
        return ", ".join(config.get("to", []))
    if channel.channel_type == "ntfy":
        server = urlsplit(config.get("url") or settings.NTFY_DEFAULT_URL).netloc
        return f"{server} · Thema {config.get('topic', '—')}"
    return urlsplit(config.get("url", "")).netloc or "—"


# Messages ----------------------------------------------------------------------------

def event_url(event: AlertEvent) -> str:
    return f"{settings.APP_URL.rstrip('/')}/alerts/events?status={event.status}"


def _metrics(event: AlertEvent) -> dict:
    try:
        return json.loads(event.metrics or "{}")
    except (TypeError, ValueError):
        return {}


def _host(url: str) -> str:
    return urlsplit(url).netloc or url


def _post(url: str, **kwargs) -> None:
    timeout = settings.NOTIFICATION_HTTP_TIMEOUT_SECONDS
    host = _host(url)
    # Checked again before every send: the name may point elsewhere by now
    problem = target_problem(url)
    if problem:
        raise ChannelError(problem)
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, **kwargs)
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        raise ChannelError(f"{host} hat nicht innerhalb von {timeout} Sekunden geantwortet.") from exc
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        hint = "Prüfe Zugang und Berechtigung des Kanals." if code in (401, 403) else "Prüfe die Adresse des Kanals."
        raise ChannelError(f"{host} hat die Nachricht mit Status {code} abgelehnt. {hint}") from exc
    except httpx.RequestError as exc:
        raise ChannelError(
            f"{host} ist nicht erreichbar ({exc.__class__.__name__}). Prüfe die Adresse des Kanals."
        ) from exc


def _send_webhook(event: AlertEvent, config: dict) -> None:
    _post(config.get("url", ""), json={
        "id": event.id,
        "type": event.alert_type,
        "severity": event.severity,
        "title": event.title,
        "description": event.description,
        "status": event.status,
        "domain": event.domain.name if event.domain else None,
        "source_ip": event.source_ip,
        "metrics": _metrics(event),
        "created_at": event.created_at.isoformat() if event.created_at else None,
        "url": event_url(event),
    })


def _send_ntfy(event: AlertEvent, config: dict) -> None:
    # JSON publishing keeps umlauts intact; header fields only carry ASCII
    server = (config.get("url") or settings.NTFY_DEFAULT_URL).rstrip("/")
    headers = {"Authorization": f"Bearer {config['token']}"} if config.get("token") else {}
    _post(server, headers=headers, json={
        "topic": config.get("topic", ""),
        "title": event.title[:250],
        "message": event.description or event.title,
        "priority": NTFY_PRIORITY.get(event.severity, 3),
        "tags": ["dmarc", event.severity],
        "click": event_url(event),
    })


def _send_slack(event: AlertEvent, config: dict) -> None:
    severity = SEVERITY_LABELS.get(event.severity, event.severity)
    _post(config.get("url", ""), json={
        "text": f"{severity}: {event.title}",
        "attachments": [{
            "color": SLACK_COLORS.get(event.severity, "#111111"),
            "title": event.title,
            "title_link": event_url(event),
            "text": event.description or "",
            "footer": f"{settings.APP_NAME} · {severity}",
        }],
    })


def _send_email(event: AlertEvent, config: dict, channel: NotificationChannel) -> None:
    from app.services.mail_render import render_alert_mail

    recipients = config.get("to") or []
    subject, text, html = render_alert_mail(event, channel)
    send_mail(recipients, subject, text, html)


def send_event(event: AlertEvent, channel: NotificationChannel) -> None:
    """Send one event over one channel. Raises ChannelError, MailNotConfigured or MailDeliveryError."""
    config = channel_config(channel)
    if channel.channel_type == "webhook":
        _send_webhook(event, config)
    elif channel.channel_type == "ntfy":
        _send_ntfy(event, config)
    elif channel.channel_type == "slack":
        _send_slack(event, config)
    elif channel.channel_type == "email":
        _send_email(event, config, channel)
    else:
        raise ChannelError(f"Die Kanalart {channel.channel_type!r} kennt die Anwendung nicht. Lege den Kanal neu an.")


def send_bundle(events: list[AlertEvent], *, channel: NotificationChannel | None = None,
                address: str | None = None) -> None:
    """Several events in one mail, to an email channel or to a further recipient of their domain."""
    from app.services.mail_render import render_alert_bundle

    subject, text, html = render_alert_bundle(events, channel, recipient=address)
    recipients = [address] if address else (channel_config(channel).get("to") or [])
    send_mail(recipients, subject, text, html)


def send_event_to_address(event: AlertEvent, address: str) -> None:
    """Send one event by mail to a further recipient of its domain."""
    from app.services.mail_render import render_alert_mail

    subject, text, html = render_alert_mail(event, None, recipient=address)
    send_mail([address], subject, text, html)


def test_event(channel: NotificationChannel) -> AlertEvent:
    """Unsaved event for the test button of a channel."""
    event = AlertEvent(
        id="test",
        organization_id=channel.organization_id,
        alert_type="test",
        severity="info",
        title="Testnachricht vom DMARC Analyzer",
        description=(f"Der Kanal „{channel.name}“ funktioniert. So sehen Alarme aus, wenn eine Regel anschlägt."),
        status="open",
        metrics="{}",
    )
    event.created_at = utcnow()
    return event


# Dispatch ------------------------------------------------------------------------------

def due_filter(now: datetime):
    """Deliveries that need an attempt now."""
    return or_(
        NotificationDelivery.status == "pending",
        (NotificationDelivery.status == "failed")
        & (NotificationDelivery.retry_count <= settings.NOTIFICATION_RETRY_MAX)
        & (NotificationDelivery.next_attempt_at.is_(None) | (NotificationDelivery.next_attempt_at <= now)),
    )


def _retry_delay(retry_count: int) -> timedelta:
    return timedelta(seconds=settings.NOTIFICATION_RETRY_DELAY_SECONDS * 2 ** max(retry_count - 1, 0))


def dispatch_pending(db: Session, now: datetime | None = None) -> dict[str, int]:
    """Send all due deliveries; returns how many were sent, failed or skipped."""
    now = now or utcnow()
    counts = {"sent": 0, "failed": 0, "skipped": 0}
    deliveries = (
        db.query(NotificationDelivery)
        .filter(due_filter(now))
        .order_by(NotificationDelivery.created_at)
        .limit(settings.NOTIFICATION_BATCH_SIZE)
        .all()
    )
    from app.services.domain_recipients import still_wants_alerts

    window = timedelta(seconds=settings.NOTIFICATION_EMAIL_BUNDLE_SECONDS)
    singles, mailboxes = [], {}
    for delivery in deliveries:
        event, channel = delivery.alert_event, delivery.channel
        if delivery.channel_id is None:
            if not delivery.recipient or not still_wants_alerts(db, event.domain_id, delivery.recipient):
                delivery.status = "skipped"
                delivery.error_message = ("Die Adresse bekommt die Alarme dieser Domain nicht mehr. Die "
                                          "Benachrichtigung wurde nicht verschickt.")
                counts["skipped"] += 1
                continue
        elif channel is None or not channel.is_active:
            delivery.status = "skipped"
            delivery.error_message = "Der Kanal ist ausgeschaltet. Die Benachrichtigung wurde nicht verschickt."
            counts["skipped"] += 1
            continue
        target = _mailbox(delivery) if window else None
        if target:
            mailboxes.setdefault(target, []).append(delivery)
        else:
            singles.append(delivery)

    for delivery in singles:
        _attempt(delivery, [delivery], now, counts)
    for (kind, key), members in mailboxes.items():
        if now - min(_aware(m.created_at, now) for m in members) < window:
            continue  # still collecting; the next run sends them together
        _attempt(members[0] if len(members) == 1 else None, members, now, counts,
                 address=key if kind == "address" else None)
    db.flush()
    if any(counts.values()):
        logger.info("Notifications: %(sent)d sent, %(failed)d failed, %(skipped)d skipped", counts)
    return counts


def _mailbox(delivery: NotificationDelivery) -> tuple[str, str] | None:
    """Mail deliveries are collected per channel or address; other channels go out at once."""
    if delivery.channel_id is None:
        return "address", delivery.recipient
    if delivery.channel.channel_type == "email":
        return "channel", delivery.channel_id
    return None


def _aware(value: datetime, now: datetime) -> datetime:
    return value.replace(tzinfo=now.tzinfo) if value.tzinfo is None else value


def _attempt(single: NotificationDelivery | None, members: list[NotificationDelivery], now: datetime,
             counts: dict[str, int], address: str | None = None) -> None:
    """Send one delivery, or all members as one mail, and record the outcome on each of them."""
    try:
        if single is not None and single.channel is None:
            send_event_to_address(single.alert_event, single.recipient)
        elif single is not None:
            send_event(single.alert_event, single.channel)
        else:
            send_bundle([m.alert_event for m in members], channel=members[0].channel, address=address)
    except (ChannelError, MailNotConfigured, MailDeliveryError) as exc:
        for member in members:
            _mark_failed(member, str(exc), now)
        counts["failed"] += len(members)
    except Exception as exc:
        logger.exception("Unexpected error sending %d deliveries", len(members))
        for member in members:
            _mark_failed(member, f"Unerwarteter Fehler beim Versand ({exc.__class__.__name__}). Die Anwendung "
                         "versucht es erneut; bleibt der Fehler, hilft das Log des Web-Containers weiter.", now)
        counts["failed"] += len(members)
    else:
        for member in members:
            member.status = "sent"
            member.sent_at = now
            member.error_message = None
            member.next_attempt_at = None
        counts["sent"] += len(members)


def _mark_failed(delivery: NotificationDelivery, reason: str, now: datetime) -> None:
    delivery.status = "failed"
    delivery.retry_count += 1
    delivery.error_message = reason[:1000]
    delivery.next_attempt_at = now + _retry_delay(delivery.retry_count)
    logger.warning("Notification %s failed (attempt %d): %s", delivery.id, delivery.retry_count, reason)
