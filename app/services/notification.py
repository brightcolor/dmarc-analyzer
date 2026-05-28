"""
Notification delivery service.
Sends alerts via configured channels (email, webhook, ntfy, slack-compatible).
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from app.models import AlertEvent, NotificationChannel, NotificationDelivery

logger = logging.getLogger(__name__)


def deliver_event(db: Session, event: AlertEvent, channel: NotificationChannel) -> NotificationDelivery:
    delivery = NotificationDelivery(
        alert_event_id=event.id,
        channel_id=channel.id,
        status="pending",
    )
    db.add(delivery)
    db.flush()

    try:
        _send(event, channel)
        delivery.status = "sent"
        delivery.sent_at = datetime.now(timezone.utc)
    except Exception as exc:
        logger.warning("Notification delivery failed (channel=%s): %s", channel.id, exc)
        delivery.status = "failed"
        delivery.error_message = str(exc)[:1000]
        delivery.retry_count += 1

    return delivery


def _send(event: AlertEvent, channel: NotificationChannel) -> None:
    config = json.loads(channel.config or "{}")
    ctype = channel.channel_type

    if ctype == "webhook":
        _send_webhook(event, config)
    elif ctype == "ntfy":
        _send_ntfy(event, config)
    elif ctype == "slack":
        _send_slack_webhook(event, config)
    elif ctype == "email":
        _send_email(event, config)
    else:
        raise ValueError(f"Unknown channel type: {ctype}")


def _send_webhook(event: AlertEvent, config: dict) -> None:
    url = config.get("url")
    if not url:
        raise ValueError("Webhook URL not configured")
    payload = {
        "id": event.id,
        "type": event.alert_type,
        "severity": event.severity,
        "title": event.title,
        "description": event.description,
        "status": event.status,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }
    with httpx.Client(timeout=10) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()


def _send_ntfy(event: AlertEvent, config: dict) -> None:
    url = config.get("url", "https://ntfy.sh")
    topic = config.get("topic")
    if not topic:
        raise ValueError("ntfy topic not configured")
    headers = {
        "Title": event.title[:255],
        "Priority": {"info": "2", "warning": "3", "critical": "5"}.get(event.severity, "3"),
        "Tags": f"dmarc,{event.severity}",
    }
    if config.get("token"):
        headers["Authorization"] = f"Bearer {config['token']}"
    with httpx.Client(timeout=10) as client:
        resp = client.post(
            f"{url.rstrip('/')}/{topic}",
            content=(event.description or event.title).encode(),
            headers=headers,
        )
        resp.raise_for_status()


def _send_slack_webhook(event: AlertEvent, config: dict) -> None:
    url = config.get("url")
    if not url:
        raise ValueError("Slack webhook URL not configured")
    color = {"info": "#36a64f", "warning": "#ff9500", "critical": "#d00000"}.get(event.severity, "#888")
    payload = {
        "attachments": [{
            "color": color,
            "title": event.title,
            "text": event.description or "",
            "footer": f"DMARC Analyzer | {event.severity}",
        }]
    }
    with httpx.Client(timeout=10) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()


def _send_email(event: AlertEvent, config: dict) -> None:
    # TODO: implement SMTP-based email delivery
    # For now, log and mark as unsupported
    logger.info(
        "Email notification not yet implemented for event %s (to: %s)",
        event.id,
        config.get("to"),
    )
    raise NotImplementedError("Email notification channel not yet implemented")
