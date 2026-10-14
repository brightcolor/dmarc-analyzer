"""
Mail texts for alerts and the weekly digest: plain text plus HTML in the bright color mail style.
Templates live in app/templates/mail; .html is escaped, .txt stays as written.
"""
import json
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from app.config import settings
from app.templates_config import (
    CLASSIFICATION_TEXT,
    _as_utc,
    _format_date,
    _format_datetime,
    _format_number,
    _format_percent,
)
from app.templates_config import (
    env as web_env,
)
from app.version import APP_NAME

MAIL_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates" / "mail"
LOGO_PATH = "/static/bc/logo/png/bc-logo-light-noclaim.png"

SEVERITY_LABELS = {"info": "Hinweis", "warning": "Warnung", "critical": "Kritisch"}
TEST_ALERT_TYPE = "test"
# Square in the label line: pink for critical, yellow for warnings, cyan for notes
SEVERITY_SQUARE = {"info": "#1dc3f3", "warning": "#fed329", "critical": "#d61f7a"}


@lru_cache(maxsize=1)
def mail_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(MAIL_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters.update(web_env.filters)
    return env


def _app_url() -> str:
    return settings.APP_URL.rstrip("/")


def _common() -> dict:
    app_url = _app_url()
    return {"app_name": APP_NAME, "app_url": app_url, "logo_url": app_url + LOGO_PATH}


def _render(name: str, context: dict) -> tuple[str, str]:
    env = mail_env()
    return env.get_template(f"{name}.txt").render(context), env.get_template(f"{name}.html").render(context)


def render_alert_mail(event, channel, recipient: str | None = None) -> tuple[str, str, str]:
    """Subject, text and HTML for one alert event, sent over an email channel or to a further recipient
    of the event's domain (channel None)."""
    from app.services.alert_service import ALERT_TYPES
    from app.services.notification import event_url

    severity = SEVERITY_LABELS.get(event.severity, event.severity)
    try:
        metrics = json.loads(event.metrics or "{}")
    except (TypeError, ValueError):
        metrics = {}
    facts = []
    if event.domain:
        facts.append(("Domain", event.domain.name))
    if event.source_ip:
        facts.append(("Quelle", event.source_ip))
    facts.append(("Schwere", severity))
    facts.append(("Zeitpunkt", _format_datetime(event.created_at)))
    context = {
        **_common(),
        "event": event,
        "channel": channel,
        "recipient": recipient,
        "domain_url": f"{_app_url()}/domains/{event.domain_id}" if event.domain_id else _app_url(),
        "organization": event.organization or channel.organization,
        "rule": event.rule,
        "is_test": event.alert_type == TEST_ALERT_TYPE,
        "metrics": metrics,
        "facts": facts,
        "severity_label": severity,
        "square": SEVERITY_SQUARE.get(event.severity, SEVERITY_SQUARE["info"]),
        "type_label": ALERT_TYPES.get(event.alert_type, "Testnachricht"),
        "event_url": event_url(event),
    }
    subject = f"{severity}: {event.title}"
    text, html = _render("alert", context)
    return subject, text, html


SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
SEVERITY_COUNT_WORDS = {"critical": ("kritischer Alarm", "kritische Alarme"), "warning": ("Warnung", "Warnungen"),
                        "info": ("Hinweis", "Hinweise")}


def render_alert_bundle(events, channel=None, recipient: str | None = None) -> tuple[str, str, str]:
    """Subject, text and HTML for several alerts in one mail, most severe first."""
    from app.config import settings as current

    # Times from SQLite come without zone, those of alerts still in the session with one
    events = sorted(events, key=lambda e: (SEVERITY_ORDER.get(e.severity, 9), _as_utc(e.created_at)))
    shown = events[:current.NOTIFICATION_BUNDLE_MAX_ITEMS]
    organization = events[0].organization or (channel.organization if channel else None)
    domains = sorted({e.domain.name for e in events if e.domain})
    title = ", ".join(domains) if recipient and domains else organization.name
    counts = {level: sum(1 for e in events if e.severity == level) for level in SEVERITY_COUNT_WORDS}
    summary = " · ".join(_plural(counts[level], *SEVERITY_COUNT_WORDS[level])
                         for level in SEVERITY_COUNT_WORDS if counts[level])
    subject = f"{len(events)} Alarme für {title}"
    if counts["critical"]:
        subject = f"Kritisch: {subject}"
    context = {
        **_common(),
        "subject": subject,
        "title": title,
        "summary": summary,
        "count": len(events),
        "more": len(events) - len(shown),
        "items": [
            {"title": e.title, "severity": SEVERITY_LABELS.get(e.severity, e.severity),
             "domain": e.domain.name if e.domain else None, "time": _format_datetime(e.created_at),
             "description": e.description}
            for e in shown
        ],
        "organization": organization,
        "channel": channel,
        "recipient": recipient,
        "domains": domains,
        "square": SEVERITY_SQUARE.get(events[0].severity, SEVERITY_SQUARE["info"]),
        "events_url": f"{_app_url()}/alerts/events?status=open",
    }
    text, html = _render("alert_bundle", context)
    return subject, text, html


def _plural(count: int, one: str, many: str) -> str:
    return f"{_format_number(count)} {one if count == 1 else many}"


def _source_label(line) -> str:
    return f"{line.ip} ({line.name})" if line.name else line.ip


def _change_text(data) -> str:
    comparison = "gegenüber der Vorwoche" if data.days == 7 else "gegenüber dem Zeitraum davor"
    change = data.rate_change
    if change is None:
        return "Für einen Vergleich fehlen Berichte aus dem Zeitraum davor."
    if abs(change) < 0.05:
        return f"Unverändert {comparison}."
    sign = "+" if change > 0 else "−"
    return f"{sign}{_format_number(abs(change), 1)} Prozentpunkte {comparison}"


def render_digest_mail(data, recipient) -> tuple[str, str, str]:
    """Subject, text and HTML of the weekly digest for one recipient."""
    org = data.organization
    title = ", ".join(data.scope) if data.scope else org.name
    if data.total:
        subject = f"DMARC-Wochenbericht {title}: {_format_percent(data.rate)} bestanden"
    else:
        subject = f"DMARC-Wochenbericht {title}: keine Berichte eingegangen"
    context = {
        **_common(),
        "data": data,
        "organization": org,
        "recipient": recipient,
        "title": title,
        "period_text": f"{_format_date(data.start)} bis {_format_date(data.end)}",
        "change_text": _change_text(data),
        "summary_rows": [
            ("Nachrichten", _format_number(data.total)),
            ("Bestanden", _format_number(data.passed)),
            ("Nicht bestanden", _format_number(data.failed)),
            ("Berichte", _format_number(data.reports)),
            ("Berichtende Empfänger", _format_number(data.reporters)),
        ],
        "domain_rows": [
            (line.name, f"{_plural(line.total, 'Nachricht', 'Nachrichten')} · "
                        f"{_format_percent(line.rate)} bestanden" if line.total else "keine Berichte")
            for line in data.domains
        ],
        "failing_rows": [
            (_source_label(line), f"{_format_number(line.failed)} von {_format_number(line.total)} nicht bestanden")
            for line in data.failing_sources
        ],
        "new_rows": [
            (_source_label(line), f"{_plural(line.total, 'Nachricht', 'Nachrichten')} · "
                                  f"{CLASSIFICATION_TEXT.get(line.classification, line.classification)}")
            for line in data.new_sources
        ],
        "new_heading": "Eine neue Quelle" if data.new_source_count == 1
        else f"{_format_number(data.new_source_count)} neue Quellen",
        "alert_heading": "Ein offener Alarm" if data.open_alert_count == 1
        else f"{_format_number(data.open_alert_count)} offene Alarme",
        "formats_text": " · ".join(
            f"{label}: {_plural(count, 'Bericht', 'Berichte')}" for label, count in data.formats
        ),
    }
    text, html = _render("digest", context)
    return subject, text, html
