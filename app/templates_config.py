"""Shared Jinja2 template configuration: filters, navigation and page-wide context."""
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.services import report_formats, tls_reports
from app.version import APP_NAME, VERSION

logger = logging.getLogger(__name__)


# Navigation ------------------------------------------------------------------

@dataclass
class NavLink:
    label: str
    href: str
    prefixes: tuple[str, ...] = ()
    superadmin_only: bool = False
    external: bool = False


@dataclass
class NavModule:
    label: str
    icon: str
    links: list[NavLink] = field(default_factory=list)


NAVIGATION = [
    NavModule("Übersicht", "home", [NavLink("Übersicht", "/dashboard", ("/dashboard",))]),
    NavModule("Domains", "globe", [NavLink("Domains", "/domains", ("/domains",))]),
    NavModule("Berichte", "file", [
        NavLink("Berichte", "/reports", ("/reports",)),
        NavLink("Fehlerberichte", "/failure-reports", ("/failure-reports",)),
        NavLink("TLS-Berichte", "/tls-reports", ("/tls-reports",)),
        NavLink("Hochladen", "/upload", ("/upload",)),
        NavLink("Importe", "/imports", ("/imports",)),
    ]),
    NavModule("Quellen", "server", [
        NavLink("Absender", "/senders", ("/senders",)),
        NavLink("IP-Adressen", "/source-ips", ("/source-ips",)),
    ]),
    NavModule("Alarme", "bell", [
        NavLink("Ereignisse", "/alerts/events", ("/alerts/events",)),
        NavLink("Regeln", "/alerts/rules", ("/alerts/rules",)),
        NavLink("Kanäle", "/alerts/channels", ("/alerts/channels",)),
        NavLink("Wochenbericht", "/alerts/digest", ("/alerts/digest",)),
    ]),
    NavModule("Empfang", "mail", [
        NavLink("Status", "/smtp/status", ("/smtp/status",)),
        NavLink("Eingegangene Mails", "/smtp/messages", ("/smtp/messages",)),
        NavLink("Abgelehnte Empfänger", "/smtp/rejections", ("/smtp/rejections",), superadmin_only=True),
    ]),
    NavModule("Verwaltung", "sliders", [
        NavLink("Benutzer", "/users", ("/users",)),
        NavLink("API-Tokens", "/api-tokens", ("/api-tokens",)),
        NavLink("Organisationen", "/organizations", ("/organizations",), superadmin_only=True),
        NavLink("API-Dokumentation", "/api/docs", external=True),
    ]),
    NavModule("Hilfe", "info", [NavLink("DMARC-Formate", "/hilfe/dmarc-formate", ("/hilfe",))]),
]


@dataclass
class RailLink:
    label: str
    href: str
    current: bool
    external: bool


@dataclass
class RailModule:
    key: str
    label: str
    icon: str
    href: str | None          # set for modules with a single page
    links: list[RailLink]
    open: bool


def build_rail(path: str, user) -> list[RailModule]:
    is_superadmin = bool(getattr(user, "is_superadmin", False))
    modules = []
    for index, module in enumerate(NAVIGATION):
        links = [
            RailLink(link.label, link.href,
                     current=any(path == p or path.startswith(p + "/") for p in link.prefixes),
                     external=link.external)
            for link in module.links
            if is_superadmin or not link.superadmin_only
        ]
        if not links:
            continue
        single = len(module.links) == 1
        modules.append(RailModule(
            key=f"m{index}",
            label=module.label,
            icon=module.icon,
            href=links[0].href if single else None,
            links=[] if single else links,
            open=any(link.current for link in links),
        ))
    return modules


def current_page(modules: list[RailModule]) -> tuple[str | None, str | None]:
    """Module label and page label for the breadcrumbs."""
    for module in modules:
        if module.href and module.open:
            return module.label, None
        for link in module.links:
            if link.current:
                return module.label, link.label
    return None, None


# Formatting -------------------------------------------------------------------

def _zone() -> ZoneInfo:
    try:
        return ZoneInfo(settings.DISPLAY_TIMEZONE)
    except Exception:  # unknown zone or missing tz database
        logger.warning("Time zone %r unavailable, showing UTC", settings.DISPLAY_TIMEZONE)
        return ZoneInfo("UTC")


def _local(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(_zone())


def _format_datetime(value: datetime | None, fmt: str = "%d.%m.%Y %H:%M") -> str:
    if value is None:
        return "—"
    return _local(value).strftime(fmt)


def _format_date(value: datetime | date | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, datetime):
        value = _local(value)
    return value.strftime("%d.%m.%Y")


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _format_utc(value: datetime | None) -> str:
    """Moment in UTC, for periods that reporters give in UTC."""
    if value is None:
        return "—"
    return f"{_as_utc(value):%d.%m.%Y %H:%M} UTC"


def _day_span(begin: datetime | None, end: datetime | None) -> str:
    """Reported days in UTC, e.g. 28.09.2026 or 26.09. – 27.09.2026. The end is the last second or the next day."""
    if begin is None:
        return "—"
    begin = _as_utc(begin)
    end = _as_utc(end) if end is not None else begin
    first = begin.date()
    last = (end - timedelta(seconds=1)).date() if end > begin else first
    return f"{first:%d.%m.%Y}" if last <= first else f"{first:%d.%m.} – {last:%d.%m.%Y}"


def _format_number(value: int | float | None, decimals: int = 0) -> str:
    if value is None:
        return "—"
    text = f"{value:,.{decimals}f}"
    return text.replace(",", " ").replace(".", ",").replace(" ", ".")


def _format_percent(value: float | None, decimals: int = 1) -> str:
    if value is None:
        return "—"
    return f"{_format_number(value, decimals)} %"


def _filesizeformat(value: int | None) -> str:
    if value is None:
        return "—"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{_format_number(size, 0 if unit == 'B' else 1)} {unit}"
        size /= 1024
    return f"{_format_number(size, 1)} TB"


def _plural(value: int | float | None, one: str, many: str) -> str:
    """Number with its word in singular or plural, e.g. 1 Adresse, 2 Adressen."""
    count = value or 0
    return f"{_format_number(count)} {one if count == 1 else many}"


def _interval(seconds: int | None) -> str:
    """Repeat interval in words, e.g. alle 5 Minuten."""
    if not seconds:
        return "—"
    for size, one, many in ((86_400, "täglich", "Tage"), (3600, "stündlich", "Stunden"),
                            (60, "jede Minute", "Minuten")):
        if seconds % size == 0:
            count = seconds // size
            return one if count == 1 else f"alle {_format_number(count)} {many}"
    return f"alle {_format_number(seconds)} Sekunden"


def _tls_rate_state(rate: float | None) -> str:
    """State pill modifier for the share of failed TLS sessions."""
    if rate is None:
        return ""
    if rate == 0:
        return "bc-state--on"
    if rate < settings.ALERT_DEFAULT_TLS_FAIL_RATE:
        return "bc-state--warn"
    return "bc-state--bad"


def _rate_state(rate: float | None) -> str:
    """State pill modifier for a DMARC pass rate."""
    if rate is None:
        return ""
    if rate >= settings.UI_PASS_RATE_GOOD:
        return "bc-state--on"
    if rate >= settings.UI_PASS_RATE_WARN:
        return "bc-state--warn"
    return "bc-state--bad"


SEVERITY_STATE = {"info": "", "warning": "bc-state--warn", "critical": "bc-state--bad"}
SEVERITY_TEXT = {"info": "Hinweis", "warning": "Warnung", "critical": "kritisch"}

STATUS_STATE = {
    "completed": "bc-state--on", "active": "bc-state--on", "resolved": "bc-state--on", "imported": "bc-state--on",
    "sent": "bc-state--on", "skipped": "",
    "quarantine": "bc-state--warn",
    "processing": "bc-state--warn", "pending": "bc-state--warn", "open": "bc-state--warn",
    "acknowledged": "", "disabled": "", "ignored": "",
    "failed": "bc-state--bad", "revoked": "bc-state--bad", "rejected": "bc-state--bad", "error": "bc-state--bad",
}
STATUS_TEXT = {
    "completed": "fertig", "processing": "läuft", "pending": "wartet", "failed": "fehlgeschlagen",
    "active": "aktiv", "disabled": "deaktiviert", "revoked": "widerrufen",
    "open": "offen", "acknowledged": "gesehen", "resolved": "erledigt", "ignored": "ignoriert",
    "imported": "importiert", "rejected": "abgelehnt", "error": "Fehler", "quarantine": "zurückgehalten",
    "sent": "verschickt", "skipped": "übersprungen",
}

CLASSIFICATION_STATE = {"trusted": "bc-state--on", "unknown": "bc-state--warn", "suspicious": "bc-state--bad",
                        "ignored": ""}
CLASSIFICATION_TEXT = {"trusted": "vertrauenswürdig", "unknown": "unbekannt", "suspicious": "verdächtig",
                       "ignored": "ignoriert"}

DISPOSITION_STATE = {"none": "", "pass": "bc-state--on", "quarantine": "bc-state--warn", "reject": "bc-state--bad"}

SOURCE_TEXT = {"smtp_inbound": "SMTP-Empfang", "web_upload": "Hochgeladen", "api": "API"}

# Delivery-Result of a failure report (RFC 6591, 3.1)
DELIVERY_TEXT = {"delivered": "zugestellt", "spam": "als Spam einsortiert", "policy": "nach Richtlinie behandelt",
                 "reject": "abgewiesen", "other": "anders behandelt"}
DELIVERY_STATE = {"delivered": "", "spam": "bc-state--warn", "policy": "bc-state--warn", "reject": "bc-state--bad",
                  "other": ""}
ALIGNMENT_TEXT = {"none": "weder DKIM noch SPF passen zur Domain", "dkim": "DKIM passt zur Domain",
                  "spf": "SPF passt zur Domain"}


def _alignment_text(value: str | None) -> str:
    """Identity-Alignment of a failure report in words; the field lists the identifiers that matched."""
    parts = {part.strip() for part in (value or "").split(",") if part.strip()}
    if parts == {"dkim", "spf"}:
        return "DKIM und SPF passen zur Domain"
    if len(parts) == 1:
        return ALIGNMENT_TEXT.get(parts.pop(), "")
    return ""

# DNS check: state of one check and of the whole domain (None: never checked)
DNS_STATE_TEXT = {"ok": "in Ordnung", "info": "Hinweis", "warning": "Warnung", "error": "Fehler",
                  "unknown": "keine Antwort"}
DNS_STATUS_TEXT = {"ok": "in Ordnung", "warning": "Warnungen", "error": "Fehler", "unknown": "unvollständig",
                   "": "noch nicht geprüft"}
DNS_STATE = {"ok": "bc-state--on", "warning": "bc-state--warn", "error": "bc-state--bad"}
DNS_ICON = {"ok": "i-check", "info": "i-st-info", "warning": "i-st-warn", "error": "i-st-error",
            "unknown": "i-st-unknown", "": "i-st-none"}

ROLE_TEXT = {"super_admin": "Betreiber", "org_admin": "Administrator", "manager": "Manager", "analyst": "Analyst",
             "read_only": "Lesezugriff", "member": "Mitglied", "viewer": "Lesezugriff"}


def _lookup(mapping: dict, keep_unknown: bool = False):
    """Filter that maps a stored value to a text or CSS class; unknown values stay as they are or vanish."""
    def lookup(value):
        key = value or ""
        if key in mapping:
            return mapping[key]
        return key if keep_unknown else ""
    return lookup


# Report file names after RFC 7489, 7.2.1.1: receiver!policy-domain!begin!end[!unique-id].extension
REPORT_FILE_NAME = re.compile(
    r"^(?P<host>[^!/\\]+)!(?P<domain>[^!/\\]+)!(?P<begin>\d{9,11})!(?P<end>\d{9,11})(?:![^/\\]*?)?"
    r"\.(?:xml\.gz|xml|gz|zip)$",
    re.IGNORECASE,
)


def report_file_parts(name: str | None) -> dict | None:
    """Receiver, domain and reported days from a report file name; None for other names."""
    match = REPORT_FILE_NAME.match(name or "")
    if not match:
        return None
    period = _day_span(datetime.fromtimestamp(int(match["begin"]), UTC), datetime.fromtimestamp(int(match["end"]), UTC))
    return {"host": match["host"], "domain": match["domain"], "period": period}


def _tojson(value) -> str:
    return json.dumps(value)


def flash(request: Request, kind: str, title: str, text: str = "") -> None:
    """Message for the next page the user sees; kind is ok, warn or bad."""
    request.session["flash"] = {"kind": kind, "title": title, "text": text}


def page_url(request: Request, page: int) -> str:
    """Current URL with another page number; keeps the other query parameters."""
    params = dict(request.query_params)
    params["page"] = str(page)
    return "?" + urlencode(params)


# Page-wide context --------------------------------------------------------------

def _with_db(request: Request, work, default):
    """Run a small query for the page frame on the database the request uses."""
    from app.database import get_db
    source = request.app.dependency_overrides.get(get_db, get_db)()
    try:
        return work(next(source))
    except Exception:
        logger.exception("Page context query failed")
        return default
    finally:
        source.close()


def _open_alert_count(request: Request) -> int:
    org_id = request.session.get("org_id") if "session" in request.scope else None
    if not org_id:
        return 0
    from app.models import AlertEvent
    return _with_db(
        request, lambda db: db.query(AlertEvent.id).filter_by(organization_id=org_id, status="open").count(), 0,
    )


def _rights(request: Request) -> dict[str, bool]:
    """What the signed-in user may do in the current organisation, for showing or hiding forms."""
    session = request.session if "session" in request.scope else {}
    user_id, org_id = session.get("user_id"), session.get("org_id")
    level = -1
    if user_id:
        from app.models import User
        from app.services.auth import role_level

        def lookup(db):
            user = db.query(User).filter_by(id=user_id, is_active=True).first()
            return role_level(db, user, org_id) if user else -1
        level = _with_db(request, lookup, -1)
    from app.services.auth import ROLE_LEVEL
    return {"analyst": level >= ROLE_LEVEL["analyst"], "manager": level >= ROLE_LEVEL["manager"],
            "admin": level >= ROLE_LEVEL["org_admin"]}


def page_context(request: Request) -> dict:
    return {
        "app_name": APP_NAME,
        "version": VERSION,
        "open_alert_count": _open_alert_count(request),
        "can": _rights(request),
        "flash": request.session.pop("flash", None) if "session" in request.scope else None,
        "password_min_length": settings.PASSWORD_MIN_LENGTH,
    }


templates = Jinja2Templates(directory="app/templates", context_processors=[page_context])

env = templates.env
env.filters["datetime"] = _format_datetime
env.filters["date"] = _format_date
env.filters["num"] = _format_number
env.filters["percent"] = _format_percent
env.filters["filesizeformat"] = _filesizeformat
env.filters["rate_state"] = _rate_state
env.filters["interval"] = _interval
env.filters["plural"] = _plural
env.filters["severity_state"] = _lookup(SEVERITY_STATE)
env.filters["severity_text"] = _lookup(SEVERITY_TEXT, keep_unknown=True)
env.filters["status_state"] = _lookup(STATUS_STATE)
env.filters["status_text"] = _lookup(STATUS_TEXT, keep_unknown=True)
env.filters["classification_state"] = _lookup(CLASSIFICATION_STATE)
env.filters["classification_text"] = _lookup(CLASSIFICATION_TEXT, keep_unknown=True)
env.filters["disposition_state"] = _lookup(DISPOSITION_STATE)
env.filters["disposition_text"] = _lookup(report_formats.DISPOSITION_TEXT, keep_unknown=True)
env.filters["reason_text"] = _lookup(report_formats.REASON_TEXT, keep_unknown=True)
env.filters["discovery_text"] = _lookup(report_formats.DISCOVERY_TEXT, keep_unknown=True)
env.filters["source_text"] = _lookup(SOURCE_TEXT, keep_unknown=True)
env.filters["delivery_text"] = _lookup(DELIVERY_TEXT, keep_unknown=True)
env.filters["delivery_state"] = _lookup(DELIVERY_STATE)
env.filters["alignment_text"] = _alignment_text
env.filters["utc"] = _format_utc
env.filters["day_span"] = _day_span
env.filters["tls_rate_state"] = _tls_rate_state
env.filters["dns_state_text"] = _lookup(DNS_STATE_TEXT, keep_unknown=True)
env.filters["dns_status_text"] = _lookup(DNS_STATUS_TEXT, keep_unknown=True)
env.filters["dns_state"] = _lookup(DNS_STATE)
env.filters["dns_icon"] = _lookup(DNS_ICON)
env.filters["tls_policy_text"] = _lookup(tls_reports.POLICY_TEXT, keep_unknown=True)
env.filters["tls_policy_hint"] = _lookup(tls_reports.POLICY_HINT)
env.filters["tls_result_text"] = _lookup(tls_reports.RESULT_TEXT, keep_unknown=True)
env.filters["tls_result_hint"] = _lookup(tls_reports.RESULT_HINT)
env.filters["role_text"] = _lookup(ROLE_TEXT, keep_unknown=True)
env.filters["tojson"] = _tojson
env.globals["page_url"] = page_url
env.globals["build_rail"] = build_rail
env.globals["current_page"] = current_page
env.globals["format_info"] = report_formats.format_info
env.globals["evidence_texts"] = report_formats.evidence_texts
env.globals["report_file_parts"] = report_file_parts
env.globals["now"] = lambda: datetime.now(UTC)
