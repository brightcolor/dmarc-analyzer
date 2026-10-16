"""
The list of alerts, ordered for reading: rows with domain, cause and source, and groups for alerts of one kind
about one domain, so 228 alerts about forged senders of one domain are one line with one set of actions.

Domains and causes come from the metrics an alert stores when it is raised (see alert_service).
"""
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from app.config import settings
from app.models import AlertEvent, Domain
from app.services.alert_details import DETAIL_TYPES, SOURCE_TYPES

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


@dataclass
class Row:
    event: AlertEvent
    title: str
    domains: list[str] = field(default_factory=list)
    domains_more: int = 0
    causes: list[dict] = field(default_factory=list)
    source: str = ""
    detail: bool = False
    metrics: dict = field(default_factory=dict)

    @property
    def domain(self) -> str:
        return self.domains[0] if self.domains else ""


@dataclass
class Group:
    alert_type: str
    domain: str
    rows: list[Row]
    label: str = ""

    @property
    def count(self) -> int:
        return len(self.rows)

    @property
    def domain_names(self) -> list[str]:
        """The domains of the group in order of appearance; a group per kind lists several."""
        names: list[str] = []
        for row in self.rows:
            for name in row.domains:
                if name not in names:
                    names.append(name)
        return names

    @property
    def severity(self) -> str:
        return min((r.event.severity for r in self.rows), key=lambda s: SEVERITY_ORDER.get(s, 3))

    @property
    def latest(self) -> datetime:
        return max(r.event.created_at for r in self.rows)

    @property
    def open_count(self) -> int:
        return sum(1 for r in self.rows if r.event.status == "open")

    @property
    def causes(self) -> list[tuple[str, int]]:
        """Causes summed over the group, the biggest first."""
        total: Counter = Counter()
        for row in self.rows:
            for cause in row.causes:
                total[cause.get("label", "")] += int(cause.get("messages", 0))
        return [(label, n) for label, n in total.most_common(3) if label]

    @property
    def messages(self) -> int:
        return sum(int(r.metrics.get("total", 0) or 0) for r in self.rows if r.event.alert_type in SOURCE_TYPES)

    @property
    def sources(self) -> int:
        return len({r.event.source_ip for r in self.rows if r.event.source_ip})


def _metrics(event: AlertEvent) -> dict:
    try:
        value = json.loads(event.metrics or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _row(event: AlertEvent, domain_names: dict[str, str], type_labels: dict[str, str]) -> Row:
    metrics = _metrics(event)
    domains = list(metrics.get("domains") or [])
    if not domains and event.domain_id in domain_names:
        domains = [domain_names[event.domain_id]]
    title = event.title
    if event.alert_type in SOURCE_TYPES and event.source_ip:
        # The domains and the host name stand in their own places, so the title keeps what happened
        title = f"{type_labels.get(event.alert_type, event.alert_type)} {event.source_ip}"
    causes = [c for c in (metrics.get("causes") or []) if isinstance(c, dict)]
    return Row(event=event, title=title, domains=domains, domains_more=int(metrics.get("domains_more") or 0),
               causes=causes, source=str(metrics.get("source_label") or ""),
               detail=event.alert_type in DETAIL_TYPES, metrics=metrics)


def _query(db: Session, org_id: str, status: str | None, severity: str | None):
    query = db.query(AlertEvent).filter_by(organization_id=org_id)
    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)
    return query.order_by(AlertEvent.created_at.desc())


def load_rows(db: Session, org_id: str, status: str | None, severity: str | None,
              type_labels: dict[str, str]) -> tuple[list[Row], bool]:
    """Rows of the alerts matching the filter, newest first; the flag says that more alerts exist than were loaded."""
    limit = settings.UI_ALERT_GROUP_LIMIT
    events = _query(db, org_id, status, severity).limit(limit + 1).all()
    truncated = len(events) > limit
    events = events[:limit]
    ids = {e.domain_id for e in events if e.domain_id}
    names = {d.id: d.name for d in db.query(Domain).filter(Domain.id.in_(ids))} if ids else {}
    return [_row(e, names, type_labels) for e in events], truncated


def group_rows(rows: list[Row], type_labels: dict[str, str]) -> list[Group]:
    """Alerts of one kind about one domain form a group; the groups come by severity, then by newest alert."""
    by_type = settings.ui_alert_group_by_type
    grouped: dict[tuple[str, str], list[Row]] = {}
    for row in rows:
        # Kinds that arise once per domain form one group over all domains
        key = (row.event.alert_type, "" if row.event.alert_type in by_type else row.domain)
        grouped.setdefault(key, []).append(row)
    groups = [Group(alert_type=key[0], domain=key[1], rows=members, label=type_labels.get(key[0], key[0]))
              for key, members in grouped.items()]
    groups.sort(key=lambda g: (SEVERITY_ORDER.get(g.severity, 3), -g.latest.timestamp()))
    return groups


def members(db: Session, org_id: str, alert_type: str, domain: str, status: str | None,
            severity: str | None, type_labels: dict[str, str]) -> list[AlertEvent]:
    """The alerts of one group, for the actions on a whole group."""
    rows, _ = load_rows(db, org_id, status, severity, type_labels)
    whole_kind = alert_type in settings.ui_alert_group_by_type
    return [r.event for r in rows if r.event.alert_type == alert_type and (whole_kind or r.domain == domain)]
