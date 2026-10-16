"""
Details of an alert about failing mail: which sources sent it, what failed for them and what to do.

An aggregate DMARC report names the sending address, the receiver that reported, the domains in the From
header and the bounce address, and the result of SPF and DKIM. It holds no single message: no subject, no
recipient address. Only a failure report (ruf) can carry those, and only when the receiver sends one.
"""
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    AlertEvent,
    AlertRule,
    DmarcAuthResult,
    DmarcFailureReport,
    DmarcRecord,
    DmarcReport,
    Domain,
    SourceIp,
)
from app.services.senders import load_catalog

# What the alert types count as failing; the single-source types look at one address
FAILING = {
    "dmarc_fail_rate": lambda r: not r.dmarc_pass,
    "spf_fail_rate": lambda r: not r.spf_aligned,
    "dkim_fail_rate": lambda r: not r.dkim_aligned,
}
SOURCE_TYPES = ("new_unknown_source", "high_volume_source", "new_source_dmarc_fail")
# Alert types whose detail page explains the causes
DETAIL_TYPES = (*FAILING, *SOURCE_TYPES)

RESULT_TEXT = {
    "pass": "bestanden", "fail": "fehlgeschlagen", "softfail": "weich fehlgeschlagen", "neutral": "neutral",
    "none": "nicht vorhanden", "temperror": "Zeitüberschreitung", "permerror": "Fehler im Eintrag",
    "policy": "durch Richtlinie verworfen", "": "unbekannt",
}


def provider_name(asn_org: str | None) -> str:
    """Operator name without the registry label: "UZMOBILE-AS - _Uzbektelekom_ Joint Stock Company" gives
    "Uzbektelekom Joint Stock Company"."""
    name = (asn_org or "").split(" - ", 1)[-1].replace("_", "").strip()
    return " ".join(name.split())


def source_label(source: SourceIp | None) -> str:
    """Short name of a source for alert titles and texts: the service or host name, then the provider."""
    if source is None:
        return ""
    name = load_catalog().name(source.sender_key) if source.sender_key else (source.reverse_dns or "")
    provider = provider_name(source.asn_org)
    if provider and provider.lower() in name.lower():
        provider = ""
    return ", ".join(part for part in (name, provider) if part)


def result_text(value: str | None) -> str:
    return RESULT_TEXT.get(value or "", value or "unbekannt")


@dataclass
class FailedSource:
    ip: str
    failed: int = 0
    total: int = 0
    spf: str = ""
    dkim: str = ""
    spf_aligned: bool = False
    dkim_aligned: bool = False
    spf_domains: list[str] = field(default_factory=list)
    dkim_checks: list[str] = field(default_factory=list)
    header_from: list[str] = field(default_factory=list)
    envelope_from: list[str] = field(default_factory=list)
    reporters: list[str] = field(default_factory=list)
    dispositions: list[str] = field(default_factory=list)
    source: SourceIp | None = None
    sender_name: str | None = None
    cause: str = ""
    cause_key: str = "other"


@dataclass
class ReporterShare:
    name: str
    failed: int
    total: int


@dataclass
class Breakdown:
    start: datetime
    end: datetime
    failed: int
    total: int
    sources: list[FailedSource]
    more_sources: int
    reporters: list[ReporterShare]
    failure_reports: int = 0
    causes: list["Cause"] = field(default_factory=list)


def window_minutes(event: AlertEvent, rule: AlertRule | None) -> int:
    """The time window the alert looked at: stored with the event, else from its rule, else one day."""
    try:
        stored = json.loads(event.metrics or "{}").get("window_minutes")
    except (TypeError, ValueError):
        stored = None
    if isinstance(stored, int | float) and stored > 0:
        return int(stored)
    return rule.time_window_minutes if rule else 1440


def _top(values, limit: int = 4) -> list[str]:
    return [value for value, _ in Counter(v for v in values if v).most_common(limit)]


# Why mail fails, in the order of the checks: key, short name, advice for the sender of the alert
CAUSES = {
    "spoof": ("Gefälschter Absender (vermutlich)",
              "Nichts einrichten: Die Quelle gehört nicht zu dir. Mit der DMARC-Richtlinie quarantine oder reject "
              "weisen Empfänger solche Mails ab."),
    "service": ("Dienst ohne passendes SPF oder DKIM",
                "Richte beim Dienst DKIM für deine Domain ein oder nimm ihn in den SPF-Eintrag auf."),
    "unknown": ("Quelle ohne passendes SPF oder DKIM",
                "Gehört die Quelle zu dir, trage ihre Adresse in den SPF-Eintrag ein oder richte DKIM ein. "
                "Gehört sie nicht zu dir, stufe sie unter Quellen als verdächtig ein."),
    "spf": ("SPF passt nicht, DKIM trägt die Mail",
            "Trage den Versender in den SPF-Eintrag der Bounce-Domain ein oder stelle die Bounce-Adresse auf "
            "deine Domain um."),
    "dkim": ("DKIM passt nicht, SPF trägt die Mail",
             "Richte beim Versender DKIM für deine Domain ein oder prüfe Schlüssel und Selector im DNS."),
    "passing": ("Besteht die Prüfung",
                "Gehört die Quelle zu dir, stufe sie unter Quellen als vertrauenswürdig ein; dann meldet sie "
                "nichts mehr."),
    "other": ("Prüfung fehlgeschlagen", "Prüfe die Einzelheiten in den Berichten dieser Quelle."),
}


def spf_snippet(ip: str) -> str:
    return f"{'ip6' if ':' in ip else 'ip4'}:{ip}"


def categorize(item: FailedSource) -> str:
    """Key of the cause of the failures of one source, see CAUSES."""
    if item.failed == 0:
        return "passing"
    if not item.spf_aligned and not item.dkim_aligned:
        if item.sender_name:
            return "service"
        if item.source is not None and item.source.pass_count == 0:
            return "spoof"
        return "unknown"
    if not item.spf_aligned:
        return "spf"
    if not item.dkim_aligned:
        return "dkim"
    return "other"


def diagnose(item: FailedSource) -> str:
    """What the numbers mean for this source and what to do, in a sentence or two."""
    own = item.header_from[0] if item.header_from else "der Absenderdomain"
    key = categorize(item)
    if key == "passing":
        return ("Die Nachrichten dieser Quelle bestehen die Prüfung. Gehört sie zu dir, stufe sie unter Quellen "
                "als vertrauenswürdig ein; sonst beobachte sie.")
    if key == "spoof":
        return ("Weder SPF noch DKIM passen, und von dieser Adresse hat noch nie eine Nachricht DMARC bestanden. "
                "Das ist meist ein gefälschter Absender (Spoofing). Eine strengere DMARC-Richtlinie "
                "(quarantine oder reject) lässt solche Mails abweisen.")
    if key == "service":
        return (f"{item.sender_name} verschickt Mails mit {own} als Absender, aber weder SPF noch DKIM passen zur "
                f"Domain. Richte bei {item.sender_name} DKIM für {own} ein oder nimm den Dienst in den "
                "SPF-Eintrag auf.")
    if key == "unknown":
        return (f"Weder SPF noch DKIM passen zu {own}. Gehört die Adresse zu dir, ergänze im SPF-Eintrag von {own} "
                f"`{spf_snippet(item.ip)}` oder richte DKIM beim Versender ein; sonst ist es vermutlich Missbrauch.")
    if key == "spf":
        if item.spf == "pass":
            return (f"SPF besteht, aber für eine andere Domain ({', '.join(item.spf_domains) or 'Bounce-Adresse'}) "
                    f"als {own}. DKIM trägt die Mail; stelle den Versand so ein, dass die Bounce-Adresse zu "
                    f"{own} passt, oder verlass dich auf DKIM.")
        return (f"SPF schlägt fehl: Die Adresse steht nicht im SPF-Eintrag der Bounce-Domain. Ergänze dort "
                f"`{spf_snippet(item.ip)}`, wenn sie zu dir gehört. DKIM trägt die Mail noch.")
    if key == "dkim":
        if item.dkim in ("none", ""):
            return (f"Die Mails tragen keine DKIM-Signatur für {own}. SPF trägt sie noch; "
                    "bei Weiterleitungen geht das verloren. Richte DKIM beim Versender ein.")
        return (f"Die DKIM-Signatur passt nicht zu {own} oder ist ungültig "
                f"({', '.join(item.dkim_checks) or 'ohne Angabe'}). SPF trägt die Mail noch; prüfe den "
                "DKIM-Schlüssel im DNS und den Selector.")
    return "Die Prüfung ist für diese Mails fehlgeschlagen; prüfe die Einzelheiten der Berichte."


@dataclass
class Cause:
    key: str
    label: str
    advice: str
    messages: int
    sources: int
    examples: list[str] = field(default_factory=list)


def summarize(items: list[FailedSource]) -> list[Cause]:
    """The causes behind the failing sources, the biggest first, each with its advice."""
    grouped: dict[str, list[FailedSource]] = defaultdict(list)
    for item in items:
        item.cause_key = categorize(item)
        grouped[item.cause_key].append(item)
    causes = []
    for key, group in grouped.items():
        label, advice = CAUSES[key]
        names = _top((g.sender_name or (g.source.reverse_dns if g.source else None) or g.ip for g in group), 3)
        causes.append(Cause(key, label, advice, sum(g.failed for g in group), len(group), names))
    return sorted(causes, key=lambda c: c.messages, reverse=True)


def causes_text(causes: list[Cause]) -> str:
    """Sentence for the alert text: the causes with their numbers."""
    if not causes:
        return ""
    parts = [f"{c.label}: {c.messages} Nachrichten von {c.sources} Quelle{'n' if c.sources != 1 else ''}"
             for c in causes[:3]]
    return "Ursachen: " + "; ".join(parts) + "."


def build(db: Session, event: AlertEvent, rule: AlertRule | None = None) -> Breakdown | None:
    """The failing sources behind a fail-rate alert or the records of a single-source alert; None for other types."""
    end = event.created_at
    start = end - timedelta(minutes=window_minutes(event, rule))
    return analyze(db, event.organization_id, event.domain_id, event.alert_type, event.source_ip, start, end)


def analyze(db: Session, org_id: str, domain_id: str | None, alert_type: str, source_ip: str | None,
            start: datetime, end: datetime) -> Breakdown | None:
    """Failing sources, causes and receivers of the reports that arrived in the window; None for other types."""
    if alert_type not in FAILING and alert_type not in SOURCE_TYPES:
        return None
    query = (
        db.query(DmarcRecord, DmarcReport.reporting_org)
        .join(DmarcReport, DmarcRecord.report_id == DmarcReport.id)
        .filter(DmarcReport.organization_id == org_id)
        .filter(DmarcReport.created_at >= start, DmarcReport.created_at < end + timedelta(seconds=1))
    )
    if domain_id:
        query = query.filter(DmarcReport.domain_id == domain_id)
    if alert_type in SOURCE_TYPES:
        if not source_ip:
            return None
        query = query.filter(DmarcRecord.source_ip == source_ip)
    rows = query.all()
    failing = FAILING.get(alert_type, lambda r: not r.dmarc_pass)
    single = alert_type in SOURCE_TYPES

    records = [r for r, _ in rows]
    auth: dict[str, list[DmarcAuthResult]] = defaultdict(list)
    failed_ids = [r.id for r in records if failing(r) or single]
    for chunk_start in range(0, len(failed_ids), 500):
        for result in db.query(DmarcAuthResult).filter(
                DmarcAuthResult.record_id.in_(failed_ids[chunk_start:chunk_start + 500])):
            auth[result.record_id].append(result)

    per_ip: dict[str, list[tuple[DmarcRecord, str | None]]] = defaultdict(list)
    for record, reporter in rows:
        per_ip[record.source_ip].append((record, reporter))
    reporters_failed: Counter = Counter()
    reporters_total: Counter = Counter()
    for record, reporter in rows:
        reporters_total[reporter or "unbekannt"] += record.count
        if failing(record):
            reporters_failed[reporter or "unbekannt"] += record.count

    sources_by_ip = {
        s.ip_address: s for s in db.query(SourceIp).filter(
            SourceIp.organization_id == org_id, SourceIp.ip_address.in_(list(per_ip)))
    } if per_ip else {}
    catalog = load_catalog()

    items = []
    for ip, entries in per_ip.items():
        bad = [(r, rep) for r, rep in entries if failing(r)]
        if not bad and not single:
            continue
        failed_count = sum(r.count for r, _ in bad)
        if not bad:
            bad = entries  # a single source is shown with all its records, even when they pass
        item = FailedSource(ip=ip, failed=failed_count, total=sum(r.count for r, _ in entries))
        item.source = sources_by_ip.get(ip)
        item.sender_name = catalog.name(item.source.sender_key) if item.source and item.source.sender_key else None
        item.spf = (_top((r.spf_result for r, _ in bad), 1) or [""])[0]
        item.dkim = (_top((r.dkim_result for r, _ in bad), 1) or [""])[0]
        # Aligned when it holds for at least half of the messages that failed, so one odd record does not decide
        weight = sum(r.count for r, _ in bad) or 1
        item.spf_aligned = sum(r.count for r, _ in bad if r.spf_aligned) * 2 >= weight
        item.dkim_aligned = sum(r.count for r, _ in bad if r.dkim_aligned) * 2 >= weight
        item.header_from = _top(r.header_from for r, _ in bad)
        item.envelope_from = _top(r.envelope_from for r, _ in bad)
        item.reporters = _top(rep for _, rep in bad)
        item.dispositions = _top(r.disposition for r, _ in bad)
        results = [a for r, _ in bad for a in auth.get(r.id, [])]
        item.spf_domains = _top(f"{a.domain} ({result_text(a.result)})" for a in results if a.auth_type == "spf")
        item.dkim_checks = _top(
            f"{a.domain or '—'}{' · ' + a.selector if a.selector else ''} ({result_text(a.result)})"
            for a in results if a.auth_type == "dkim")
        item.cause = diagnose(item)
        items.append(item)
    items.sort(key=lambda i: i.failed, reverse=True)

    limit = settings.UI_ALERT_DETAIL_SOURCES
    failure_reports = 0
    if domain_id:
        failure_reports = db.query(DmarcFailureReport.id).filter(
            DmarcFailureReport.organization_id == org_id,
            DmarcFailureReport.domain_id == domain_id,
            DmarcFailureReport.created_at >= start, DmarcFailureReport.created_at < end + timedelta(seconds=1),
        ).count()
    return Breakdown(
        start=start, end=end,
        failed=sum(i.failed for i in items), total=sum(r.count for r in records),
        sources=items[:limit], more_sources=max(0, len(items) - limit),
        reporters=sorted((ReporterShare(n, reporters_failed[n], reporters_total[n]) for n in reporters_total
                          if reporters_failed[n]), key=lambda x: x.failed, reverse=True),
        failure_reports=failure_reports, causes=summarize(items),
    )


def top_sources_text(db: Session, org_id: str, records: list[DmarcRecord], failing, limit: int) -> str:
    """Sentence naming the sources behind the failures, for the text of the alert; empty without any."""
    if limit <= 0:
        return ""
    failed: Counter = Counter()
    for record in records:
        if failing(record):
            failed[record.source_ip] += record.count
    if not failed:
        return ""
    ips = [ip for ip, _ in failed.most_common(limit)]
    known = {s.ip_address: s for s in db.query(SourceIp).filter(
        SourceIp.organization_id == org_id, SourceIp.ip_address.in_(ips))}
    parts = []
    for ip in ips:
        label = source_label(known.get(ip))
        parts.append(f"{ip}{f' ({label})' if label else ''}: {failed[ip]}")
    rest = len(failed) - len(ips)
    return "Häufigste Quellen: " + ", ".join(parts) + (f" und {rest} weitere" if rest > 0 else "") + "."


@dataclass
class SourceContext:
    domains: list[tuple[str, int]]
    more_domains: int
    messages: int
    passed: int
    spf_aligned: int
    dkim_aligned: int
    reporters: list[str]

    def domains_text(self) -> str:
        names = ", ".join(f"{name} ({count})" for name, count in self.domains)
        return names + (f" und {self.more_domains} weitere" if self.more_domains else "")


def source_context(db: Session, org_id: str, ip: str, limit: int | None = None) -> SourceContext:
    """Which domains an address sent for, how its mail fared and who reported it, over all reports."""
    limit = settings.ALERT_DESCRIPTION_DOMAINS if limit is None else limit
    rows = (
        db.query(DmarcRecord, DmarcReport.reporting_org, Domain.name)
        .join(DmarcReport, DmarcRecord.report_id == DmarcReport.id)
        .outerjoin(Domain, Domain.id == DmarcRecord.domain_id)
        .filter(DmarcRecord.organization_id == org_id, DmarcRecord.source_ip == ip)
        .all()
    )
    per_domain: Counter = Counter()
    reporters: Counter = Counter()
    context = SourceContext([], 0, 0, 0, 0, 0, [])
    for record, reporter, name in rows:
        per_domain[name or record.header_from or "unbekannte Domain"] += record.count
        reporters[reporter or "unbekannt"] += record.count
        context.messages += record.count
        context.passed += record.count if record.dmarc_pass else 0
        context.spf_aligned += record.count if record.spf_aligned else 0
        context.dkim_aligned += record.count if record.dkim_aligned else 0
    ordered = per_domain.most_common()
    context.domains = ordered[:limit] if limit else []
    context.more_domains = max(0, len(ordered) - len(context.domains))
    context.reporters = [name for name, _ in reporters.most_common(3)]
    return context


def source_text(db: Session, org_id: str, source: SourceIp) -> str:
    """Context for the text of an alert about one source: domains, results, host, network, receivers."""
    context = source_context(db, org_id, source.ip_address)
    parts = []
    if context.domains:
        parts.append(f"Sie verschickt Mails für {context.domains_text()}.")
    if context.messages:
        parts.append(f"SPF passt bei {context.spf_aligned} von {context.messages} Nachrichten, "
                     f"DKIM bei {context.dkim_aligned}.")
    where = [part for part in (
        f"Hostname {source.reverse_dns}" if source.reverse_dns else
        ("kein Hostname (rDNS) eingetragen" if source.enriched_at else ""),
        f"Netz AS{source.asn} ({source.asn_org})" if source.asn and source.asn_org else
        (f"Netz AS{source.asn}" if source.asn else ""),
        f"Land {source.country_code}" if source.country_code else "") if part]
    if where:
        parts.append(", ".join(where) + ".")
    if context.reporters:
        parts.append(f"Angenommen von: {', '.join(context.reporters)}.")
    return " ".join(parts)

