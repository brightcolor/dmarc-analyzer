"""
Rule-based recommendation engine for DMARC domains.
Deterministic and explainable; all thresholds come from settings.
"""
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.models import DmarcRecord, DmarcReport, Domain, InboundMailAddress, SourceIp

ENFORCING_POLICIES = ("quarantine", "reject")
POLICY_ACTION = {"quarantine": "in den Spam-Ordner", "reject": "abgewiesen"}


@dataclass
class Recommendation:
    code: str
    severity: str  # info, warning, critical
    title: str
    description: str
    data_basis: str


def _pct(value: float) -> str:
    """Percentage in German notation, e.g. 96,4 %."""
    return f"{value:.1f}".replace(".", ",") + " %"


def _n(value: int) -> str:
    """Count with German thousands separator, e.g. 1.105."""
    return f"{value:,}".replace(",", ".")


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def get_recommendations_for_domain(db: Session, org_id: str, domain_id: str) -> list[Recommendation]:
    recs: list[Recommendation] = []
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org_id).first()
    if not domain:
        return recs

    now = datetime.now(UTC)
    window_days = settings.RECOMMENDATION_WINDOW_DAYS
    stale_days = settings.RECOMMENDATION_STALE_REPORT_DAYS
    window_start = now - timedelta(days=window_days)
    stale_since = now - timedelta(days=stale_days)

    # --- Report address ---
    has_address = (
        db.query(InboundMailAddress)
        .filter_by(organization_id=org_id, domain_id=domain_id, status="active")
        .first()
        is not None
    )
    if not has_address:
        has_org_address = (
            db.query(InboundMailAddress)
            .filter_by(organization_id=org_id, status="active")
            .filter(InboundMailAddress.domain_id.is_(None))
            .first()
            is not None
        )
        if not has_org_address:
            recs.append(Recommendation(
                code="NO_INBOUND_ADDRESS",
                severity="warning",
                title="Keine aktive Berichtsadresse",
                description=(
                    "Für diese Domain ist keine Empfangsadresse für DMARC-Berichte aktiv. Lege eine Adresse an "
                    "und trage sie als rua im DMARC-Eintrag ein. Erst dann kommen hier Berichte an."
                ),
                data_basis="Keine aktive Empfangsadresse für die Domain oder die Organisation.",
            ))

    # --- Report flow ---
    recent_report = (
        db.query(DmarcReport)
        .filter_by(organization_id=org_id, domain_id=domain_id)
        .filter(DmarcReport.created_at >= stale_since)
        .first()
    )
    if not recent_report:
        last_report = (
            db.query(DmarcReport)
            .filter_by(organization_id=org_id, domain_id=domain_id)
            .order_by(DmarcReport.created_at.desc())
            .first()
        )
        if last_report is None:
            recs.append(Recommendation(
                code="NO_REPORTS_EVER",
                severity="warning",
                title="Noch keine DMARC-Berichte empfangen",
                description=(
                    "Für diese Domain ist noch kein Sammelbericht eingegangen. Prüfe, ob der DMARC-Eintrag im DNS "
                    "veröffentlicht ist und die richtige rua-Adresse enthält."
                ),
                data_basis="0 Berichte für diese Domain.",
            ))
        else:
            days_since = (now - _as_utc(last_report.created_at)).days
            recs.append(Recommendation(
                code="REPORTS_STALE",
                severity="info",
                title=f"Seit {days_since} Tagen keine neuen Berichte",
                description=(
                    f"Der letzte Bericht kam vor {days_since} Tagen. Entweder verschickt die Domain derzeit keine "
                    "Mails, oder die rua-Adresse im DMARC-Eintrag hat sich geändert."
                ),
                data_basis=f"Letzter Bericht am {last_report.created_at:%d.%m.%Y}, Schwelle {stale_days} Tage.",
            ))

    recs.extend(_policy_tag_recommendations(domain))

    # --- Traffic in the evaluation window ---
    records = (
        db.query(DmarcRecord)
        .join(DmarcReport)
        .filter(
            DmarcReport.organization_id == org_id,
            DmarcReport.domain_id == domain_id,
            DmarcReport.created_at >= window_start,
        )
        .all()
    )
    if not records:
        return recs

    total_msgs = sum(r.count for r in records)
    pass_msgs = sum(r.count for r in records if r.dmarc_pass)
    fail_msgs = total_msgs - pass_msgs
    pass_rate = pass_msgs / total_msgs * 100 if total_msgs > 0 else 0
    fail_rate = fail_msgs / total_msgs * 100 if total_msgs > 0 else 0

    unknown_ips = (
        db.query(SourceIp)
        .filter_by(organization_id=org_id, classification="unknown")
        .filter(SourceIp.ip_address.in_([r.source_ip for r in records]))
        .count()
    )

    enough_for_policy = total_msgs >= settings.RECOMMENDATION_MIN_MESSAGES
    if (domain.dmarc_policy == "none" and enough_for_policy
            and pass_rate >= settings.RECOMMENDATION_QUARANTINE_PASS_RATE):
        recs.append(Recommendation(
            code="READY_FOR_QUARANTINE",
            severity="info",
            title="Bereit für p=quarantine",
            description=(
                f"{_pct(pass_rate)} der Nachrichten der letzten {window_days} Tage bestehen DMARC. Wenn alle "
                "Versandquellen geprüft sind, kann die Policy auf p=quarantine steigen."
            ),
            data_basis=f"Bestehensquote {_pct(pass_rate)}, {_n(total_msgs)} Nachrichten, Policy none.",
        ))

    if (domain.dmarc_policy == "quarantine" and enough_for_policy and unknown_ips == 0
            and pass_rate >= settings.RECOMMENDATION_REJECT_PASS_RATE):
        recs.append(Recommendation(
            code="READY_FOR_REJECT",
            severity="info",
            title="Bereit für p=reject",
            description=(
                f"{_pct(pass_rate)} der Nachrichten bestehen DMARC, und alle Versandquellen sind eingestuft. "
                "Mit p=reject ist die Domain am besten gegen Missbrauch geschützt."
            ),
            data_basis=f"Bestehensquote {_pct(pass_rate)}, {_n(total_msgs)} Nachrichten, 0 unbekannte Quellen.",
        ))

    enough_for_fail_rate = total_msgs >= settings.RECOMMENDATION_FAIL_MIN_MESSAGES
    if enough_for_fail_rate and fail_rate > settings.RECOMMENDATION_HIGH_FAIL_RATE:
        recs.append(Recommendation(
            code="HIGH_FAIL_RATE",
            severity="warning",
            title=f"Hohe Fehlerquote: {_pct(fail_rate)}",
            description=(
                f"{_n(fail_msgs)} von {_n(total_msgs)} Nachrichten der letzten {window_days} Tage bestehen DMARC "
                "nicht. Prüfe die fehlschlagenden Quellen und ihre SPF- und DKIM-Einrichtung."
            ),
            data_basis=f"Fehlerquote {_pct(fail_rate)}, {_n(fail_msgs)} von {_n(total_msgs)} Nachrichten.",
        ))

    if (domain.dmarc_policy in ENFORCING_POLICIES and enough_for_fail_rate
            and fail_rate > settings.RECOMMENDATION_ENFORCED_FAIL_RATE):
        recs.append(Recommendation(
            code="POLICY_ACTIVE_FAILURES",
            severity="critical",
            title=f"p={domain.dmarc_policy} ist aktiv, aber {_pct(fail_rate)} scheitern",
            description=(
                f"Empfänger stellen fehlschlagende Mails {POLICY_ACTION[domain.dmarc_policy]}. Darunter können "
                "echte Mails sein. Prüfe die fehlschlagenden Quellen sofort."
            ),
            data_basis=f"Policy {domain.dmarc_policy}, Fehlerquote {_pct(fail_rate)}.",
        ))

    if unknown_ips > 0:
        recs.append(Recommendation(
            code="UNKNOWN_SOURCES",
            severity="warning",
            title=("Eine unbekannte Versandquelle" if unknown_ips == 1
                   else f"{_n(unknown_ips)} unbekannte Versandquellen"),
            description=(
                ("Eine IP-Adresse hat Mails für diese Domain verschickt und ist noch nicht eingestuft. "
                 if unknown_ips == 1 else
                 f"{_n(unknown_ips)} IP-Adressen haben Mails für diese Domain verschickt und sind noch nicht "
                 "eingestuft. ")
                + "Ordne sie unter „Quellen“ als vertrauenswürdig, verdächtig oder ignoriert ein."
            ),
            data_basis=f"{_n(unknown_ips)} {'Quelle' if unknown_ips == 1 else 'Quellen'} mit Einstufung „unbekannt“.",
        ))

    spf_only_count = sum(r.count for r in records if r.spf_aligned and not r.dkim_aligned)
    if spf_only_count > 0 and total_msgs > 0:
        share = spf_only_count / total_msgs * 100
        if share >= settings.RECOMMENDATION_SPF_ONLY_SHARE:
            recs.append(Recommendation(
                code="DKIM_MISSING_FOR_SPF_SENDERS",
                severity="info",
                title=f"{_pct(share)} bestehen nur per SPF",
                description=(
                    "Diese Nachrichten bestehen DMARC allein über SPF. Bei Weiterleitungen bricht SPF, eine "
                    "DKIM-Signatur bleibt erhalten. Richte für diese Quellen DKIM ein."
                ),
                data_basis=f"{_n(spf_only_count)} von {_n(total_msgs)} Nachrichten nur mit SPF-Alignment.",
            ))

    return recs


def _policy_tag_recommendations(domain: Domain) -> list[Recommendation]:
    """Hints about pct (RFC 7489) and t (RFC 9989) in the published record."""
    recs: list[Recommendation] = []
    policy = domain.dmarc_policy
    if policy not in ENFORCING_POLICIES:
        return recs

    pct = domain.dmarc_policy_pct
    testing = (domain.dmarc_policy_testing or "").lower() == "y"

    if pct == 0 and not testing:
        recs.append(Recommendation(
            code="PCT_ZERO_WITHOUT_TESTING",
            severity="warning",
            title="pct=0: Testbetrieb gilt nur für ältere Empfänger",
            description=(
                f"Mit pct=0 stufen Empfänger nach RFC 7489 die Policy p={policy} für alle fehlgeschlagenen Mails "
                "um eine Stufe ab. RFC 9989 kennt pct nicht mehr: Empfänger nach dem neuen Standard wenden "
                f"p={policy} voll an. Soll die Domain im Testbetrieb bleiben, ergänze t=y im DMARC-Eintrag."
            ),
            data_basis="pct=0 laut letztem Bericht nach RFC 7489, kein t=y in Berichten nach RFC 9990.",
        ))
    elif pct is not None and 0 < pct < 100:
        recs.append(Recommendation(
            code="PCT_PARTIAL",
            severity="info",
            title=f"pct={pct}: Policy gilt nur für einen Teil der Mails",
            description=(
                f"Empfänger nach RFC 7489 wenden p={policy} auf {pct} % der fehlgeschlagenen Mails an. RFC 9989 "
                "kennt pct nicht mehr: Empfänger nach dem neuen Standard wenden die Policy auf alle an. Setze pct "
                "auf 100 oder entferne es, sobald alle Quellen sauber authentifiziert sind."
            ),
            data_basis=f"pct={pct} laut letztem Bericht nach RFC 7489.",
        ))

    if testing:
        recs.append(Recommendation(
            code="TESTING_MODE",
            severity="info",
            title="Testmodus aktiv (t=y)",
            description=(
                f"Die Domain bittet Empfänger nach RFC 9989, p={policy} vorerst nicht anzuwenden. Entferne t=y, "
                "sobald alle Quellen sauber authentifiziert sind. Empfänger nach RFC 7489 kennen t nicht und "
                "richten sich weiter nach p und pct."
            ),
            data_basis="t=y laut letztem Bericht nach RFC 9990.",
        ))

    return recs
