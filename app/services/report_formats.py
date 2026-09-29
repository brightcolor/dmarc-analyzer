"""
Labels, explanations and statistics for the two DMARC report formats (RFC 7489 and RFC 9990).
"""
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import DmarcReport
from app.services.dmarc_parser import FORMAT_RFC7489, FORMAT_RFC9990


@dataclass(frozen=True)
class FormatInfo:
    code: str | None
    label: str        # short badge text
    name: str         # human name
    standard: str     # standards documents
    summary: str      # one-sentence explanation


FORMATS = {
    FORMAT_RFC7489: FormatInfo(
        code=FORMAT_RFC7489,
        label="RFC 7489",
        name="DMARC, Fassung von 2015",
        standard="RFC 7489",
        summary="Das bisherige Berichtsformat. Es kennt pct, aber weder den Testmodus t noch np.",
    ),
    FORMAT_RFC9990: FormatInfo(
        code=FORMAT_RFC9990,
        label="RFC 9990",
        name="DMARCbis, Fassung von 2026",
        standard="RFC 9989 und RFC 9990",
        summary="Das neue Berichtsformat. Es kennt den Testmodus t und np, pct gibt es darin nicht mehr.",
    ),
}

UNKNOWN_FORMAT = FormatInfo(
    code=None,
    label="nicht erfasst",
    name="Format nicht erfasst",
    standard="",
    summary="Der Bericht wurde vor Version 0.2.0 importiert, als die Anwendung das Format noch nicht erfasste.",
)

EVIDENCE_TEXT = {
    "namespace": "Der Bericht nennt den Namespace urn:ietf:params:xml:ns:dmarc-2.0 aus RFC 9990.",
    "np": "Der Bericht enthält das Feld np, die Policy für nicht existierende Subdomains.",
    "testing": "Der Bericht enthält das Feld testing, den Testmodus t.",
    "discovery_method": "Der Bericht nennt, wie der Empfänger die Organisationsdomain ermittelt hat.",
    "generator": "Der Bericht nennt die Software, die ihn erzeugt hat.",
    "disposition_pass": "Mindestens ein Datensatz hat die Behandlung „pass“, die es erst seit RFC 9990 gibt.",
    "policy_test_mode": "Ein Datensatz nennt den Grund policy_test_mode, den es erst seit RFC 9990 gibt.",
    "pct": "Der Bericht enthält pct, das es nur in RFC 7489 gibt.",
    "legacy_reason": "Ein Datensatz nennt forwarded oder sampled_out. Diese Gründe gibt es nur in RFC 7489.",
    "default": "Der Bericht enthält keine Merkmale des neuen Formats und wird nach RFC 7489 gelesen.",
}

REASON_TEXT = {
    "forwarded": "Weiterleitung",
    "sampled_out": "durch pct ausgenommen",
    "trusted_forwarder": "vertrauenswürdiger Weiterleiter",
    "mailing_list": "Mailingliste",
    "local_policy": "eigene Regel des Empfängers",
    "policy_test_mode": "Testmodus t=y",
    "other": "anderer Grund",
}

DISPOSITION_TEXT = {
    "none": "keine Maßnahme",
    "pass": "bestanden",
    "quarantine": "Spam-Ordner",
    "reject": "abgewiesen",
}

DISCOVERY_TEXT = {
    "psl": "Public Suffix List",
    "treewalk": "DNS-Tree-Walk",
}


def format_info(code: str | None) -> FormatInfo:
    return FORMATS.get(code or "", UNKNOWN_FORMAT)


def evidence_texts(evidence: str | None) -> list[str]:
    codes = [c for c in (evidence or "").split(",") if c]
    return [EVIDENCE_TEXT.get(c, c) for c in codes]


@dataclass
class ReporterFormat:
    reporting_org: str
    report_format: str | None
    reports: int
    last_period_end: datetime | None


def format_counts(db: Session, org_id: str, domain_id: str | None = None,
                  since: datetime | None = None) -> dict[str | None, int]:
    """Number of reports per format code (None = not recorded)."""
    query = db.query(DmarcReport.report_format, func.count(DmarcReport.id)).filter(
        DmarcReport.organization_id == org_id
    )
    if domain_id:
        query = query.filter(DmarcReport.domain_id == domain_id)
    if since:
        query = query.filter(DmarcReport.created_at >= since)
    return {fmt: count for fmt, count in query.group_by(DmarcReport.report_format).all()}


def reporter_formats(db: Session, org_id: str, domain_id: str | None = None,
                     since: datetime | None = None) -> list[ReporterFormat]:
    """Which reporting organisation sends which format, most active first."""
    query = db.query(
        DmarcReport.reporting_org,
        DmarcReport.report_format,
        func.count(DmarcReport.id),
        func.max(DmarcReport.period_end),
    ).filter(DmarcReport.organization_id == org_id)
    if domain_id:
        query = query.filter(DmarcReport.domain_id == domain_id)
    if since:
        query = query.filter(DmarcReport.created_at >= since)
    rows = query.group_by(DmarcReport.reporting_org, DmarcReport.report_format).all()
    result = [
        ReporterFormat(reporting_org=org or "unbekannt", report_format=fmt, reports=count, last_period_end=last)
        for org, fmt, count, last in rows
    ]
    return sorted(result, key=lambda r: (-r.reports, r.reporting_org))
