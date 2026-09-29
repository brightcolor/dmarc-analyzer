"""
Safe DMARC aggregate report parser (XXE protection via defusedxml).

Reads both report formats:
- RFC 7489 (classic DMARC, 2015)
- RFC 9990 (DMARCbis aggregate reporting, 2026), namespace urn:ietf:params:xml:ns:dmarc-2.0

Namespaces are stripped before parsing, so namespaced and plain reports share one code path.
The detected format and the evidence for it are returned with the report.
"""
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

import defusedxml.ElementTree as safe_et

from app.config import settings

logger = logging.getLogger(__name__)

PARSER_VERSION = "2.0"

FORMAT_RFC7489 = "rfc7489"
FORMAT_RFC9990 = "rfc9990"
DMARC2_NAMESPACE = "urn:ietf:params:xml:ns:dmarc-2.0"

# Evidence codes stored with each report; the UI explains them.
EVIDENCE_NAMESPACE = "namespace"
EVIDENCE_NEW_DISPOSITION = "disposition_pass"
EVIDENCE_TEST_MODE_REASON = "policy_test_mode"
EVIDENCE_PCT = "pct"
EVIDENCE_LEGACY_REASON = "legacy_reason"
EVIDENCE_DEFAULT = "default"

# Elements and values that exist only in RFC 9990 reports.
RFC9990_POLICY_FIELDS = ("np", "testing", "discovery_method")
RFC9990_METADATA_FIELDS = ("generator",)
RFC9990_DISPOSITIONS = ("pass",)
RFC9990_REASONS = ("policy_test_mode",)
# Override reasons that RFC 9990 removed.
RFC7489_REASONS = ("forwarded", "sampled_out")

# RFC 7489 section 6.3: pct defaults to 100 when absent.
RFC7489_DEFAULT_PCT = 100


@dataclass
class ParsedAuthResult:
    auth_type: str
    domain: str
    result: str
    selector: str | None = None
    scope: str | None = None


@dataclass
class ParsedOverrideReason:
    type: str
    comment: str | None = None


@dataclass
class ParsedRecord:
    source_ip: str
    count: int
    disposition: str
    dkim_result: str | None
    spf_result: str | None
    header_from: str | None
    envelope_from: str | None
    auth_results: list[ParsedAuthResult] = field(default_factory=list)
    reasons: list[ParsedOverrideReason] = field(default_factory=list)


@dataclass
class ParsedReport:
    report_id: str
    reporting_org: str | None
    reporting_email: str | None
    period_begin: datetime | None
    period_end: datetime | None
    policy_domain: str | None
    policy_adkim: str
    policy_aspf: str
    policy_p: str
    policy_sp: str | None
    policy_pct: int | None
    policy_fo: str | None
    policy_np: str | None = None
    policy_testing: str | None = None
    policy_discovery_method: str | None = None
    report_format: str = FORMAT_RFC7489
    format_evidence: list[str] = field(default_factory=list)
    schema_version: str | None = None
    generator: str | None = None
    records: list[ParsedRecord] = field(default_factory=list)
    parser_version: str = PARSER_VERSION


class DmarcParseError(Exception):
    pass


def _text(el, default: str = "") -> str:
    return (el.text or "").strip() if el is not None else default


def _find_text(parent, tag: str, default: str = "") -> str:
    if parent is None:
        return default
    return _text(parent.find(tag), default)


def _lower_or_none(value: str) -> str | None:
    return value.lower() if value else None


def _strip_namespaces(root) -> str | None:
    """Remove XML namespaces from all tags in place. Returns the namespace of the root element."""
    root_namespace = None
    if isinstance(root.tag, str) and root.tag.startswith("{"):
        root_namespace = root.tag[1:].split("}", 1)[0]
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.startswith("{"):
            el.tag = el.tag.split("}", 1)[1]
    return root_namespace


def _detect_format(root, root_namespace: str | None) -> tuple[str, list[str]]:
    """Decide between RFC 7489 and RFC 9990 and return the evidence for the decision."""
    if root_namespace == DMARC2_NAMESPACE:
        return FORMAT_RFC9990, [EVIDENCE_NAMESPACE]

    evidence: list[str] = []
    policy = root.find("policy_published")
    if policy is not None:
        evidence += [tag for tag in RFC9990_POLICY_FIELDS if policy.find(tag) is not None]
    metadata = root.find("report_metadata")
    if metadata is not None:
        evidence += [tag for tag in RFC9990_METADATA_FIELDS if metadata.find(tag) is not None]
    if any(_text(el).lower() in RFC9990_DISPOSITIONS for el in root.iter("disposition")):
        evidence.append(EVIDENCE_NEW_DISPOSITION)
    reason_types = {_find_text(reason, "type").lower() for reason in root.iter("reason")}
    if reason_types & set(RFC9990_REASONS):
        evidence.append(EVIDENCE_TEST_MODE_REASON)
    if evidence:
        return FORMAT_RFC9990, evidence

    if policy is not None and policy.find("pct") is not None:
        evidence.append(EVIDENCE_PCT)
    if reason_types & set(RFC7489_REASONS):
        evidence.append(EVIDENCE_LEGACY_REASON)
    return FORMAT_RFC7489, evidence or [EVIDENCE_DEFAULT]


def parse_xml_bytes(data: bytes, max_records: int | None = None) -> ParsedReport:
    """
    Parse a DMARC aggregate report (RFC 7489 or RFC 9990) from bytes.
    Raises DmarcParseError with a user-readable message on invalid input.
    """
    limit = max_records if max_records is not None else settings.DMARC_MAX_RECORDS_PER_REPORT

    try:
        root = safe_et.fromstring(data)
    except Exception as exc:
        raise DmarcParseError(
            f"Die Datei ist kein gültiges XML und lässt sich nicht als DMARC-Bericht lesen ({exc})."
        ) from exc

    root_namespace = _strip_namespaces(root)
    if root.tag != "feedback":
        raise DmarcParseError(
            f"Die Datei beginnt mit <{root.tag}>. Ein DMARC-Sammelbericht beginnt mit <feedback>; "
            "vermutlich ist das ein anderer Berichtstyp."
        )

    meta = root.find("report_metadata")
    if meta is None:
        raise DmarcParseError(
            "Dem Bericht fehlt der Abschnitt <report_metadata> mit berichtender Stelle und Berichtsnummer. "
            "Der Bericht ist unvollständig und wurde übersprungen."
        )

    report_format, evidence = _detect_format(root, root_namespace)

    report_id = _find_text(meta, "report_id")
    reporting_org = _find_text(meta, "org_name") or None
    reporting_email = _find_text(meta, "email") or None
    generator = _find_text(meta, "generator") or None
    schema_version = _find_text(root, "version") or None

    period_begin = period_end = None
    date_range = meta.find("date_range")
    if date_range is not None:
        try:
            begin_ts = int(_find_text(date_range, "begin", "0"))
            end_ts = int(_find_text(date_range, "end", "0"))
            if begin_ts:
                period_begin = datetime.fromtimestamp(begin_ts, tz=UTC)
            if end_ts:
                period_end = datetime.fromtimestamp(end_ts, tz=UTC)
        except (ValueError, OSError):
            logger.warning("Report %s has an unreadable date_range", report_id)

    pp = root.find("policy_published")
    pct_str = _find_text(pp, "pct")
    policy_pct: int | None = None
    if pct_str:
        try:
            policy_pct = int(pct_str)
        except ValueError:
            logger.warning("Report %s has a non-numeric pct value: %r", report_id, pct_str)
    elif report_format == FORMAT_RFC7489:
        policy_pct = RFC7489_DEFAULT_PCT

    records: list[ParsedRecord] = []
    for i, rec in enumerate(root.findall("record")):
        if i >= limit:
            logger.warning("Report %s exceeds %d records, truncating", report_id, limit)
            break

        row = rec.find("row")
        if row is None:
            continue

        source_ip = _find_text(row, "source_ip")
        if not source_ip:
            continue

        try:
            count = int(_find_text(row, "count", "1"))
        except ValueError:
            count = 1

        policy_eval = row.find("policy_evaluated")
        disposition = (_find_text(policy_eval, "disposition") or "none").lower()
        row_dkim = _lower_or_none(_find_text(policy_eval, "dkim"))
        row_spf = _lower_or_none(_find_text(policy_eval, "spf"))
        reasons = []
        if policy_eval is not None:
            for reason_el in policy_eval.findall("reason"):
                reason_type = _find_text(reason_el, "type").lower()
                if reason_type:
                    reasons.append(ParsedOverrideReason(reason_type, _find_text(reason_el, "comment") or None))

        identifiers = rec.find("identifiers")
        header_from = _find_text(identifiers, "header_from") or None
        envelope_from = _find_text(identifiers, "envelope_from") or None

        auth_results: list[ParsedAuthResult] = []
        auth_el = rec.find("auth_results")
        if auth_el is not None:
            for dkim_el in auth_el.findall("dkim"):
                d = _find_text(dkim_el, "domain")
                r = _find_text(dkim_el, "result").lower()
                if d and r:
                    auth_results.append(
                        ParsedAuthResult("dkim", d, r, selector=_find_text(dkim_el, "selector") or None)
                    )
            for spf_el in auth_el.findall("spf"):
                d = _find_text(spf_el, "domain")
                r = _find_text(spf_el, "result").lower()
                if d and r:
                    auth_results.append(
                        ParsedAuthResult("spf", d, r, scope=_find_text(spf_el, "scope") or None)
                    )

        records.append(ParsedRecord(
            source_ip=source_ip,
            count=count,
            disposition=disposition,
            dkim_result=row_dkim,
            spf_result=row_spf,
            header_from=header_from,
            envelope_from=envelope_from,
            auth_results=auth_results,
            reasons=reasons,
        ))

    return ParsedReport(
        report_id=report_id,
        reporting_org=reporting_org,
        reporting_email=reporting_email,
        period_begin=period_begin,
        period_end=period_end,
        policy_domain=_find_text(pp, "domain") or None,
        policy_adkim=_find_text(pp, "adkim").lower() or "r",
        policy_aspf=_find_text(pp, "aspf").lower() or "r",
        policy_p=_find_text(pp, "p").lower() or "none",
        policy_sp=_lower_or_none(_find_text(pp, "sp")),
        policy_pct=policy_pct,
        policy_fo=_find_text(pp, "fo") or None,
        policy_np=_lower_or_none(_find_text(pp, "np")),
        policy_testing=_lower_or_none(_find_text(pp, "testing")),
        policy_discovery_method=_lower_or_none(_find_text(pp, "discovery_method")),
        report_format=report_format,
        format_evidence=evidence,
        schema_version=schema_version,
        generator=generator,
        records=records,
    )
