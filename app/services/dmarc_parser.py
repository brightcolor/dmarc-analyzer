"""
Safe DMARC XML parser using defusedxml (XXE protection).
Implements iterparse for memory-efficient processing.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import defusedxml.ElementTree as safe_et

logger = logging.getLogger(__name__)

PARSER_VERSION = "1.0"

# Maximum records per report to prevent memory exhaustion
MAX_RECORDS = 50_000


@dataclass
class ParsedAuthResult:
    auth_type: str
    domain: str
    result: str
    selector: Optional[str] = None
    scope: Optional[str] = None


@dataclass
class ParsedRecord:
    source_ip: str
    count: int
    disposition: str
    dkim_result: Optional[str]
    spf_result: Optional[str]
    header_from: Optional[str]
    envelope_from: Optional[str]
    auth_results: list[ParsedAuthResult] = field(default_factory=list)


@dataclass
class ParsedReport:
    report_id: str
    reporting_org: Optional[str]
    reporting_email: Optional[str]
    period_begin: Optional[datetime]
    period_end: Optional[datetime]
    policy_domain: Optional[str]
    policy_adkim: str
    policy_aspf: str
    policy_p: str
    policy_sp: Optional[str]
    policy_pct: int
    policy_fo: Optional[str]
    records: list[ParsedRecord] = field(default_factory=list)
    parser_version: str = PARSER_VERSION


class DmarcParseError(Exception):
    pass


def _text(el, default: str = "") -> str:
    return (el.text or "").strip() if el is not None else default


def _find_text(parent, tag: str, default: str = "") -> str:
    el = parent.find(tag)
    return _text(el, default)


def parse_xml_bytes(data: bytes) -> ParsedReport:
    """
    Parse DMARC aggregate report XML from bytes.
    Raises DmarcParseError on invalid input.
    """
    try:
        root = safe_et.fromstring(data)
    except Exception as exc:
        raise DmarcParseError(f"XML parse error: {exc}") from exc

    if root.tag not in ("feedback", "{urn:ietf:params:xml:ns:dmarc-2.0}feedback"):
        raise DmarcParseError(f"Unexpected root element: {root.tag}")

    # --- report_metadata ---
    meta = root.find("report_metadata")
    if meta is None:
        raise DmarcParseError("Missing <report_metadata>")

    report_id = _find_text(meta, "report_id") or ""
    reporting_org = _find_text(meta, "org_name") or None
    reporting_email = _find_text(meta, "email") or None

    period_begin = period_end = None
    date_range = meta.find("date_range")
    if date_range is not None:
        try:
            begin_ts = int(_find_text(date_range, "begin", "0"))
            end_ts = int(_find_text(date_range, "end", "0"))
            if begin_ts:
                period_begin = datetime.fromtimestamp(begin_ts, tz=timezone.utc)
            if end_ts:
                period_end = datetime.fromtimestamp(end_ts, tz=timezone.utc)
        except (ValueError, OSError):
            pass

    # --- policy_published ---
    pp = root.find("policy_published")
    policy_domain = None
    policy_adkim = "r"
    policy_aspf = "r"
    policy_p = "none"
    policy_sp = None
    policy_pct = 100
    policy_fo = None

    if pp is not None:
        policy_domain = _find_text(pp, "domain") or None
        policy_adkim = _find_text(pp, "adkim") or "r"
        policy_aspf = _find_text(pp, "aspf") or "r"
        policy_p = _find_text(pp, "p") or "none"
        policy_sp = _find_text(pp, "sp") or None
        pct_str = _find_text(pp, "pct")
        try:
            policy_pct = int(pct_str) if pct_str else 100
        except ValueError:
            policy_pct = 100
        policy_fo = _find_text(pp, "fo") or None

    # --- records ---
    records: list[ParsedRecord] = []
    for i, rec in enumerate(root.findall("record")):
        if i >= MAX_RECORDS:
            logger.warning("Report %s exceeds MAX_RECORDS (%d), truncating", report_id, MAX_RECORDS)
            break

        row = rec.find("row")
        if row is None:
            continue

        source_ip = _find_text(row, "source_ip")
        if not source_ip:
            continue

        count_str = _find_text(row, "count", "1")
        try:
            count = int(count_str)
        except ValueError:
            count = 1

        policy_eval = row.find("policy_evaluated")
        disposition = "none"
        row_dkim = None
        row_spf = None
        if policy_eval is not None:
            disposition = _find_text(policy_eval, "disposition") or "none"
            row_dkim = _find_text(policy_eval, "dkim") or None
            row_spf = _find_text(policy_eval, "spf") or None

        # identifiers
        identifiers = rec.find("identifiers")
        header_from = None
        envelope_from = None
        if identifiers is not None:
            header_from = _find_text(identifiers, "header_from") or None
            envelope_from = _find_text(identifiers, "envelope_from") or None

        # auth_results
        auth_results: list[ParsedAuthResult] = []
        auth_el = rec.find("auth_results")
        if auth_el is not None:
            for dkim_el in auth_el.findall("dkim"):
                d = _find_text(dkim_el, "domain")
                r = _find_text(dkim_el, "result")
                s = _find_text(dkim_el, "selector") or None
                if d and r:
                    auth_results.append(ParsedAuthResult("dkim", d, r, selector=s))

            for spf_el in auth_el.findall("spf"):
                d = _find_text(spf_el, "domain")
                r = _find_text(spf_el, "result")
                sc = _find_text(spf_el, "scope") or None
                if d and r:
                    auth_results.append(ParsedAuthResult("spf", d, r, scope=sc))

        records.append(ParsedRecord(
            source_ip=source_ip,
            count=count,
            disposition=disposition,
            dkim_result=row_dkim,
            spf_result=row_spf,
            header_from=header_from,
            envelope_from=envelope_from,
            auth_results=auth_results,
        ))

    return ParsedReport(
        report_id=report_id,
        reporting_org=reporting_org,
        reporting_email=reporting_email,
        period_begin=period_begin,
        period_end=period_end,
        policy_domain=policy_domain,
        policy_adkim=policy_adkim,
        policy_aspf=policy_aspf,
        policy_p=policy_p,
        policy_sp=policy_sp,
        policy_pct=policy_pct,
        policy_fo=policy_fo,
        records=records,
    )
