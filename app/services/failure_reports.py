"""
Failure reports (ruf): one report per mail that failed DMARC, sent as an ARF mail
(multipart/report with a message/feedback-report part, RFC 5965 with the extension of RFC 6591; RFC 9991 for
DMARCbis). The third part carries the reported mail (message/rfc822) or only its header (text/rfc822-headers).

The application keeps the feedback fields and, when FAILURE_REPORT_STORE_HEADERS is on, the header of the
reported mail. The body of the reported mail is never stored.
"""
import base64
import binascii
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.message import Message
from email.parser import HeaderParser
from email.utils import parseaddr, parsedate_to_datetime

from sqlalchemy.orm import Session

from app.config import settings
from app.models import DmarcFailureReport, Domain
from app.services.text import clean_text

logger = logging.getLogger(__name__)

# MIME types of RFC 5965 and RFC 6591
REPORT_TYPE = "multipart/report"
FEEDBACK_TYPE = "message/feedback-report"
ORIGINAL_MESSAGE = "message/rfc822"
ORIGINAL_HEADERS = "text/rfc822-headers"


@dataclass
class ParsedFailureReport:
    feedback_type: str | None = None
    auth_failure: str | None = None
    identity_alignment: str | None = None
    delivery_result: str | None = None
    reported_domain: str | None = None
    source_ip: str | None = None
    arrival_date: datetime | None = None
    incidents: int = 1
    original_mail_from: str | None = None
    original_rcpt_to: str | None = None
    reporting_mta: str | None = None
    user_agent: str | None = None
    dkim_domain: str | None = None
    dkim_identity: str | None = None
    dkim_selector: str | None = None
    spf_dns: str | None = None
    authentication_results: str | None = None
    header_from: str | None = None
    subject: str | None = None
    message_id: str | None = None
    original_headers: str | None = None


def _report_parts(message: Message) -> list[Message] | None:
    """Parts of the multipart/report, also when a reporter wraps it in multipart/mixed."""
    if message.get_content_type() == REPORT_TYPE:
        return list(message.iter_parts())
    if message.is_multipart():
        for part in message.iter_parts():
            if part.get_content_type() == REPORT_TYPE:
                return list(part.iter_parts())
    return None


def _header_block(part: Message) -> Message | None:
    """The fields of a message/feedback-report or message/rfc822 part as a header block."""
    payload = part.get_payload()
    if isinstance(payload, list) and payload and isinstance(payload[0], Message):
        block = payload[0]
        if block.keys():
            return block
        # A few reporters encode the part in base64; the parser then sees no header fields
        text = block.get_payload()
        if not isinstance(text, str) or str(part.get("Content-Transfer-Encoding", "")).lower() != "base64":
            return None
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="replace")
        except (ValueError, binascii.Error):
            return None
        return HeaderParser(policy=policy.default).parsestr(decoded)
    raw = part.get_payload(decode=True)
    if not raw:
        return None
    return HeaderParser(policy=policy.default).parsestr(raw.decode("utf-8", errors="replace"))


def _values(block: Message | None, name: str) -> list[str]:
    if block is None:
        return []
    return [" ".join(str(v).split()) for v in (block.get_all(name) or []) if str(v).strip()]


def _first(block: Message | None, name: str) -> str | None:
    values = _values(block, name)
    return values[0] if values else None


def _joined(block: Message | None, name: str, separator: str = ", ") -> str | None:
    values = _values(block, name)
    return separator.join(values) if values else None


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _address(value: str | None) -> str | None:
    if not value:
        return None
    return parseaddr(value)[1] or value.strip("<> ")


def _domain_of(value: str | None) -> str | None:
    address = _address(value)
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().lower().rstrip(".") or None


def _limit_bytes(text: str, limit: int) -> str:
    data = text.encode("utf-8")
    if len(data) <= limit:
        return text
    return data[:limit].decode("utf-8", errors="ignore") + "\n[gekürzt]"


def parse_failure_report(raw: bytes) -> ParsedFailureReport | None:
    """Read an ARF mail. Returns None when the mail carries no feedback report."""
    try:
        message = message_from_bytes(raw, policy=policy.default)
        parts = _report_parts(message)
        if not parts:
            return None
        feedback_part = next((p for p in parts if p.get_content_type() == FEEDBACK_TYPE), None)
        if feedback_part is None:
            return None
        fields = _header_block(feedback_part)
        original_part = next((p for p in parts if p.get_content_type() in (ORIGINAL_MESSAGE, ORIGINAL_HEADERS)), None)
        original = _header_block(original_part) if original_part is not None else None
    except Exception as exc:  # malformed mails must not stop the reception
        logger.warning("Failure report could not be read: %s", exc)
        return None

    report = ParsedFailureReport(
        feedback_type=(_first(fields, "Feedback-Type") or "").lower() or None,
        auth_failure=(_joined(fields, "Auth-Failure") or "").lower() or None,
        identity_alignment=(_joined(fields, "Identity-Alignment") or "").lower() or None,
        delivery_result=(_first(fields, "Delivery-Result") or "").lower() or None,
        source_ip=_first(fields, "Source-IP"),
        arrival_date=_date(_first(fields, "Arrival-Date") or _first(fields, "Received-Date")),
        original_mail_from=_address(_first(fields, "Original-Mail-From")),
        original_rcpt_to=", ".join(a for a in (_address(v) for v in _values(fields, "Original-Rcpt-To")) if a) or None,
        reporting_mta=(_first(fields, "Reporting-MTA") or "").removeprefix("dns;").strip() or None,
        user_agent=_first(fields, "User-Agent"),
        dkim_domain=_first(fields, "DKIM-Domain"),
        dkim_identity=_first(fields, "DKIM-Identity"),
        dkim_selector=_first(fields, "DKIM-Selector"),
        spf_dns=_joined(fields, "SPF-DNS", "; "),
        authentication_results=_joined(fields, "Authentication-Results", "\n"),
    )
    try:
        report.incidents = max(1, int(_first(fields, "Incidents") or 1))
    except ValueError:
        report.incidents = 1

    if original is not None:
        report.header_from = _first(original, "From")
        report.subject = _first(original, "Subject")
        report.message_id = _first(original, "Message-ID")
        if settings.FAILURE_REPORT_STORE_HEADERS:
            lines = [f"{name}: {' '.join(str(value).split())}" for name, value in original.items()]
            report.original_headers = _limit_bytes("\n".join(lines), settings.FAILURE_REPORT_MAX_HEADER_BYTES)

    reported = _first(fields, "Reported-Domain")
    report.reported_domain = (reported.lower().rstrip(".") if reported else None) or _domain_of(report.header_from)
    return report


def _cut(value: str | None, size: int | None) -> str | None:
    return clean_text(value, size) or None if value else None


def _find_domain(db: Session, organization_id: str, report: ParsedFailureReport) -> str | None:
    for name in (report.reported_domain, _domain_of(report.header_from)):
        if not name:
            continue
        domain = db.query(Domain.id).filter_by(organization_id=organization_id, name=name).first()
        if domain:
            return domain.id
    return None


def store_failure_report(db: Session, report: ParsedFailureReport, *, organization_id: str,
                         domain_id: str | None = None, smtp_message_id: str | None = None,
                         reporter: str | None = None, import_source: str = "smtp_inbound") -> DmarcFailureReport:
    """Save a parsed report; without a domain from the receiving address the reported domain decides."""
    record = DmarcFailureReport(
        organization_id=organization_id,
        domain_id=domain_id or _find_domain(db, organization_id, report),
        smtp_message_id=smtp_message_id,
        import_source=import_source,
        reporter=_cut(reporter, 500),
        user_agent=_cut(report.user_agent, 255),
        reporting_mta=_cut(report.reporting_mta, 255),
        feedback_type=_cut(report.feedback_type, 50),
        auth_failure=_cut(report.auth_failure, 100),
        identity_alignment=_cut(report.identity_alignment, 50),
        delivery_result=_cut(report.delivery_result, 50),
        reported_domain=_cut(report.reported_domain, 255),
        source_ip=_cut(report.source_ip, 45),
        arrival_date=report.arrival_date,
        incidents=report.incidents,
        original_mail_from=_cut(report.original_mail_from, 320),
        original_rcpt_to=_cut(report.original_rcpt_to, 1000),
        dkim_domain=_cut(report.dkim_domain, 255),
        dkim_identity=_cut(report.dkim_identity, 320),
        dkim_selector=_cut(report.dkim_selector, 255),
        spf_dns=_cut(report.spf_dns, 500),
        authentication_results=_cut(report.authentication_results, None),
        header_from=_cut(report.header_from, 500),
        subject=_cut(report.subject, 500),
        message_id=_cut(report.message_id, 500),
        original_headers=_cut(report.original_headers, None),
    )
    db.add(record)
    db.flush()
    logger.info("Failure report stored for %s from %s", record.reported_domain, record.source_ip)
    return record
