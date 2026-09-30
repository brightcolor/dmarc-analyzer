"""
SMTP TLS reports (TLS-RPT, RFC 8460): once a day, sending mail servers report how many sessions to the mail
servers of a domain succeeded with TLS and why the others failed. A domain asks for them with a TXT record at
_smtp._tls.<domain>: v=TLSRPTv1; rua=mailto:<address>.

A report is a JSON file, mostly compressed (application/tlsrpt+gzip), attached to a multipart/report with
report-type=tlsrpt. The application keeps the summary of every policy and the failure details.
"""
import gzip
import json
import logging
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email import message_from_bytes, policy
from email.message import Message

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Domain, TlsReport, TlsReportFailure, TlsReportPolicy
from app.services.mime_parser import GZIP_MAGIC, MimeParseError, _safe_gunzip

logger = logging.getLogger(__name__)

# Report type, media types and DNS record of RFC 8460 (sections 3 and 5.3)
REPORT_TYPE = "tlsrpt"
GZIP_TYPE = "application/tlsrpt+gzip"
JSON_TYPE = "application/tlsrpt+json"
FILE_ENDINGS = (".json", ".json.gz")
DNS_PREFIX = "_smtp._tls"
# Largest session count the database columns hold (32-bit integer)
MAX_SESSIONS = 2_147_483_647
DNS_VERSION = "v=TLSRPTv1"

# Policy types of RFC 8460, 4.4, as the interface names them
POLICY_TEXT = {"sts": "MTA-STS", "tlsa": "DANE", "no-policy-found": "ohne Richtlinie"}
POLICY_HINT = {
    "sts": "Der Absender prüfte die Verbindungen nach deiner MTA-STS-Richtlinie.",
    "tlsa": "Der Absender prüfte die Zertifikate nach den TLSA-Einträgen deiner Mailserver (DANE).",
    "no-policy-found": "Der Absender fand weder MTA-STS noch DANE und verschlüsselte, wo dein Mailserver es anbot.",
}

# Result types of RFC 8460, 4.3: short text and what it means for the mail server of the domain
RESULT_TEXT = {
    "starttls-not-supported": "STARTTLS fehlt",
    "certificate-host-mismatch": "Zertifikat passt nicht zum Namen",
    "certificate-expired": "Zertifikat abgelaufen",
    "certificate-not-trusted": "Zertifikat nicht vertrauenswürdig",
    "validation-failure": "Prüfung gescheitert",
    "tlsa-invalid": "TLSA-Eintrag ungültig",
    "dnssec-invalid": "DNSSEC ungültig",
    "dane-required": "DANE verlangt",
    "sts-policy-fetch-error": "MTA-STS-Richtlinie nicht abrufbar",
    "sts-policy-invalid": "MTA-STS-Richtlinie ungültig",
    "sts-webpki-invalid": "Zertifikat der MTA-STS-Seite ungültig",
    "": "ohne Angabe",
}
RESULT_HINT = {
    "starttls-not-supported": "Der Mailserver bot kein STARTTLS an. Schalte STARTTLS ein oder prüfe, ob ein "
                              "Filter davor die Verschlüsselung abschneidet.",
    "certificate-host-mismatch": "Das Zertifikat nennt einen anderen Namen als den MX-Eintrag. Stelle ein "
                                 "Zertifikat aus, das den Namen des Mailservers enthält.",
    "certificate-expired": "Das Zertifikat des Mailservers ist abgelaufen. Erneuere es und lade den Mailserver neu.",
    "certificate-not-trusted": "Das Zertifikat ist selbst signiert, oder die Zwischenzertifikate fehlen. Liefere "
                               "die ganze Kette einer bekannten Zertifizierungsstelle aus.",
    "validation-failure": "Die Prüfung scheiterte aus einem anderen Grund. Der Fehlercode nennt Einzelheiten.",
    "tlsa-invalid": "Der TLSA-Eintrag passt nicht zum Zertifikat. Trage nach einem Zertifikatswechsel den neuen "
                    "Wert ein.",
    "dnssec-invalid": "Die DNSSEC-Signaturen der Zone ließen sich nicht prüfen. Prüfe die Signatur beim DNS-Anbieter.",
    "dane-required": "Der Absender verlangt DANE und fand keinen nutzbaren TLSA-Eintrag.",
    "sts-policy-fetch-error": "Die Datei https://mta-sts.<domain>/.well-known/mta-sts.txt war nicht erreichbar. "
                              "Prüfe Webserver und DNS-Eintrag von mta-sts.",
    "sts-policy-invalid": "Die MTA-STS-Richtlinie ließ sich nicht lesen. Prüfe Aufbau und Werte der Datei.",
    "sts-webpki-invalid": "Der Webserver unter mta-sts.<domain> hat kein gültiges Zertifikat.",
}


class TlsReportError(ValueError):
    """A TLS report that cannot be read; the text says why, in the words of the interface."""


@dataclass
class ParsedFailure:
    result_type: str
    failed_sessions: int
    sending_mta_ip: str | None = None
    receiving_mx_hostname: str | None = None
    receiving_mx_helo: str | None = None
    receiving_ip: str | None = None
    additional_information: str | None = None
    failure_reason_code: str | None = None


@dataclass
class ParsedPolicy:
    policy_type: str
    policy_domain: str | None
    policy_strings: list[str]
    mx_hosts: list[str]
    successful_sessions: int
    failed_sessions: int
    failures: list[ParsedFailure] = field(default_factory=list)


@dataclass
class ParsedTlsReport:
    report_id: str
    organization_name: str | None
    contact_info: str | None
    period_begin: datetime | None
    period_end: datetime | None
    policies: list[ParsedPolicy]
    failure_details_omitted: int = 0

    @property
    def policy_domain(self) -> str | None:
        return next((p.policy_domain for p in self.policies if p.policy_domain), None)

    @property
    def successful_sessions(self) -> int:
        return sum(p.successful_sessions for p in self.policies)

    @property
    def failed_sessions(self) -> int:
        return sum(p.failed_sessions for p in self.policies)


@dataclass
class TlsReportMail:
    """The TLS reports of one mail and why others in it could not be read."""
    reports: list[ParsedTlsReport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files: int = 0


# Reading the JSON document ----------------------------------------------------------

def _text(value, size: int) -> str | None:
    if value is None or isinstance(value, dict | list | bool):
        return None
    return " ".join(str(value).split())[:size] or None


def _host(value) -> str | None:
    text = _text(value, 255)
    return (text.lower().rstrip(".") or None) if text else None


def _strings(value) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return [text for text in (_text(v, 1000) for v in values) if text]


def _count(value, what: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        raise TlsReportError(f"{what} ist keine Zahl ({value!r}).")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise TlsReportError(f"{what} ist keine Zahl ({value!r}).") from None
    if number < 0:
        raise TlsReportError(f"{what} ist negativ ({number}).")
    if number > MAX_SESSIONS:
        raise TlsReportError(f"{what} ist unplausibel groß ({number}).")
    return number


def _moment(value, what: str) -> datetime | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise TlsReportError(f"{what} ist kein Zeitpunkt ({value!r}).")
    try:
        moment = datetime.fromisoformat(value.strip().upper())
        return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    except (ValueError, OverflowError):
        raise TlsReportError(f"{what} ist kein Zeitpunkt nach RFC 3339 ({value!r}).") from None


def _failure(entry: dict, where: str) -> ParsedFailure:
    return ParsedFailure(
        result_type=(_text(entry.get("result-type"), 60) or "").lower(),
        failed_sessions=_count(entry.get("failed-session-count"), f"Die Zahl gescheiterter Verbindungen in {where}"),
        sending_mta_ip=_text(entry.get("sending-mta-ip"), 45),
        receiving_mx_hostname=_host(entry.get("receiving-mx-hostname")),
        receiving_mx_helo=_host(entry.get("receiving-mx-helo")),
        receiving_ip=_text(entry.get("receiving-ip"), 45),
        additional_information=_text(entry.get("additional-information"), 1000),
        failure_reason_code=_text(entry.get("failure-reason-code"), 255),
    )


def _policy(entry, number: int) -> ParsedPolicy:
    where = f"Richtlinie {number}"
    if not isinstance(entry, dict):
        raise TlsReportError(f"{where} ist kein JSON-Objekt.")
    policy_part = entry.get("policy") if isinstance(entry.get("policy"), dict) else {}
    summary = entry.get("summary") if isinstance(entry.get("summary"), dict) else {}
    details = entry.get("failure-details") or []
    if not isinstance(details, list):
        raise TlsReportError(f"Die Fehlerangaben von {where} sind keine Liste.")
    return ParsedPolicy(
        policy_type=(_text(policy_part.get("policy-type"), 30) or "no-policy-found").lower(),
        policy_domain=_host(policy_part.get("policy-domain")),
        policy_strings=_strings(policy_part.get("policy-string")),
        mx_hosts=_strings(policy_part.get("mx-host")),
        successful_sessions=_count(summary.get("total-successful-session-count"),
                                   f"Die Zahl erfolgreicher Verbindungen von {where}"),
        failed_sessions=_count(summary.get("total-failure-session-count"),
                               f"Die Zahl gescheiterter Verbindungen von {where}"),
        failures=[_failure(item, f"Fehlerangabe {index} von {where}")
                  for index, item in enumerate(details, 1) if isinstance(item, dict)],
    )


def _limit_failures(policies: list[ParsedPolicy]) -> int:
    """Keep the failure details with the most failed sessions; returns how many were left out."""
    limit = settings.TLS_REPORT_MAX_FAILURE_DETAILS
    entries = [(failure.failed_sessions, p, f) for p, pol in enumerate(policies) for f, failure in
               enumerate(pol.failures)]
    if len(entries) <= limit:
        return 0
    keep = {(p, f) for _, p, f in sorted(entries, key=lambda entry: -entry[0])[:limit]}
    for p, pol in enumerate(policies):
        pol.failures = [failure for f, failure in enumerate(pol.failures) if (p, f) in keep]
    return len(entries) - limit


def parse_tls_report(data: bytes) -> ParsedTlsReport:
    """Read the JSON document of a TLS report; raises TlsReportError with the reason."""
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except UnicodeDecodeError:
        raise TlsReportError("Der TLS-Bericht ist kein UTF-8-Text.") from None
    except json.JSONDecodeError as exc:
        raise TlsReportError(f"Der TLS-Bericht ist kein gültiges JSON (Zeile {exc.lineno}, Spalte {exc.colno}).") \
            from None
    except RecursionError:
        raise TlsReportError("Der TLS-Bericht ist zu tief verschachtelt.") from None
    except ValueError:  # e.g. a number with more digits than Python converts
        raise TlsReportError("Der TLS-Bericht enthält einen Wert außerhalb des lesbaren Bereichs.") from None
    if not isinstance(document, dict):
        raise TlsReportError("Der TLS-Bericht ist kein JSON-Objekt.")
    report_id = _text(document.get("report-id"), 500)
    if not report_id:
        raise TlsReportError("Dem TLS-Bericht fehlt die Kennung (report-id).")
    policies = document.get("policies")
    if not isinstance(policies, list):
        raise TlsReportError("Dem TLS-Bericht fehlt die Liste der Richtlinien (policies).")
    if len(policies) > settings.TLS_REPORT_MAX_POLICIES:
        raise TlsReportError(f"Der TLS-Bericht enthält {len(policies)} Richtlinien, erlaubt sind höchstens "
                             f"{settings.TLS_REPORT_MAX_POLICIES} (TLS_REPORT_MAX_POLICIES).")
    date_range = document.get("date-range") if isinstance(document.get("date-range"), dict) else {}
    parsed = [_policy(entry, number) for number, entry in enumerate(policies, 1)]
    for what, total in (("erfolgreicher", sum(p.successful_sessions for p in parsed)),
                        ("gescheiterter", sum(p.failed_sessions for p in parsed))):
        if total > MAX_SESSIONS:
            raise TlsReportError(f"Die Summe {what} Verbindungen ist unplausibel groß ({total}).")
    return ParsedTlsReport(
        report_id=report_id,
        organization_name=_text(document.get("organization-name"), 500),
        contact_info=_text(document.get("contact-info"), 500),
        period_begin=_moment(date_range.get("start-datetime"), "Der Beginn des Zeitraums"),
        period_end=_moment(date_range.get("end-datetime"), "Das Ende des Zeitraums"),
        policies=parsed,
        failure_details_omitted=_limit_failures(parsed),
    )


# Finding reports in a mail ----------------------------------------------------------

def _declared(message: Message) -> bool:
    """The mail announces a TLS report: report type tlsrpt or the header fields of RFC 8460, 5.3."""
    if message.get_content_type() == "multipart/report" and \
            str(message.get_param("report-type") or "").lower() == REPORT_TYPE:
        return True
    return bool(message.get("TLS-Report-Domain") or message.get("TLS-Report-Submitter"))


def _report_files(message: Message) -> list[tuple[str, str, bytes]]:
    """Name, media type and content of every part that can hold a TLS report."""
    files = []
    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        name = part.get_filename() or ""
        if content_type not in (GZIP_TYPE, JSON_TYPE) and not name.lower().endswith(FILE_ENDINGS):
            continue
        payload = part.get_payload(decode=True)
        if payload:
            files.append((name or content_type, content_type, payload))
    return files


def _json_bytes(name: str, content_type: str, payload: bytes) -> bytes:
    if len(payload) > settings.ARCHIVE_MAX_ATTACHMENT_BYTES:
        raise TlsReportError(f"Die Datei ist {len(payload)} Bytes groß, erlaubt sind höchstens "
                             f"{settings.ARCHIVE_MAX_ATTACHMENT_BYTES} (ARCHIVE_MAX_ATTACHMENT_BYTES).")
    if content_type == GZIP_TYPE or name.lower().endswith(".gz") or payload[:2] == GZIP_MAGIC:
        try:
            return _safe_gunzip(payload)  # an archive bomb raises ZipBombError for the caller
        except (gzip.BadGzipFile, zlib.error, EOFError) as exc:
            raise TlsReportError(f"Die Datei ließ sich nicht entpacken: {exc}.") from None
    return payload


def find_tls_reports(raw: bytes) -> TlsReportMail | None:
    """TLS reports in a mail. None when the mail carries none, so the search for DMARC reports continues."""
    try:
        message = message_from_bytes(raw, policy=policy.default)
        declared = _declared(message)
        files = _report_files(message)
    except Exception as exc:  # malformed mails must not stop the reception
        logger.warning("Mail could not be searched for TLS reports: %s", exc)
        return None
    if not files and not declared:
        return None

    found = TlsReportMail(files=len(files))
    for name, content_type, payload in files:
        try:
            found.reports.append(parse_tls_report(_json_bytes(name, content_type, payload)))
        except TlsReportError as exc:
            found.errors.append(f"{name}: {exc}")
        except MimeParseError:
            raise  # an archive bomb holds the whole mail back
        except Exception as exc:  # a strange report must not make the sender deliver again and again
            logger.exception("TLS report %s could not be read", name)
            found.errors.append(f"{name}: Der TLS-Bericht ließ sich nicht lesen ({exc.__class__.__name__}).")
    announced = declared or any(content_type in (GZIP_TYPE, JSON_TYPE) for _, content_type, _ in files)
    if not found.reports and not announced:
        # Some other JSON file: the search for DMARC reports decides
        return None
    if not files:
        found.errors.append(f"Die Mail kündigt einen TLS-Bericht an, enthält aber keine Datei im Format {GZIP_TYPE} "
                            f"oder {JSON_TYPE}.")
    return found


# Storing ------------------------------------------------------------------------------

def _find_domain(db: Session, organization_id: str, name: str | None) -> str | None:
    if not name:
        return None
    domain = db.query(Domain.id).filter_by(organization_id=organization_id, name=name).first()
    return domain.id if domain else None


def _json_list(values: list[str]) -> str | None:
    return json.dumps(values) if values else None


def store_tls_report(db: Session, report: ParsedTlsReport, *, organization_id: str, domain_id: str | None = None,
                     smtp_message_id: str | None = None, import_source: str = "smtp_inbound") -> TlsReport | None:
    """Save a parsed report. The policy domain names the domain, else the receiving address does.

    Returns None when the organisation already holds a report with this ID; senders deliver again after errors.
    """
    exists = db.query(TlsReport.id).filter_by(organization_id=organization_id, report_id=report.report_id).first()
    if exists:
        logger.info("TLS report %s is already stored, skipping", report.report_id)
        return None
    record = TlsReport(
        organization_id=organization_id,
        domain_id=_find_domain(db, organization_id, report.policy_domain) or domain_id,
        smtp_message_id=smtp_message_id,
        import_source=import_source,
        report_id=report.report_id,
        organization_name=report.organization_name,
        contact_info=report.contact_info,
        period_begin=report.period_begin,
        period_end=report.period_end,
        policy_domain=report.policy_domain,
        successful_sessions=report.successful_sessions,
        failed_sessions=report.failed_sessions,
        failure_details_omitted=report.failure_details_omitted,
    )
    for position, parsed in enumerate(report.policies):
        entry = TlsReportPolicy(
            position=position,
            policy_type=parsed.policy_type,
            policy_domain=parsed.policy_domain,
            policy_strings=_json_list(parsed.policy_strings),
            mx_hosts=_json_list(parsed.mx_hosts),
            successful_sessions=parsed.successful_sessions,
            failed_sessions=parsed.failed_sessions,
        )
        entry.failures = [
            TlsReportFailure(
                result_type=failure.result_type,
                sending_mta_ip=failure.sending_mta_ip,
                receiving_mx_hostname=failure.receiving_mx_hostname,
                receiving_mx_helo=failure.receiving_mx_helo,
                receiving_ip=failure.receiving_ip,
                failed_sessions=failure.failed_sessions,
                additional_information=failure.additional_information,
                failure_reason_code=failure.failure_reason_code,
            )
            for failure in parsed.failures
        ]
        record.policies.append(entry)
    db.add(record)
    db.flush()
    logger.info("TLS report %s stored for %s: %d successful, %d failed sessions", record.report_id,
                record.policy_domain, record.successful_sessions, record.failed_sessions)
    return record


def mail_outcome(stored: int, duplicates: int, errors: list[str]) -> tuple[str, str | None]:
    """Status and note of a received mail with TLS reports."""
    if errors and not stored and not duplicates:
        return "failed", "Der TLS-Bericht ließ sich nicht lesen und bleibt unberücksichtigt. " + " ".join(errors)
    notes = []
    if duplicates:
        notes.append("Diesen TLS-Bericht gab es schon; die Anwendung hat ihn einmal gespeichert."
                     if duplicates == 1 else f"{duplicates} TLS-Berichte gab es schon; sie sind einmal gespeichert.")
    if errors:
        notes.append("Ein Teil ließ sich nicht lesen: " + " ".join(errors))
    return "completed", " ".join(notes) or None


# Figures for the interface and the alert rule -------------------------------------------

def suggest_tls_record(address: str) -> str:
    return f"{DNS_VERSION}; rua=mailto:{address}"


@dataclass
class TlsSummary:
    reports: int = 0
    successful: int = 0
    failed: int = 0
    top_result: str | None = None
    top_result_sessions: int = 0

    @property
    def total(self) -> int:
        return self.successful + self.failed

    @property
    def failure_rate(self) -> float | None:
        return self.failed / self.total * 100 if self.total else None


def summarize(db: Session, organization_id: str, since: datetime, until: datetime,
              domain_id: str | None = None) -> TlsSummary:
    """Sessions of the TLS reports that arrived in a period, with the most frequent reason for failures."""
    conditions = [TlsReport.organization_id == organization_id, TlsReport.created_at >= since,
                  TlsReport.created_at < until]
    if domain_id:
        conditions.append(TlsReport.domain_id == domain_id)
    count, successful, failed = db.query(
        func.count(TlsReport.id), func.coalesce(func.sum(TlsReport.successful_sessions), 0),
        func.coalesce(func.sum(TlsReport.failed_sessions), 0),
    ).filter(*conditions).one()
    summary = TlsSummary(reports=count, successful=int(successful), failed=int(failed))
    if summary.failed:
        top = (
            db.query(TlsReportFailure.result_type, func.sum(TlsReportFailure.failed_sessions).label("sessions"))
            .join(TlsReportPolicy, TlsReportFailure.policy_id == TlsReportPolicy.id)
            .filter(TlsReportPolicy.report_id.in_(select(TlsReport.id).where(*conditions)))
            .group_by(TlsReportFailure.result_type)
            .order_by(func.sum(TlsReportFailure.failed_sessions).desc(), TlsReportFailure.result_type)
            .first()
        )
        if top:
            summary.top_result, summary.top_result_sessions = top.result_type, int(top.sessions or 0)
    return summary


def recent_summary(db: Session, organization_id: str, domain_id: str, days: int,
                   now: datetime | None = None) -> TlsSummary:
    now = now or datetime.now(UTC)
    return summarize(db, organization_id, now - timedelta(days=days), now + timedelta(seconds=1), domain_id)
