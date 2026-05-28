"""
Import service: converts parsed DMARC data into database records.
Handles deduplication, domain resolution, and source IP tracking.
"""
import hashlib
import logging
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models import (
    DmarcAuthResult,
    DmarcRecord,
    DmarcReport,
    Domain,
    ImportError,
    ImportJob,
    SourceIp,
)
from app.services.dmarc_evaluator import (
    AuthResultEntry,
    EvalResult,
    PolicyConfig,
    RecordEvalInput,
    evaluate_record,
)
from app.services.dmarc_parser import (
    PARSER_VERSION,
    DmarcParseError,
    ParsedReport,
    parse_xml_bytes,
)

logger = logging.getLogger(__name__)


def _file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_or_create_domain(db: Session, organization_id: str, name: str) -> Domain:
    name = name.lower().strip().rstrip(".")
    domain = db.query(Domain).filter_by(organization_id=organization_id, name=name).first()
    if not domain:
        domain = Domain(organization_id=organization_id, name=name, is_active=True)
        db.add(domain)
        db.flush()
    return domain


def _upsert_source_ip(db: Session, org_id: str, ip: str, count: int, passed: bool) -> None:
    sip = db.query(SourceIp).filter_by(organization_id=org_id, ip_address=ip).first()
    now = datetime.now(UTC)
    if not sip:
        sip = SourceIp(
            organization_id=org_id,
            ip_address=ip,
            first_seen_at=now,
            last_seen_at=now,
            total_messages=count,
            pass_count=count if passed else 0,
            fail_count=0 if passed else count,
        )
        db.add(sip)
    else:
        sip.total_messages += count
        if passed:
            sip.pass_count += count
        else:
            sip.fail_count += count
        sip.last_seen_at = now
        if sip.total_messages > 0:
            sip.pass_rate = round(sip.pass_count / sip.total_messages * 100, 2)


def check_duplicate(db: Session, org_id: str, report_id: str) -> bool:
    return (
        db.query(DmarcReport.id)
        .filter_by(organization_id=org_id, report_id=report_id)
        .first()
        is not None
    )


def store_parsed_report(
    db: Session,
    parsed: ParsedReport,
    organization_id: str,
    import_job_id: str,
    import_source: str = "web_upload",
) -> DmarcReport:
    """
    Persist a ParsedReport to the database.
    Handles domain resolution, record evaluation and source IP updates.
    """
    policy_domain = (parsed.policy_domain or "").lower().strip()
    domain: Domain | None = None
    if policy_domain:
        domain = get_or_create_domain(db, organization_id, policy_domain)

    report = DmarcReport(
        organization_id=organization_id,
        domain_id=domain.id if domain else None,
        import_job_id=import_job_id,
        report_id=parsed.report_id,
        reporting_org=parsed.reporting_org,
        reporting_email=parsed.reporting_email,
        period_begin=parsed.period_begin,
        period_end=parsed.period_end,
        policy_domain=policy_domain or None,
        policy_adkim=parsed.policy_adkim,
        policy_aspf=parsed.policy_aspf,
        policy_p=parsed.policy_p,
        policy_sp=parsed.policy_sp,
        policy_pct=parsed.policy_pct,
        policy_fo=parsed.policy_fo,
        import_source=import_source,
        parser_version=PARSER_VERSION,
    )
    db.add(report)
    db.flush()  # get report.id

    policy_cfg = PolicyConfig(
        domain=policy_domain or "",
        adkim=parsed.policy_adkim or "r",
        aspf=parsed.policy_aspf or "r",
        p=parsed.policy_p or "none",
        sp=parsed.policy_sp or "none",
        pct=parsed.policy_pct or 100,
    )

    total = pass_count = fail_count = 0

    for pr in parsed.records:
        eval_input = RecordEvalInput(
            source_ip=pr.source_ip,
            count=pr.count,
            header_from=pr.header_from or policy_domain,
            envelope_from=pr.envelope_from,
            dkim_result=pr.dkim_result,
            spf_result=pr.spf_result,
            auth_results=[
                AuthResultEntry(
                    auth_type=ar.auth_type,
                    domain=ar.domain,
                    result=ar.result,
                    selector=ar.selector,
                    scope=ar.scope,
                )
                for ar in pr.auth_results
            ],
        )
        eval_result: EvalResult = evaluate_record(eval_input, policy_cfg)

        record = DmarcRecord(
            report_id=report.id,
            organization_id=organization_id,
            domain_id=domain.id if domain else None,
            source_ip=pr.source_ip,
            count=pr.count,
            disposition=pr.disposition,
            dkim_result=pr.dkim_result,
            spf_result=pr.spf_result,
            header_from=pr.header_from,
            envelope_from=pr.envelope_from,
            dmarc_pass=eval_result.dmarc_pass,
            spf_aligned=eval_result.spf_aligned,
            dkim_aligned=eval_result.dkim_aligned,
            policy_applied=eval_result.policy_applied,
        )
        db.add(record)
        db.flush()

        for ar in pr.auth_results:
            db.add(DmarcAuthResult(
                record_id=record.id,
                auth_type=ar.auth_type,
                domain=ar.domain,
                result=ar.result,
                selector=ar.selector,
                scope=ar.scope,
            ))

        # Update source IP stats
        _upsert_source_ip(db, organization_id, pr.source_ip, pr.count, eval_result.dmarc_pass)

        total += pr.count
        if eval_result.dmarc_pass:
            pass_count += pr.count
        else:
            fail_count += pr.count

    report.total_messages = total
    report.pass_count = pass_count
    report.fail_count = fail_count
    report.pass_rate = round(pass_count / total * 100, 2) if total > 0 else None

    # Update domain's last report timestamp and cached policy
    if domain:
        domain.last_report_at = datetime.now(UTC)
        domain.dmarc_policy = parsed.policy_p
        domain.dmarc_policy_sp = parsed.policy_sp
        domain.dmarc_policy_pct = parsed.policy_pct

    db.flush()
    return report


def process_import_job(db: Session, job: ImportJob) -> None:
    """
    Main entry point: read the file for this job and import it.
    Updates job.status accordingly.
    """
    import os

    from app.services.mime_parser import _safe_gunzip, _safe_unzip

    job.status = "processing"
    job.started_at = datetime.now(UTC)
    db.flush()

    org_id = job.organization_id
    source = job.source

    try:
        if not job.file_path or not os.path.exists(job.file_path):
            raise FileNotFoundError(f"Import file not found: {job.file_path}")

        with open(job.file_path, "rb") as fh:
            raw = fh.read()

        file_hash = _file_hash(raw)
        job.file_hash = file_hash

        file_type = (job.file_type or "").lower()
        xml_blobs: list[tuple[str, bytes]] = []

        if file_type == "zip" or (job.file_name or "").lower().endswith(".zip"):
            entries = _safe_unzip(raw)
            for name, data in entries:
                if name.lower().endswith(".gz"):
                    try:
                        xml_blobs.append((name, _safe_gunzip(data)))
                    except Exception as exc:
                        _record_error(db, job.id, "gunzip", str(exc), name)
                else:
                    xml_blobs.append((name, data))
        elif file_type in ("xml_gz", "gz") or (job.file_name or "").lower().endswith(".gz"):
            xml_blobs.append((job.file_name or "report.xml", _safe_gunzip(raw)))
        else:
            xml_blobs.append((job.file_name or "report.xml", raw))

        imported = skipped = failed = 0

        for fname, xml_data in xml_blobs:
            try:
                parsed = parse_xml_bytes(xml_data)
            except DmarcParseError as exc:
                _record_error(db, job.id, "xml_parse", str(exc), fname)
                failed += 1
                continue

            if not parsed.report_id:
                _record_error(db, job.id, "missing_report_id", "Report has no report_id", fname)
                failed += 1
                continue

            if check_duplicate(db, org_id, parsed.report_id):
                logger.info("Duplicate report %s, skipping", parsed.report_id)
                skipped += 1
                continue

            store_parsed_report(db, parsed, org_id, job.id, import_source=source)
            imported += 1

        job.records_imported = imported
        job.records_skipped = skipped
        job.records_failed = failed
        job.status = "completed" if failed == 0 else ("failed" if imported == 0 else "completed")
        job.completed_at = datetime.now(UTC)

    except Exception as exc:
        logger.exception("Import job %s failed: %s", job.id, exc)
        job.status = "failed"
        job.error_message = str(exc)[:2000]
        job.completed_at = datetime.now(UTC)
        _record_error(db, job.id, "fatal", str(exc))


def _record_error(db: Session, job_id: str, error_type: str, msg: str, ctx: str = "") -> None:
    db.add(ImportError(job_id=job_id, error_type=error_type, error_message=msg[:2000], context=ctx[:500]))
    db.flush()
