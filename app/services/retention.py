"""
Retention: removes data older than the limits of each organisation and the server settings.

- DMARC reports with their records, import jobs with their files and received mails after the
  report_retention_days of the organisation,
- stored raw mails after SMTP_INBOUND_RAW_RETENTION_DAYS,
- rejected delivery attempts after SMTP_REJECTION_RETENTION_DAYS,
- login attempts after LOGIN_ATTEMPT_RETENTION_DAYS.

One run deletes at most RETENTION_BATCH_SIZE entries per kind; the scheduler continues in the next run.
Bulk statements keep the run quick and work without foreign key cascades in SQLite.
"""
import logging
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, exists, select, update
from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    AlertEvent,
    DmarcAuthResult,
    DmarcRecord,
    DmarcReport,
    ImportError,
    ImportJob,
    InboundMailAttachment,
    LoginAttempt,
    Organization,
    SmtpInboundMessage,
    SmtpInboundRejection,
)
from app.security import utcnow

logger = logging.getLogger(__name__)

NO_SYNC = {"synchronize_session": False}


@dataclass
class RetentionResult:
    reports: int = 0
    import_jobs: int = 0
    messages: int = 0
    raw_mails: int = 0
    rejections: int = 0
    login_attempts: int = 0
    files: int = 0

    def __bool__(self) -> bool:
        return any(getattr(self, f.name) for f in fields(self))


def _remove_file(path: str | None, base: Path) -> bool:
    """Delete a stored file, but only inside the directory the application writes to."""
    if not path:
        return False
    try:
        target = Path(path).resolve()
        if base.resolve() not in target.parents:
            logger.warning("Retention skips %s: outside %s", target, base)
            return False
        if target.exists():
            target.unlink()
            return True
    except OSError as exc:
        logger.warning("Retention could not delete %s: %s", path, exc)
    return False


def _purge_reports(db: Session, org: Organization, cutoff: datetime, limit: int) -> int:
    ids = [rid for (rid,) in db.query(DmarcReport.id).filter(
        DmarcReport.organization_id == org.id, DmarcReport.created_at < cutoff,
    ).order_by(DmarcReport.created_at).limit(limit)]
    if not ids:
        return 0
    record_ids = select(DmarcRecord.id).where(DmarcRecord.report_id.in_(ids))
    db.execute(delete(DmarcAuthResult).where(DmarcAuthResult.record_id.in_(record_ids)).execution_options(**NO_SYNC))
    db.execute(delete(DmarcRecord).where(DmarcRecord.report_id.in_(ids)).execution_options(**NO_SYNC))
    db.execute(update(AlertEvent).where(AlertEvent.report_id.in_(ids)).values(report_id=None)
               .execution_options(**NO_SYNC))
    db.execute(delete(DmarcReport).where(DmarcReport.id.in_(ids)).execution_options(**NO_SYNC))
    return len(ids)


def _purge_import_jobs(db: Session, org: Organization, cutoff: datetime, limit: int) -> tuple[int, int]:
    rows = db.query(ImportJob.id, ImportJob.file_path).filter(
        ImportJob.organization_id == org.id,
        ImportJob.created_at < cutoff,
        ~exists().where(DmarcReport.import_job_id == ImportJob.id),
    ).limit(limit).all()
    if not rows:
        return 0, 0
    ids = [job_id for job_id, _ in rows]
    files = sum(_remove_file(path, settings.upload_dir_path) for _, path in rows)
    db.execute(update(InboundMailAttachment).where(InboundMailAttachment.import_job_id.in_(ids))
               .values(import_job_id=None).execution_options(**NO_SYNC))
    db.execute(delete(ImportError).where(ImportError.job_id.in_(ids)).execution_options(**NO_SYNC))
    db.execute(delete(ImportJob).where(ImportJob.id.in_(ids)).execution_options(**NO_SYNC))
    return len(ids), files


def _purge_messages(db: Session, org: Organization, cutoff: datetime, limit: int) -> tuple[int, int]:
    rows = db.query(SmtpInboundMessage.id, SmtpInboundMessage.raw_path).filter(
        SmtpInboundMessage.organization_id == org.id, SmtpInboundMessage.received_at < cutoff,
    ).limit(limit).all()
    if not rows:
        return 0, 0
    ids = [msg_id for msg_id, _ in rows]
    files = sum(_remove_file(path, settings.raw_mail_dir_path) for _, path in rows)
    db.execute(update(ImportJob).where(ImportJob.smtp_message_id.in_(ids)).values(smtp_message_id=None)
               .execution_options(**NO_SYNC))
    db.execute(update(AlertEvent).where(AlertEvent.smtp_message_id.in_(ids)).values(smtp_message_id=None)
               .execution_options(**NO_SYNC))
    db.execute(delete(InboundMailAttachment).where(InboundMailAttachment.message_id.in_(ids))
               .execution_options(**NO_SYNC))
    db.execute(delete(SmtpInboundMessage).where(SmtpInboundMessage.id.in_(ids)).execution_options(**NO_SYNC))
    return len(ids), files


def _purge_raw_mails(db: Session, now: datetime, limit: int) -> int:
    cutoff = now - timedelta(days=settings.SMTP_INBOUND_RAW_RETENTION_DAYS)
    messages = db.query(SmtpInboundMessage).filter(
        SmtpInboundMessage.raw_path.isnot(None), SmtpInboundMessage.received_at < cutoff,
    ).limit(limit).all()
    for message in messages:
        _remove_file(message.raw_path, settings.raw_mail_dir_path)
        message.raw_path = None
    return len(messages)


def _purge_rejections(db: Session, now: datetime) -> int:
    cutoff = now - timedelta(days=settings.SMTP_REJECTION_RETENTION_DAYS)
    result = db.execute(delete(SmtpInboundRejection).where(SmtpInboundRejection.created_at < cutoff)
                        .execution_options(**NO_SYNC))
    return result.rowcount or 0


def _purge_login_attempts(db: Session, now: datetime) -> int:
    cutoff = now - timedelta(days=settings.LOGIN_ATTEMPT_RETENTION_DAYS)
    result = db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < cutoff).execution_options(**NO_SYNC))
    return result.rowcount or 0


def run_retention(db: Session, now: datetime | None = None) -> RetentionResult:
    now = now or utcnow()
    limit = settings.RETENTION_BATCH_SIZE
    result = RetentionResult()
    for org in db.query(Organization).order_by(Organization.name).all():
        cutoff = now - timedelta(days=org.report_retention_days)
        result.reports += _purge_reports(db, org, cutoff, limit)
        jobs, job_files = _purge_import_jobs(db, org, cutoff, limit)
        messages, mail_files = _purge_messages(db, org, cutoff, limit)
        result.import_jobs += jobs
        result.messages += messages
        result.files += job_files + mail_files
    result.raw_mails = _purge_raw_mails(db, now, limit)
    result.rejections = _purge_rejections(db, now)
    result.login_attempts = _purge_login_attempts(db, now)
    db.flush()
    if result:
        logger.info("Retention removed %s", result)
    return result
