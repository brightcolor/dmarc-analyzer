"""
SMTP message handler.
Called by aiosmtpd after a message is fully received and accepted.
"""
import asyncio
import hashlib
import logging
import os
from datetime import datetime, timezone
from email import message_from_bytes
from typing import Optional

from aiosmtpd.smtp import Envelope as SmtpEnvelope, SMTP as SmtpServer, Session as SmtpSession

from app.config import settings
from app.database import get_db_context
from app.models import ImportJob, InboundMailAttachment, SmtpInboundMessage, SmtpInboundRejection
from app.services.mime_parser import (
    MimeParseError,
    ZipBombError,
    extract_dmarc_attachments,
    parse_mail_headers,
    sha256_hex,
)
from app.services.import_service import process_import_job
from app.services.alert_service import create_system_alert
from smtp_inbound.validator import validate_recipient

logger = logging.getLogger(__name__)


class DmarcSmtpHandler:
    """
    aiosmtpd handler for DMARC report emails.
    Validates recipients at RCPT TO and processes messages after DATA.
    """

    def __init__(self):
        self.max_size = settings.SMTP_INBOUND_MAX_MESSAGE_SIZE
        self.max_recipients = settings.SMTP_INBOUND_MAX_RECIPIENTS
        self.ip_rate_limit = settings.SMTP_INBOUND_RATE_LIMIT_PER_IP
        self.rcpt_rate_limit = settings.SMTP_INBOUND_RATE_LIMIT_PER_RECIPIENT
        self.store_raw = settings.SMTP_INBOUND_STORE_RAW
        self.reject_unknown = settings.SMTP_INBOUND_REJECT_UNKNOWN

    # ── RCPT TO handler ───────────────────────────────────────────────────────

    async def handle_RCPT(
        self,
        server: SmtpServer,
        session: SmtpSession,
        envelope: SmtpEnvelope,
        address: str,
        rcpt_options: list,
    ) -> str:
        if len(envelope.rcpt_tos) >= self.max_recipients:
            await self._record_rejection(
                session.peer[0] if session.peer else "unknown",
                address, "452", "4.5.3 Too many recipients"
            )
            return "452 4.5.3 Too many recipients"

        remote_ip = session.peer[0] if session.peer else "unknown"

        result = await asyncio.to_thread(
            validate_recipient,
            address.lower(),
            remote_ip,
            0,  # size unknown at RCPT stage
            self.ip_rate_limit,
            self.rcpt_rate_limit,
            self.max_size,
        )

        if not result.accepted:
            await self._record_rejection(remote_ip, address, str(result.smtp_code), result.smtp_message)
            return f"{result.smtp_code} {result.smtp_message}"

        # Store validation result on envelope for use in DATA handler
        if not hasattr(envelope, "_validation_results"):
            envelope._validation_results = {}
        envelope._validation_results[address.lower()] = result

        envelope.rcpt_tos.append(address)
        return "250 2.1.5 Recipient OK"

    # ── DATA handler ──────────────────────────────────────────────────────────

    async def handle_DATA(
        self,
        server: SmtpServer,
        session: SmtpSession,
        envelope: SmtpEnvelope,
    ) -> str:
        raw: bytes = envelope.content  # type: ignore[assignment]
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")

        remote_ip = session.peer[0] if session.peer else "unknown"

        if len(raw) > self.max_size:
            return "552 5.3.4 Message size exceeds fixed limit"

        headers = parse_mail_headers(raw)
        validations = getattr(envelope, "_validation_results", {})

        for rcpt in envelope.rcpt_tos:
            vr = validations.get(rcpt.lower())
            if not vr or not vr.organization_id:
                logger.warning("No validation result for accepted recipient %s, skipping", rcpt)
                continue

            await asyncio.to_thread(
                self._persist_and_process,
                raw=raw,
                envelope_sender=envelope.mail_from or "",
                envelope_recipient=rcpt,
                remote_ip=remote_ip,
                headers=headers,
                address_id=vr.address_id,
                organization_id=vr.organization_id,
                domain_id=vr.domain_id,
            )

        return "250 2.0.0 OK"

    # ── Persistence and processing ────────────────────────────────────────────

    def _persist_and_process(
        self,
        *,
        raw: bytes,
        envelope_sender: str,
        envelope_recipient: str,
        remote_ip: str,
        headers: dict,
        address_id: Optional[str],
        organization_id: str,
        domain_id: Optional[str],
    ) -> None:
        """Synchronous persistence and processing (called via asyncio.to_thread)."""
        raw_path = None
        if self.store_raw:
            raw_path = self._save_raw_mail(organization_id, raw)

        try:
            with get_db_context() as db:
                # Create inbound message record
                msg = SmtpInboundMessage(
                    inbound_address_id=address_id,
                    organization_id=organization_id,
                    domain_id=domain_id,
                    envelope_sender=envelope_sender[:320] if envelope_sender else None,
                    envelope_recipient=envelope_recipient[:320],
                    remote_ip=remote_ip[:45],
                    header_from=headers.get("from", "")[:500] or None,
                    header_to=headers.get("to", "")[:1000] or None,
                    subject=headers.get("subject", "")[:500] or None,
                    message_id=headers.get("message_id", "")[:500] or None,
                    received_at=datetime.now(timezone.utc),
                    size_bytes=len(raw),
                    raw_path=raw_path,
                    import_status="processing",
                )
                db.add(msg)
                db.flush()

                # Update last_used_at on inbound address
                if address_id:
                    from app.models import InboundMailAddress
                    addr = db.query(InboundMailAddress).filter_by(id=address_id).first()
                    if addr:
                        addr.last_used_at = datetime.now(timezone.utc)

                # Extract DMARC attachments
                try:
                    attachments = extract_dmarc_attachments(raw)
                except ZipBombError as exc:
                    logger.warning("ZIP bomb detected from %s: %s", remote_ip, exc)
                    msg.import_status = "quarantine"
                    msg.error_message = f"ZIP bomb protection triggered: {exc}"
                    create_system_alert(
                        db,
                        org_id=organization_id,
                        alert_type="import_failed",
                        severity="critical",
                        title=f"ZIP bomb blocked from {remote_ip}",
                        description=str(exc),
                        smtp_message_id=msg.id,
                    )
                    return
                except MimeParseError as exc:
                    logger.warning("MIME parse error from %s: %s", remote_ip, exc)
                    msg.import_status = "quarantine"
                    msg.error_message = f"MIME parse error: {exc}"
                    return

                if not attachments:
                    logger.info("No DMARC attachments found in mail from %s to %s", remote_ip, envelope_recipient)
                    msg.import_status = "completed"
                    msg.error_message = "No DMARC report attachments found"
                    return

                msg.attachment_count = len(attachments)
                imported_count = 0

                for att in attachments:
                    # Record attachment
                    att_record = InboundMailAttachment(
                        message_id=msg.id,
                        filename=att.filename[:500] if att.filename else None,
                        content_type=att.content_type[:200] if att.content_type else None,
                        size_bytes=len(att.data),
                        hash_sha256=att.sha256,
                    )
                    db.add(att_record)
                    db.flush()

                    # Save attachment to disk for import job
                    att_dir = settings.upload_dir_path / organization_id / "smtp"
                    att_dir.mkdir(parents=True, exist_ok=True)
                    att_path = att_dir / f"{att.sha256[:16]}_{att.filename or 'report.xml'}"
                    with open(att_path, "wb") as fh:
                        fh.write(att.data)

                    # Determine file type
                    fn_lower = (att.filename or "").lower()
                    if fn_lower.endswith(".zip"):
                        ftype = "zip"
                    elif fn_lower.endswith(".gz"):
                        ftype = "xml_gz"
                    else:
                        ftype = "xml"

                    # Create and run import job
                    job = ImportJob(
                        organization_id=organization_id,
                        domain_id=domain_id,
                        smtp_message_id=msg.id,
                        source="smtp_inbound",
                        status="pending",
                        file_path=str(att_path),
                        file_name=att.filename,
                        file_size=len(att.data),
                        file_hash=att.sha256,
                        file_type=ftype,
                    )
                    db.add(job)
                    db.flush()

                    att_record.import_job_id = job.id
                    process_import_job(db, job)

                    if job.status == "completed":
                        att_record.status = "completed"
                        imported_count += 1
                    else:
                        att_record.status = "failed"
                        att_record.error_message = job.error_message

                msg.import_status = "completed" if imported_count > 0 else "failed"
                if imported_count == 0:
                    msg.error_message = "All attachments failed to import"
                msg.processed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.exception("Error processing mail from %s to %s: %s", remote_ip, envelope_recipient, exc)

    @staticmethod
    def _save_raw_mail(organization_id: str, raw: bytes) -> Optional[str]:
        try:
            raw_dir = settings.raw_mail_dir_path / organization_id
            raw_dir.mkdir(parents=True, exist_ok=True)
            h = sha256_hex(raw)
            path = raw_dir / f"{h[:16]}.eml"
            with open(path, "wb") as fh:
                fh.write(raw)
            return str(path)
        except Exception as exc:
            logger.warning("Failed to save raw mail: %s", exc)
            return None

    # ── Rejection logging ─────────────────────────────────────────────────────

    @staticmethod
    async def _record_rejection(remote_ip: str, attempted: str, code: str, reason: str) -> None:
        try:
            await asyncio.to_thread(
                DmarcSmtpHandler._write_rejection, remote_ip, attempted, code, reason
            )
        except Exception as exc:
            logger.warning("Failed to record rejection: %s", exc)

    @staticmethod
    def _write_rejection(remote_ip: str, attempted: str, code: str, reason: str) -> None:
        with get_db_context() as db:
            db.add(SmtpInboundRejection(
                remote_ip=remote_ip[:45],
                attempted_recipient=attempted[:320],
                rejection_code=code[:10],
                rejection_reason=reason[:500],
            ))
