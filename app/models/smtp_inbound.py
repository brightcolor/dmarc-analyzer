from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, now_utc, uuid_pk


class SmtpInboundMessage(Base):
    __tablename__ = "smtp_inbound_messages"

    id: Mapped[str] = uuid_pk()
    inbound_address_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("inbound_mail_addresses.id", ondelete="SET NULL"), nullable=True, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True, index=True
    )

    envelope_sender: Mapped[str | None] = mapped_column(String(320), nullable=True)
    envelope_recipient: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    remote_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    header_from: Mapped[str | None] = mapped_column(String(500), nullable=True)
    header_to: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    message_id: Mapped[str | None] = mapped_column(String(500), nullable=True, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_path: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # pending, processing, completed, failed, quarantine
    import_status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False, index=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    attachment_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

    inbound_address: Mapped[Optional["InboundMailAddress"]] = relationship(
        "InboundMailAddress", back_populates="smtp_messages"
    )
    attachments: Mapped[list["InboundMailAttachment"]] = relationship(
        "InboundMailAttachment", back_populates="message", cascade="all, delete-orphan"
    )
    import_jobs: Mapped[list["ImportJob"]] = relationship(
        "ImportJob", back_populates="smtp_message"
    )


class SmtpInboundRejection(Base):
    __tablename__ = "smtp_inbound_rejections"

    id: Mapped[str] = uuid_pk()
    remote_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    attempted_recipient: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    rejection_code: Mapped[str] = mapped_column(String(10), nullable=False)
    rejection_reason: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)


class InboundMailAttachment(Base):
    __tablename__ = "inbound_mail_attachments"

    id: Mapped[str] = uuid_pk()
    message_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("smtp_inbound_messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    import_job_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("import_jobs.id", ondelete="SET NULL"), nullable=True
    )
    filename: Mapped[str | None] = mapped_column(String(500), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    hash_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # pending, processing, completed, failed, unsupported
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

    message: Mapped["SmtpInboundMessage"] = relationship("SmtpInboundMessage", back_populates="attachments")
