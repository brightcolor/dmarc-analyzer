from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, now_utc, uuid_pk


class ImportJob(Base):
    __tablename__ = "import_jobs"

    id: Mapped[str] = uuid_pk()
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True
    )
    smtp_message_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("smtp_inbound_messages.id", ondelete="SET NULL"), nullable=True
    )

    # smtp_inbound, web_upload, api
    source: Mapped[str] = mapped_column(String(30), nullable=False, default="web_upload", index=True)
    # pending, processing, completed, failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)

    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    file_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    file_type: Mapped[str | None] = mapped_column(String(20), nullable=True)  # xml, xml_gz, zip

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    records_imported: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_skipped: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False, index=True
    )
    parser_version: Mapped[str | None] = mapped_column(String(20), nullable=True)

    smtp_message: Mapped[Optional["SmtpInboundMessage"]] = relationship(
        "SmtpInboundMessage", back_populates="import_jobs"
    )
    import_errors: Mapped[list["ImportError"]] = relationship(
        "ImportError", back_populates="job", cascade="all, delete-orphan"
    )
    dmarc_reports: Mapped[list["DmarcReport"]] = relationship(
        "DmarcReport", back_populates="import_job",
        foreign_keys="DmarcReport.import_job_id"
    )

    def __repr__(self) -> str:
        return f"<ImportJob {self.id} [{self.status}]>"


class ImportError(Base):
    __tablename__ = "import_errors"

    id: Mapped[str] = uuid_pk()
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("import_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    error_type: Mapped[str] = mapped_column(String(50), nullable=False)
    error_message: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

    job: Mapped["ImportJob"] = relationship("ImportJob", back_populates="import_errors")
