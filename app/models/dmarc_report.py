from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, now_utc, uuid_pk


class DmarcReport(Base):
    __tablename__ = "dmarc_reports"

    id: Mapped[str] = uuid_pk()
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True, index=True
    )
    import_job_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("import_jobs.id", ondelete="SET NULL"), nullable=True
    )

    # From XML: <report_metadata>
    report_id: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    reporting_org: Mapped[str | None] = mapped_column(String(500), nullable=True)
    reporting_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    # Time range
    period_begin: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    # From XML: <policy_published>
    policy_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    policy_adkim: Mapped[str | None] = mapped_column(String(1), nullable=True)  # r or s
    policy_aspf: Mapped[str | None] = mapped_column(String(1), nullable=True)   # r or s
    policy_p: Mapped[str | None] = mapped_column(String(20), nullable=True)     # none/quarantine/reject
    policy_sp: Mapped[str | None] = mapped_column(String(20), nullable=True)
    policy_pct: Mapped[int | None] = mapped_column(Integer, nullable=True)
    policy_fo: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Aggregated counts (computed on import)
    total_messages: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pass_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fail_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pass_rate: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Import metadata
    import_source: Mapped[str] = mapped_column(String(30), default="web_upload", nullable=False)
    parser_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)

    domain: Mapped[Optional["Domain"]] = relationship("Domain", back_populates="dmarc_reports")
    import_job: Mapped[Optional["ImportJob"]] = relationship("ImportJob", back_populates="dmarc_reports")
    records: Mapped[list["DmarcRecord"]] = relationship(
        "DmarcRecord", back_populates="report", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<DmarcReport {self.report_id} [{self.policy_domain}]>"


class DmarcRecord(Base):
    __tablename__ = "dmarc_records"

    id: Mapped[str] = uuid_pk()
    report_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("dmarc_reports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True
    )

    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    # none, quarantine, reject
    disposition: Mapped[str] = mapped_column(String(20), nullable=False, default="none", index=True)

    # Row-level auth results
    dkim_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    spf_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    header_from: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    envelope_from: Mapped[str | None] = mapped_column(String(320), nullable=True)

    # Computed
    dmarc_pass: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    spf_aligned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    dkim_aligned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    policy_applied: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

    report: Mapped["DmarcReport"] = relationship("DmarcReport", back_populates="records")
    auth_results: Mapped[list["DmarcAuthResult"]] = relationship(
        "DmarcAuthResult", back_populates="record", cascade="all, delete-orphan"
    )


class DmarcAuthResult(Base):
    __tablename__ = "dmarc_auth_results"

    id: Mapped[str] = uuid_pk()
    record_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("dmarc_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # dkim or spf
    auth_type: Mapped[str] = mapped_column(String(10), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    selector: Mapped[str | None] = mapped_column(String(255), nullable=True)  # DKIM only
    scope: Mapped[str | None] = mapped_column(String(20), nullable=True)      # SPF only

    record: Mapped["DmarcRecord"] = relationship("DmarcRecord", back_populates="auth_results")
