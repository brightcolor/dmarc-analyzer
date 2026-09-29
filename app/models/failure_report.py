from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, now_utc, uuid_pk


class DmarcFailureReport(Base):
    """A failure report (ruf) about one mail, in the Abuse Reporting Format (RFC 5965, RFC 6591, RFC 9991).

    Keeps the feedback fields and, if enabled, the header of the reported mail; never its body.
    """
    __tablename__ = "dmarc_failure_reports"

    id: Mapped[str] = uuid_pk()
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True, index=True
    )
    smtp_message_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("smtp_inbound_messages.id", ondelete="SET NULL"), nullable=True, index=True
    )
    import_source: Mapped[str] = mapped_column(String(30), default="smtp_inbound", nullable=False)

    # Who reported: sender of the report mail and the fields User-Agent and Reporting-MTA
    reporter: Mapped[str | None] = mapped_column(String(500), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reporting_mta: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Feedback fields
    feedback_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    auth_failure: Mapped[str | None] = mapped_column(String(100), nullable=True)  # dmarc, dkim, spf, ...
    identity_alignment: Mapped[str | None] = mapped_column(String(50), nullable=True)  # none, dkim, spf
    delivery_result: Mapped[str | None] = mapped_column(String(50), nullable=True)  # delivered, spam, reject, ...
    reported_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    arrival_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    incidents: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    original_mail_from: Mapped[str | None] = mapped_column(String(320), nullable=True)
    original_rcpt_to: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    dkim_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dkim_identity: Mapped[str | None] = mapped_column(String(320), nullable=True)
    dkim_selector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    spf_dns: Mapped[str | None] = mapped_column(String(500), nullable=True)
    authentication_results: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The reported mail: a few header fields and, if FAILURE_REPORT_STORE_HEADERS is on, the whole header
    header_from: Mapped[str | None] = mapped_column(String(500), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    message_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    original_headers: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)

    domain: Mapped[Optional["Domain"]] = relationship("Domain")

    @property
    def failed_checks(self) -> list[str]:
        return [part.strip() for part in (self.auth_failure or "").split(",") if part.strip()]

    def __repr__(self) -> str:
        return f"<DmarcFailureReport {self.reported_domain} {self.source_ip}>"
