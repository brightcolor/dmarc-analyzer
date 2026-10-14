import json
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, now_utc, uuid_pk


def _json_list(value: str | None) -> list[str]:
    try:
        items = json.loads(value) if value else []
    except ValueError:
        return []
    return [str(item) for item in items] if isinstance(items, list) else []


class TlsReport(Base):
    """An SMTP TLS report (TLS-RPT, RFC 8460): how often senders reached the domain's mail servers with TLS."""
    __tablename__ = "tls_reports"
    __table_args__ = (UniqueConstraint("organization_id", "report_id", name="uq_tls_reports_org_report"),)

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

    report_id: Mapped[str] = mapped_column(String(500), nullable=False)
    organization_name: Mapped[str | None] = mapped_column(String(500), nullable=True)  # the reporting sender
    contact_info: Mapped[str | None] = mapped_column(String(500), nullable=True)
    period_begin: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    policy_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    successful_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Failure details beyond TLS_REPORT_MAX_FAILURE_DETAILS, counted but not stored
    failure_details_omitted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)

    domain: Mapped[Optional["Domain"]] = relationship("Domain")
    policies: Mapped[list["TlsReportPolicy"]] = relationship(
        "TlsReportPolicy", back_populates="report", cascade="all, delete-orphan", order_by="TlsReportPolicy.position"
    )

    @property
    def total_sessions(self) -> int:
        return self.successful_sessions + self.failed_sessions

    @property
    def failure_rate(self) -> float | None:
        return self.failed_sessions / self.total_sessions * 100 if self.total_sessions else None


class TlsReportPolicy(Base):
    """One policy of a TLS report: MTA-STS, DANE or none found, with its session counts."""
    __tablename__ = "tls_report_policies"

    id: Mapped[str] = uuid_pk()
    report_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tls_reports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    policy_type: Mapped[str] = mapped_column(String(30), nullable=False)  # sts, tlsa, no-policy-found
    policy_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    policy_strings: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list, e.g. MTA-STS lines
    mx_hosts: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    successful_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    report: Mapped["TlsReport"] = relationship("TlsReport", back_populates="policies")
    failures: Mapped[list["TlsReportFailure"]] = relationship(
        "TlsReportFailure", back_populates="policy", cascade="all, delete-orphan",
        order_by="TlsReportFailure.failed_sessions.desc()",
    )

    @property
    def total_sessions(self) -> int:
        return self.successful_sessions + self.failed_sessions

    @property
    def failure_rate(self) -> float | None:
        return self.failed_sessions / self.total_sessions * 100 if self.total_sessions else None

    @property
    def policy_lines(self) -> list[str]:
        return _json_list(self.policy_strings)

    @property
    def mx_host_list(self) -> list[str]:
        return _json_list(self.mx_hosts)


class TlsReportFailure(Base):
    """Why sessions of one policy failed (failure-details in RFC 8460)."""
    __tablename__ = "tls_report_failures"

    id: Mapped[str] = uuid_pk()
    policy_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tls_report_policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    result_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    sending_mta_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    receiving_mx_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    receiving_mx_helo: Mapped[str | None] = mapped_column(String(255), nullable=True)
    receiving_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    failed_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    additional_information: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    failure_reason_code: Mapped[str | None] = mapped_column(String(255), nullable=True)

    policy: Mapped["TlsReportPolicy"] = relationship("TlsReportPolicy", back_populates="failures")
