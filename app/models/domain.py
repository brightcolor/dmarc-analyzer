from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, now_utc, uuid_pk


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[str] = uuid_pk()
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    verification_status: Mapped[str] = mapped_column(
        String(20), default="unverified", nullable=False
    )  # unverified, pending, verified, failed
    verification_token: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verified_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_report_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Cached from latest report
    dmarc_policy: Mapped[str | None] = mapped_column(String(20), nullable=True)
    dmarc_policy_sp: Mapped[str | None] = mapped_column(String(20), nullable=True)
    dmarc_policy_pct: Mapped[int | None] = mapped_column(nullable=True)

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False
    )

    organization: Mapped["Organization"] = relationship("Organization", back_populates="domains")
    inbound_addresses: Mapped[list["InboundMailAddress"]] = relationship(
        "InboundMailAddress", back_populates="domain"
    )
    dmarc_reports: Mapped[list["DmarcReport"]] = relationship(
        "DmarcReport", back_populates="domain"
    )
    alert_rules: Mapped[list["AlertRule"]] = relationship("AlertRule", back_populates="domain")

    def __repr__(self) -> str:
        return f"<Domain {self.name}>"
