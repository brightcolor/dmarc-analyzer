from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, now_utc, uuid_pk


class InboundMailAddress(Base):
    __tablename__ = "inbound_mail_addresses"

    id: Mapped[str] = uuid_pk()
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True, index=True
    )
    address: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    token: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    # active, disabled, revoked
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False, index=True)
    # org_report, domain_report
    purpose: Mapped[str] = mapped_column(String(30), default="org_report", nullable=False)

    max_message_size: Mapped[int] = mapped_column(
        Integer, default=10 * 1024 * 1024, nullable=False
    )  # 10MB
    rate_limit_per_hour: Mapped[int] = mapped_column(Integer, default=120, nullable=False)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False
    )

    organization: Mapped["Organization"] = relationship("Organization", back_populates="inbound_addresses")
    domain: Mapped[Optional["Domain"]] = relationship("Domain", back_populates="inbound_addresses")
    smtp_messages: Mapped[list["SmtpInboundMessage"]] = relationship(
        "SmtpInboundMessage", back_populates="inbound_address"
    )

    @property
    def is_accepting(self) -> bool:
        return self.status == "active"

    def __repr__(self) -> str:
        return f"<InboundMailAddress {self.address} [{self.status}]>"
