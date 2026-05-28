from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, now_utc, uuid_pk


class PlanDefinition(Base):
    __tablename__ = "plan_definitions"

    id: Mapped[str] = uuid_pk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    slug: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    max_domains: Mapped[int] = mapped_column(Integer, default=10)
    max_users: Mapped[int] = mapped_column(Integer, default=5)
    max_api_tokens: Mapped[int] = mapped_column(Integer, default=5)
    max_alert_rules: Mapped[int] = mapped_column(Integer, default=20)
    max_inbound_addresses: Mapped[int] = mapped_column(Integer, default=20)
    report_retention_days: Mapped[int] = mapped_column(Integer, default=365)
    smtp_rate_limit_per_hour: Mapped[int] = mapped_column(Integer, default=200)
    api_rate_limit_per_hour: Mapped[int] = mapped_column(Integer, default=1000)
    features: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    organizations: Mapped[list["Organization"]] = relationship("Organization", back_populates="plan")


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = uuid_pk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    owner_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    plan_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("plan_definitions.id"), nullable=True
    )

    max_domains: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    max_users: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    max_api_tokens: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    max_alert_rules: Mapped[int] = mapped_column(Integer, default=20, nullable=False)
    max_inbound_addresses: Mapped[int] = mapped_column(Integer, default=20, nullable=False)
    report_retention_days: Mapped[int] = mapped_column(Integer, default=365, nullable=False)
    smtp_rate_limit_per_hour: Mapped[int] = mapped_column(Integer, default=200, nullable=False)
    api_rate_limit_per_hour: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False
    )

    plan: Mapped[Optional["PlanDefinition"]] = relationship("PlanDefinition", back_populates="organizations")
    memberships: Mapped[list["OrganizationMembership"]] = relationship(
        "OrganizationMembership", back_populates="organization", cascade="all, delete-orphan",
        foreign_keys="OrganizationMembership.organization_id"
    )
    domains: Mapped[list["Domain"]] = relationship("Domain", back_populates="organization")
    inbound_addresses: Mapped[list["InboundMailAddress"]] = relationship(
        "InboundMailAddress", back_populates="organization"
    )
    alert_rules: Mapped[list["AlertRule"]] = relationship("AlertRule", back_populates="organization")
    api_tokens: Mapped[list["ApiToken"]] = relationship("ApiToken", back_populates="organization")
    notification_channels: Mapped[list["NotificationChannel"]] = relationship(
        "NotificationChannel", back_populates="organization"
    )

    def __repr__(self) -> str:
        return f"<Organization {self.slug}>"


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"

    id: Mapped[str] = uuid_pk()
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Roles: super_admin, org_admin, manager, analyst, read_only
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    invited_by: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

    user: Mapped["User"] = relationship("User", foreign_keys=[user_id], back_populates="memberships")
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="memberships", foreign_keys=[organization_id]
    )
