from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, now_utc, uuid_pk


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = uuid_pk()
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # email, webhook, ntfy, pushover, slack
    channel_type: Mapped[str] = mapped_column(String(30), nullable=False)
    config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON (no passwords in plaintext)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False
    )

    organization: Mapped["Organization"] = relationship("Organization", back_populates="notification_channels")
    deliveries: Mapped[list["NotificationDelivery"]] = relationship(
        "NotificationDelivery", back_populates="channel"
    )


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"

    id: Mapped[str] = uuid_pk()
    alert_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alert_events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    channel_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False
    )
    # pending, sent, failed
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False, index=True)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

    alert_event: Mapped["AlertEvent"] = relationship("AlertEvent", back_populates="deliveries")
    channel: Mapped["NotificationChannel"] = relationship("NotificationChannel", back_populates="deliveries")
