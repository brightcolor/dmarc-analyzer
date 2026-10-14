from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, now_utc, uuid_pk


class SenderApproval(Base):
    """Decision of an organisation about a sending service; it applies to every IP address of that service."""

    __tablename__ = "sender_approvals"
    __table_args__ = (UniqueConstraint("organization_id", "sender_key", name="uq_sender_approval_org_key"),)

    id: Mapped[str] = uuid_pk()
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sender_key: Mapped[str] = mapped_column(String(64), nullable=False)
    # trusted, suspicious, ignored
    classification: Mapped[str] = mapped_column(String(20), nullable=False)
    decided_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
