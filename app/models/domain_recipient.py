from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, now_utc, uuid_pk


class DomainRecipient(Base):
    """A further mail address for one domain: gets its alerts, its weekly digest or both."""
    __tablename__ = "domain_recipients"
    __table_args__ = (UniqueConstraint("domain_id", "email", name="uq_domain_recipients_domain_email"),)

    id: Mapped[str] = uuid_pk()
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    alerts: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    digest: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    digest_last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
