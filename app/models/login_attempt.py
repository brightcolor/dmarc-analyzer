from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, now_utc, uuid_pk


class LoginAttempt(Base):
    """One attempt to log in or to use the setup code; too many failures lock the address or the account."""

    __tablename__ = "login_attempts"

    id: Mapped[str] = uuid_pk()
    # login, setup
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    account: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)
