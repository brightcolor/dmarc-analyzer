from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class SchedulerRun(Base):
    """Last run of each scheduled job; the row is claimed before a run, so a job runs once at a time."""

    __tablename__ = "scheduler_runs"

    name: Mapped[str] = mapped_column(String(50), primary_key=True)
    last_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(20), nullable=True)  # ok / error
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
