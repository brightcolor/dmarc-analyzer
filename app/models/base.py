import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def uuid_pk() -> Mapped[str]:
    return mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))


def now_utc() -> datetime:
    return datetime.now(UTC)
