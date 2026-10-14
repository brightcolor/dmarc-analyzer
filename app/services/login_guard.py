"""
Lock against guessing: too many failed logins or setup codes within LOGIN_FAILURE_WINDOW_SECONDS lock the
IP address (LOGIN_MAX_FAILURES_PER_IP) or the account (LOGIN_MAX_FAILURES_PER_ACCOUNT) for
LOGIN_LOCKOUT_SECONDS after the last failure. A successful login starts the count anew.
Attempts during a lock are turned away without a check and without being counted.
"""
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import settings
from app.models import LoginAttempt
from app.security import utcnow


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _locked_until(db: Session, kind: str, column, value: str, limit: int, now: datetime) -> datetime | None:
    since = now - timedelta(seconds=settings.LOGIN_FAILURE_WINDOW_SECONDS)
    last_success = db.query(func.max(LoginAttempt.created_at)).filter(
        LoginAttempt.kind == kind, column == value, LoginAttempt.success.is_(True),
    ).scalar()
    if last_success is not None and _as_utc(last_success) > since:
        since = _as_utc(last_success)
    count, last_failure = db.query(func.count(LoginAttempt.id), func.max(LoginAttempt.created_at)).filter(
        LoginAttempt.kind == kind, column == value, LoginAttempt.success.is_(False), LoginAttempt.created_at > since,
    ).one()
    if count < limit or last_failure is None:
        return None
    until = _as_utc(last_failure) + timedelta(seconds=settings.LOGIN_LOCKOUT_SECONDS)
    return until if until > now else None


def locked_until(db: Session, kind: str, ip: str, account: str | None = None,
                 now: datetime | None = None) -> datetime | None:
    """End of the lock for this address or account, or None."""
    now = now or utcnow()
    candidates = [_locked_until(db, kind, LoginAttempt.ip_address, ip, settings.LOGIN_MAX_FAILURES_PER_IP, now)]
    if account:
        candidates.append(_locked_until(db, kind, LoginAttempt.account, account,
                                        settings.LOGIN_MAX_FAILURES_PER_ACCOUNT, now))
    found = [c for c in candidates if c is not None]
    return max(found) if found else None


def record_attempt(db: Session, kind: str, ip: str, account: str | None, success: bool,
                   now: datetime | None = None) -> None:
    db.add(LoginAttempt(kind=kind, ip_address=ip[:45], account=(account or None) and account[:255],
                        success=success, created_at=now or utcnow()))
    db.flush()
