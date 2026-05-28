"""
RCPT TO validation for SMTP Inbound.
All DB checks happen here before a mail is accepted.
"""
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from threading import Lock

logger = logging.getLogger(__name__)

# ── Simple in-memory rate limiter ────────────────────────────────────────────

_rate_lock = Lock()
_ip_counts: dict[str, list[float]] = defaultdict(list)
_rcpt_counts: dict[str, list[float]] = defaultdict(list)


def _count_within_window(timestamps: list[float], window_seconds: int) -> int:
    now = time.monotonic()
    cutoff = now - window_seconds
    # Remove expired entries in place
    while timestamps and timestamps[0] < cutoff:
        timestamps.pop(0)
    return len(timestamps)


def record_and_check_ip_rate(ip: str, limit_per_hour: int) -> bool:
    """Returns True if the IP is under the rate limit (allowed)."""
    with _rate_lock:
        ts = _ip_counts[ip]
        count = _count_within_window(ts, 3600)
        if count >= limit_per_hour:
            return False
        ts.append(time.monotonic())
        return True


def record_and_check_recipient_rate(address: str, limit_per_hour: int) -> bool:
    """Returns True if the recipient address is under the rate limit."""
    with _rate_lock:
        ts = _rcpt_counts[address]
        count = _count_within_window(ts, 3600)
        if count >= limit_per_hour:
            return False
        ts.append(time.monotonic())
        return True


# ── Recipient validation ──────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    accepted: bool
    smtp_code: int
    smtp_message: str
    address_id: str | None = None
    organization_id: str | None = None
    domain_id: str | None = None


def validate_recipient(
    address: str,
    remote_ip: str,
    message_size: int,
    ip_rate_limit: int,
    recipient_rate_limit: int,
    max_message_size: int,
) -> ValidationResult:
    """
    Validate a RCPT TO address synchronously.
    Must be called with a live DB session — imported lazily to avoid
    circular imports at module load time.
    """
    from app.database import get_db_context
    from app.services.inbound_address import validate_for_smtp

    # Size check first (no DB needed)
    if message_size > max_message_size:
        return ValidationResult(
            accepted=False,
            smtp_code=552,
            smtp_message="5.3.4 Message size exceeds fixed limit",
        )

    # IP rate limit
    if not record_and_check_ip_rate(remote_ip, ip_rate_limit):
        logger.warning("SMTP rate limit exceeded for IP %s", remote_ip)
        return ValidationResult(
            accepted=False,
            smtp_code=421,
            smtp_message="4.7.0 Too many connections from your IP, try later",
        )

    # DB validation
    with get_db_context() as db:
        accepted, reason, addr = validate_for_smtp(db, address)

    if not accepted:
        code_str, _, message = reason.partition(" ")
        try:
            code = int(code_str)
        except ValueError:
            code = 550
        return ValidationResult(
            accepted=False,
            smtp_code=code,
            smtp_message=reason[len(code_str):].strip() or "recipient rejected",
        )

    # Recipient rate limit
    if not record_and_check_recipient_rate(address, recipient_rate_limit):
        return ValidationResult(
            accepted=False,
            smtp_code=421,
            smtp_message="4.7.0 Rate limit exceeded for this recipient",
        )

    return ValidationResult(
        accepted=True,
        smtp_code=250,
        smtp_message="2.1.5 Recipient OK",
        address_id=addr.id if addr else None,
        organization_id=addr.organization_id if addr else None,
        domain_id=addr.domain_id if addr else None,
    )
