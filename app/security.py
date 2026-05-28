import hashlib
import secrets
import string
from datetime import UTC, datetime

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


MAX_PASSWORD_BYTES = 72


def hash_password(password: str) -> str:
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must not exceed {MAX_PASSWORD_BYTES} bytes.")
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    if len(plain.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False
    return pwd_context.verify(plain, hashed)


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure URL-safe token."""
    return secrets.token_urlsafe(length)


def generate_inbound_token(length: int = 12) -> str:
    """Generate a hard-to-guess token suitable for inbound mail addresses."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_api_token() -> tuple[str, str]:
    """Return (raw_token, hashed_token). raw_token shown once, hash stored."""
    raw = "dmarc_" + secrets.token_hex(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def hash_api_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_verification_token() -> str:
    return secrets.token_hex(24)


def utcnow() -> datetime:
    return datetime.now(UTC)
