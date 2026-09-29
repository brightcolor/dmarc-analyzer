"""
First-run setup. While no administrator exists, every page leads to /auth/setup, and only
someone who knows the setup code can create the first administrator. The code appears in
the server log at startup and via `python -m app.setup_code`; it is deleted once used.
"""
import hmac
import logging
import re
import secrets

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AppSettings, User

logger = logging.getLogger(__name__)

SETUP_CODE_KEY = "setup_code"
# Unambiguous characters: no 0/O, 1/I/L
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_GROUP = 4


def admin_exists(db: Session) -> bool:
    return db.query(User.id).filter_by(is_superadmin=True, is_active=True).first() is not None


def normalize_code(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (value or "").upper())


def _format_code(raw: str) -> str:
    return "-".join(raw[i:i + CODE_GROUP] for i in range(0, len(raw), CODE_GROUP))


def _stored_code(db: Session) -> AppSettings | None:
    return db.query(AppSettings).filter_by(key=SETUP_CODE_KEY, organization_id=None).first()


def ensure_setup_code(db: Session) -> str | None:
    """Current setup code, created on demand. None once an administrator exists."""
    if admin_exists(db):
        clear_setup_code(db)
        return None
    row = _stored_code(db)
    if row and row.value:
        return row.value
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(settings.SETUP_CODE_LENGTH))
    code = _format_code(raw)
    db.add(AppSettings(key=SETUP_CODE_KEY, value=code, is_sensitive=True,
                       description="Einrichtungscode für das erste Administratorkonto"))
    db.commit()
    return code


def consume_setup_code(db: Session, candidate: str) -> bool:
    """Check the code and delete it in one step, so only one request can use it."""
    row = _stored_code(db)
    if not row or not row.value:
        return False
    if not hmac.compare_digest(normalize_code(candidate), normalize_code(row.value)):
        return False
    result = db.execute(
        delete(AppSettings).where(AppSettings.id == row.id, AppSettings.value == row.value)
    )
    return result.rowcount == 1


def clear_setup_code(db: Session) -> None:
    db.execute(delete(AppSettings).where(AppSettings.key == SETUP_CODE_KEY))
    db.commit()


def setup_path_is_open(path: str) -> bool:
    """Paths that stay reachable while setup is pending (health, API, static files, the setup page)."""
    if path == "/auth/setup":
        return True
    return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in settings.setup_open_paths)


def log_setup_hint(code: str) -> None:
    logger.warning(
        "Ersteinrichtung offen: Es gibt noch kein Administratorkonto. Öffne %s/auth/setup und gib den "
        "Einrichtungscode %s ein. Den Code zeigt auch der Befehl: docker compose exec web python -m app.setup_code",
        settings.APP_URL.rstrip("/"), code,
    )
