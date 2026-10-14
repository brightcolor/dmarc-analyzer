"""
The account of the signed-in user: name, e-mail address and password.

Changing the e-mail address or the password asks for the current password. Wrong entries count like failed
logins (kind "account" in app.services.login_guard), so a stolen session cannot guess the password.
A new password ends every other session of the user.
"""
import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models import User
from app.security import hash_password, utcnow, verify_password
from app.services.login_guard import locked_until, record_attempt
from app.services.passwords import password_problem

# Dots only between domain labels: overlapping character classes made long input backtrack quadratically
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")
NAME_MAX_LENGTH = 255
EMAIL_MAX_LENGTH = 255
LOCK_KIND = "account"


class AccountError(ValueError):
    """A change that was refused; the message says what is wrong and what to do next."""

    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.field = field


@dataclass
class ProfileChange:
    name_changed: bool = False
    email_changed: bool = False
    old_email: str = ""


def check_current_password(db: Session, user: User, password: str, ip: str, now=None) -> None:
    """Raise AccountError unless the password is the user's; failures count towards the lock."""
    now = now or utcnow()
    until = locked_until(db, LOCK_KIND, ip, user.email, now)
    if until:
        from app.templates_config import _format_datetime as format_datetime

        raise AccountError(
            "Zu viele falsche Passwörter in kurzer Zeit. Aus Sicherheitsgründen ist die Änderung bis "
            f"{format_datetime(until)} Uhr gesperrt. Versuche es danach noch einmal.",
            "current_password",
        )
    ok = bool(password) and verify_password(password, user.password_hash)
    record_attempt(db, LOCK_KIND, ip, user.email, success=ok, now=now)
    if not ok:
        # The failure stays on record even though the change is turned away
        db.commit()
        raise AccountError("Das aktuelle Passwort stimmt nicht. Prüfe die Schreibweise; beim Passwort zählt "
                           "Groß- und Kleinschreibung.", "current_password")


def change_profile(db: Session, user: User, full_name: str, email: str, current_password: str,
                   ip: str) -> ProfileChange:
    """Save name and e-mail address; a new address needs the current password."""
    name = " ".join(full_name.split())
    if len(name) > NAME_MAX_LENGTH:
        raise AccountError(f"Der Name ist zu lang. Erlaubt sind höchstens {NAME_MAX_LENGTH} Zeichen.", "full_name")
    new_email = email.strip().lower()
    result = ProfileChange(old_email=user.email)

    if new_email != user.email:
        if not new_email or not EMAIL_RE.match(new_email) or len(new_email) > EMAIL_MAX_LENGTH:
            raise AccountError("Das ist keine gültige E-Mail-Adresse. Trage sie in der Form name@example.com ein.",
                               "email")
        if db.query(User.id).filter(User.email == new_email, User.id != user.id).first():
            raise AccountError("Diese E-Mail-Adresse gehört schon zu einem anderen Konto. Nimm eine andere "
                               "Adresse.", "email")
        check_current_password(db, user, current_password, ip)
        user.email = new_email
        result.email_changed = True

    if (name or None) != user.full_name:
        user.full_name = name or None
        result.name_changed = True
    db.flush()
    return result


def change_password(db: Session, user: User, current_password: str, new_password: str, repeat: str,
                    ip: str) -> float:
    """Set a new password and end the older sessions; returns the moment (UTC timestamp) for the current one."""
    problem = password_problem(new_password, repeat)
    if problem:
        raise AccountError(problem, "password")
    check_current_password(db, user, current_password, ip)
    if verify_password(new_password, user.password_hash):
        raise AccountError("Das neue Passwort ist dasselbe wie das aktuelle. Wähle ein anderes.", "password")
    now = utcnow()
    user.password_hash = hash_password(new_password)
    user.password_reset_token = None
    user.password_reset_expires_at = None
    user.credentials_changed_at = now
    db.flush()
    return now.timestamp()

