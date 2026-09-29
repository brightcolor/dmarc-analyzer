"""Password rules shared by setup, invitations and account changes."""
from app.config import settings
from app.security import MAX_PASSWORD_BYTES


def password_problem(password: str, repeat: str | None = None) -> str | None:
    """German message describing what is wrong with the password, or None when it is acceptable."""
    if repeat is not None and password != repeat:
        return "Die beiden Passwörter stimmen nicht überein. Tippe das Passwort in beiden Feldern gleich ein."
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return (f"Das Passwort ist zu kurz. Es braucht mindestens {settings.PASSWORD_MIN_LENGTH} Zeichen; "
                "der Knopf „Vorschlagen“ erzeugt ein sicheres Passwort.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return (f"Das Passwort ist zu lang. Erlaubt sind höchstens {MAX_PASSWORD_BYTES} Byte, bei Umlauten "
                "und Sonderzeichen also etwas weniger Zeichen.")
    if len(set(password)) < 4:
        return "Das Passwort besteht fast nur aus demselben Zeichen. Nimm eine längere, gemischte Zeichenfolge."
    return None
