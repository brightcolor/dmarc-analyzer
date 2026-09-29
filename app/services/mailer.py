"""
Outgoing mail for alerts and the weekly digest.

MAIL_BACKEND picks the way: an SMTP server (MAIL_SMTP_*) or the HTTP API of a Postal server (POSTAL_API_*).
The API needs only HTTPS, which helps on hosts whose provider blocks outgoing port 25.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from urllib.parse import urlsplit

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Paths of the Postal API (https://docs.postalserver.io/developer/api)
POSTAL_SEND_PATH = "/api/v1/send/message"
POSTAL_MESSAGE_PATH = "/api/v1/messages/message"
AUTO_SUBMITTED = {"Auto-Submitted": "auto-generated"}

# Error codes of the Postal API that point to a setting; the others are passed on with Postal's text
POSTAL_REASONS = {
    "InvalidServerAPIKey": "Postal kennt den API-Schlüssel nicht. Prüfe POSTAL_API_KEY.",
    "AccessDenied": "Der API-Schlüssel darf in Postal keine Mails senden. Prüfe den Zugang am Mailserver in Postal.",
    "ServerSuspended": "Der Mailserver in Postal ist gesperrt. Gib ihn in Postal wieder frei.",
    "UnauthenticatedFromAddress": "Postal darf nicht mit dem Absender {sender} senden. Trage die Domain am "
                                  "Mailserver in Postal ein und lass sie dort prüfen, oder ändere MAIL_FROM.",
    "FromAddressMissing": "MAIL_FROM enthält keine Absenderadresse.",
    "NoRecipients": "Es gibt keinen Empfänger für diese Mail.",
}


class MailNotConfigured(Exception):
    pass


class MailDeliveryError(Exception):
    pass


def mail_configured() -> bool:
    if settings.MAIL_BACKEND == "postal":
        return bool(settings.POSTAL_API_URL and settings.POSTAL_API_KEY.strip())
    return bool(settings.MAIL_SMTP_HOST.strip())


def not_configured_reason() -> str:
    """What is missing for sending mail, as a sentence for users and operators."""
    if settings.MAIL_BACKEND == "postal":
        return ("Der Mailversand über Postal ist nicht eingerichtet. Trage POSTAL_API_URL und POSTAL_API_KEY in die "
                ".env ein und starte den Web-Container neu.")
    return ("Der Mailversand ist nicht eingerichtet. Trage MAIL_SMTP_HOST und den Zugang in die .env ein und starte "
            "den Web-Container neu.")


def describe_backend() -> str:
    """Where mails go, for the status page."""
    if settings.MAIL_BACKEND == "postal":
        return f"Postal-API {settings.POSTAL_API_URL or '(ohne Adresse)'}"
    return f"SMTP {settings.MAIL_SMTP_HOST}:{settings.MAIL_SMTP_PORT} ({settings.MAIL_SMTP_SECURITY})"


def _message_id_domain() -> str:
    address = parseaddr(settings.MAIL_FROM)[1]
    return address.rsplit("@", 1)[-1] if "@" in address else "localhost"


def build_message(recipients: list[str], subject: str, text: str, html: str | None = None) -> EmailMessage:
    message = EmailMessage()
    message["From"] = settings.MAIL_FROM
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=_message_id_domain())
    for name, value in AUTO_SUBMITTED.items():
        message[name] = value
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    return message


def send_mail(recipients: list[str], subject: str, text: str, html: str | None = None) -> None:
    """Send one mail to all recipients. Raises MailNotConfigured or MailDeliveryError with a German reason."""
    if not mail_configured():
        raise MailNotConfigured(not_configured_reason())
    if not recipients:
        raise MailDeliveryError(POSTAL_REASONS["NoRecipients"])
    if settings.MAIL_BACKEND == "postal":
        _send_postal(recipients, subject, text, html)
    else:
        _send_smtp(build_message(recipients, subject, text, html))
    logger.info("Mail sent to %d recipients over %s: %s", len(recipients), settings.MAIL_BACKEND, subject)


# SMTP ----------------------------------------------------------------------------------

def _open_smtp() -> smtplib.SMTP:
    host, port, timeout = settings.MAIL_SMTP_HOST.strip(), settings.MAIL_SMTP_PORT, settings.MAIL_TIMEOUT_SECONDS
    context = ssl.create_default_context()
    if settings.MAIL_SMTP_SECURITY == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    try:
        if settings.MAIL_SMTP_SECURITY == "starttls":
            server.starttls(context=context)
        if settings.MAIL_SMTP_USER:
            server.login(settings.MAIL_SMTP_USER, settings.MAIL_SMTP_PASSWORD)
    except Exception:
        server.close()
        raise
    return server


def _smtp_errors(action):
    host, port = settings.MAIL_SMTP_HOST.strip(), settings.MAIL_SMTP_PORT
    try:
        return action()
    except smtplib.SMTPAuthenticationError as exc:
        raise MailDeliveryError(
            f"Der SMTP-Server {host} hat die Anmeldung abgelehnt. Prüfe MAIL_SMTP_USER und MAIL_SMTP_PASSWORD."
        ) from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise MailDeliveryError(
            f"Der SMTP-Server {host} nimmt diese Empfänger nicht an: {', '.join(exc.recipients)}."
        ) from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise MailDeliveryError(
            f"Die Mail ließ sich über {host}:{port} nicht senden ({exc}). Prüfe Adresse, Port und Verschlüsselung."
        ) from exc


def _send_smtp(message: EmailMessage) -> None:
    def send():
        with _open_smtp() as server:
            server.send_message(message)
    _smtp_errors(send)


# Postal --------------------------------------------------------------------------------

def _postal_client() -> httpx.Client:
    return httpx.Client(timeout=settings.MAIL_TIMEOUT_SECONDS)


def _postal_call(path: str, payload: dict) -> dict:
    """POST to the Postal API; returns the answer or raises MailDeliveryError with a readable reason."""
    url = settings.POSTAL_API_URL + path
    host = urlsplit(settings.POSTAL_API_URL).netloc or settings.POSTAL_API_URL
    headers = {"X-Server-API-Key": settings.POSTAL_API_KEY.strip()}
    try:
        with _postal_client() as client:
            response = client.post(url, json=payload, headers=headers)
    except httpx.TimeoutException as exc:
        raise MailDeliveryError(
            f"Postal unter {host} hat nicht innerhalb von {settings.MAIL_TIMEOUT_SECONDS} Sekunden geantwortet. "
            "Versuche es später erneut."
        ) from exc
    except httpx.HTTPError as exc:
        raise MailDeliveryError(f"Postal unter {host} ist nicht erreichbar ({exc}). Prüfe POSTAL_API_URL.") from exc
    try:
        answer = response.json()
    except ValueError as exc:
        raise MailDeliveryError(
            f"Postal unter {host} hat mit HTTP {response.status_code} ohne lesbare Antwort geantwortet. "
            "Prüfe POSTAL_API_URL."
        ) from exc
    if not isinstance(answer, dict):
        raise MailDeliveryError(f"Postal unter {host} hat eine unerwartete Antwort geschickt. Prüfe POSTAL_API_URL.")
    return answer


def _postal_reason(answer: dict) -> str:
    data = answer.get("data") if isinstance(answer.get("data"), dict) else {}
    code = str(data.get("code") or answer.get("status") or "unbekannt")
    template = POSTAL_REASONS.get(code)
    if template:
        return template.format(sender=parseaddr(settings.MAIL_FROM)[1] or settings.MAIL_FROM)
    text = str(data.get("message") or "ohne Begründung")
    return f"Postal hat die Mail abgelehnt: {text} (Code {code})."


def _send_postal(recipients: list[str], subject: str, text: str, html: str | None) -> None:
    payload = {
        "to": recipients,
        "from": settings.MAIL_FROM,
        "subject": subject,
        "plain_body": text,
        "headers": dict(AUTO_SUBMITTED),
    }
    if html:
        payload["html_body"] = html
    if settings.POSTAL_MESSAGE_TAG.strip():
        payload["tag"] = settings.POSTAL_MESSAGE_TAG.strip()
    answer = _postal_call(POSTAL_SEND_PATH, payload)
    if answer.get("status") != "success":
        raise MailDeliveryError(_postal_reason(answer))


# Checking the way out without sending ------------------------------------------------------

def check_connection() -> str:
    """Log in to the SMTP server or ask Postal with the key, without sending a mail.

    Returns a sentence about what worked; raises MailNotConfigured or MailDeliveryError.
    """
    if not mail_configured():
        raise MailNotConfigured(not_configured_reason())
    if settings.MAIL_BACKEND == "postal":
        # A message id that never exists: a valid key gets MessageNotFound, an invalid one InvalidServerAPIKey
        answer = _postal_call(POSTAL_MESSAGE_PATH, {"id": 0})
        code = (answer.get("data") or {}).get("code") if isinstance(answer.get("data"), dict) else None
        if answer.get("status") == "success" or code == "MessageNotFound":
            return f"Postal unter {settings.POSTAL_API_URL} nimmt den API-Schlüssel an."
        raise MailDeliveryError(_postal_reason(answer))

    def login():
        with _open_smtp():
            pass
    _smtp_errors(login)
    who = "mit Anmeldung" if settings.MAIL_SMTP_USER else "ohne Anmeldung"
    return f"Der SMTP-Server {settings.MAIL_SMTP_HOST}:{settings.MAIL_SMTP_PORT} nimmt die Verbindung {who} an."
