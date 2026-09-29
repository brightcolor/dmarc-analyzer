"""
Outgoing mail for alerts and the weekly digest, over the SMTP server from the settings.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr

from app.config import settings

logger = logging.getLogger(__name__)


class MailNotConfigured(Exception):
    pass


class MailDeliveryError(Exception):
    pass


def mail_configured() -> bool:
    return bool(settings.MAIL_SMTP_HOST.strip())


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
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    return message


def send_mail(recipients: list[str], subject: str, text: str, html: str | None = None) -> None:
    """Send one mail to all recipients. Raises MailNotConfigured or MailDeliveryError with a German reason."""
    if not mail_configured():
        raise MailNotConfigured(
            "Der Mailversand ist nicht eingerichtet. Trage MAIL_SMTP_HOST und den Zugang in die .env ein."
        )
    if not recipients:
        raise MailDeliveryError("Es gibt keinen Empfänger für diese Mail.")

    message = build_message(recipients, subject, text, html)
    host, port, timeout = settings.MAIL_SMTP_HOST.strip(), settings.MAIL_SMTP_PORT, settings.MAIL_TIMEOUT_SECONDS
    context = ssl.create_default_context()
    try:
        if settings.MAIL_SMTP_SECURITY == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
        with server:
            if settings.MAIL_SMTP_SECURITY == "starttls":
                server.starttls(context=context)
            if settings.MAIL_SMTP_USER:
                server.login(settings.MAIL_SMTP_USER, settings.MAIL_SMTP_PASSWORD)
            server.send_message(message)
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
    logger.info("Mail sent to %d recipients: %s", len(recipients), subject)
