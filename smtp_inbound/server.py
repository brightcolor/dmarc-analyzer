"""
SMTP Inbound server — entry point.
Starts aiosmtpd on the configured port and runs forever.

Encryption is opportunistic STARTTLS, the way mail servers deliver to an MX on port 25: the session starts in
plain text and switches after the EHLO. A certificate that cannot be read leaves the reception running without
STARTTLS, so reports keep arriving; the log says what to fix.
"""
import asyncio
import logging
import ssl

logger = logging.getLogger(__name__)

TLS_VERSIONS = {"TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}


def tls_context() -> ssl.SSLContext | None:
    """Server context for STARTTLS from the settings; None when TLS is off or the certificate cannot be loaded."""
    from app.config import settings

    if not settings.SMTP_INBOUND_TLS_ENABLED:
        return None
    cert, key = settings.SMTP_INBOUND_TLS_CERT_PATH, settings.SMTP_INBOUND_TLS_KEY_PATH
    if not cert or not key:
        logger.error("STARTTLS ist eingeschaltet, aber SMTP_INBOUND_TLS_CERT_PATH oder SMTP_INBOUND_TLS_KEY_PATH "
                     "fehlt. Der Empfang läuft ohne Verschlüsselung weiter; trage beide Pfade ein und starte den "
                     "SMTP-Container neu.")
        return None
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = TLS_VERSIONS[settings.SMTP_INBOUND_TLS_MIN_VERSION]
    try:
        context.load_cert_chain(certfile=cert, keyfile=key)
    except (OSError, ssl.SSLError) as exc:
        logger.error("Das Zertifikat für STARTTLS ließ sich nicht laden (%s, %s): %s. Der Empfang läuft ohne "
                     "Verschlüsselung weiter; prüfe Pfade und Leserechte des SMTP-Containers und starte ihn neu.",
                     cert, key, exc)
        return None
    return context


async def start_smtp_server() -> None:
    from aiosmtpd.controller import Controller

    from app.config import settings
    from smtp_inbound.handler import DmarcSmtpHandler

    if not settings.SMTP_INBOUND_ENABLED:
        logger.info("SMTP Inbound is disabled (SMTP_INBOUND_ENABLED=false)")
        return

    context = tls_context()
    controller = Controller(
        DmarcSmtpHandler(),
        hostname=settings.SMTP_INBOUND_BIND,
        port=settings.SMTP_INBOUND_PORT,
        server_hostname=settings.SMTP_INBOUND_DOMAIN,
        # Enforce message size at SMTP level (aiosmtpd ≥1.4 uses data_size_limit)
        data_size_limit=settings.SMTP_INBOUND_MAX_MESSAGE_SIZE,
        # STARTTLS on offer; senders without TLS still deliver
        tls_context=context,
        require_starttls=False,
    )

    controller.start()
    logger.info(
        "SMTP Inbound listening on %s:%d (domain=%s, starttls=%s)",
        settings.SMTP_INBOUND_BIND,
        settings.SMTP_INBOUND_PORT,
        settings.SMTP_INBOUND_DOMAIN,
        context is not None,
    )

    try:
        # Run forever
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("SMTP Inbound shutting down")
        controller.stop()
