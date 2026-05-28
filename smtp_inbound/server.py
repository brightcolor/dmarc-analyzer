"""
SMTP Inbound server — entry point.
Starts aiosmtpd on the configured port and runs forever.
"""
import asyncio
import logging
import ssl
import sys

logger = logging.getLogger(__name__)


async def start_smtp_server() -> None:
    from aiosmtpd.controller import Controller

    from app.config import settings
    from smtp_inbound.handler import DmarcSmtpHandler

    if not settings.SMTP_INBOUND_ENABLED:
        logger.info("SMTP Inbound is disabled (SMTP_INBOUND_ENABLED=false)")
        return

    handler = DmarcSmtpHandler()

    # Optional TLS
    ssl_context = None
    if settings.SMTP_INBOUND_TLS_ENABLED:
        if not settings.SMTP_INBOUND_TLS_CERT_PATH or not settings.SMTP_INBOUND_TLS_KEY_PATH:
            logger.error("TLS enabled but TLS_CERT_PATH or TLS_KEY_PATH not configured")
            sys.exit(1)
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(
            certfile=settings.SMTP_INBOUND_TLS_CERT_PATH,
            keyfile=settings.SMTP_INBOUND_TLS_KEY_PATH,
        )
        logger.info("TLS enabled for SMTP Inbound")

    controller = Controller(
        handler,
        hostname=settings.SMTP_INBOUND_BIND,
        port=settings.SMTP_INBOUND_PORT,
        ssl_context=ssl_context,
        server_hostname=settings.SMTP_INBOUND_DOMAIN,
        # Enforce message size at SMTP level
        # aiosmtpd checks DATA size via size_limit parameter
        size_limit=settings.SMTP_INBOUND_MAX_MESSAGE_SIZE,
    )

    controller.start()
    logger.info(
        "SMTP Inbound listening on %s:%d (domain=%s, tls=%s)",
        settings.SMTP_INBOUND_BIND,
        settings.SMTP_INBOUND_PORT,
        settings.SMTP_INBOUND_DOMAIN,
        settings.SMTP_INBOUND_TLS_ENABLED,
    )

    try:
        # Run forever
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("SMTP Inbound shutting down")
        controller.stop()
