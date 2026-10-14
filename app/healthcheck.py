"""
Health check of the container image: python -m app.healthcheck

Web interface and mail reception run from the same image. The check passes as soon as one target of
HEALTHCHECK_TARGETS answers, so every container reports on the service it runs.
"""
import contextlib
import socket
import sys
from urllib.parse import urlsplit

import httpx

from app.config import settings

# Longest greeting line read from the mail reception (RFC 5321 allows 512 octets per reply line)
SMTP_LINE_LIMIT = 512


def _seconds(value: float) -> str:
    return f"{value:g}".replace(".", ",")


def _probe_http(url: str, timeout: float) -> str | None:
    # Straight to the container itself, past any proxy from the environment
    response = httpx.get(url, timeout=timeout, trust_env=False)
    if 200 <= response.status_code < 300:
        return None
    return f"antwortet mit Status {response.status_code}"


def _probe_smtp(host: str, port: int, timeout: float) -> str | None:
    with socket.create_connection((host, port), timeout=timeout) as connection:
        with connection.makefile("rb") as reader:
            greeting = reader.readline(SMTP_LINE_LIMIT)
        # The greeting decides; a connection that closes before the goodbye changes nothing
        with contextlib.suppress(OSError):
            connection.sendall(b"QUIT\r\n")
    if greeting.startswith(b"220"):
        return None
    if not greeting:
        return "beendet die Verbindung ohne Begrüßung"
    return f"begrüßt mit {greeting[:3].decode('ascii', 'replace')} statt 220"


def describe(target: str) -> str:
    """The target as checked: an smtp target without port gets SMTP_INBOUND_PORT."""
    parts = urlsplit(target)
    if parts.scheme == "smtp" and parts.port is None:
        return f"{target.rstrip('/')}:{settings.SMTP_INBOUND_PORT}"
    return target


def probe(target: str, timeout: float) -> str | None:
    """None when the target answers as expected, else the reason in a few words."""
    parts = urlsplit(target)
    try:
        if parts.scheme == "smtp":
            return _probe_smtp(parts.hostname, parts.port or settings.SMTP_INBOUND_PORT, timeout)
        return _probe_http(target, timeout)
    except (TimeoutError, httpx.TimeoutException):
        return f"antwortet nicht innerhalb von {_seconds(timeout)} Sekunden"
    except (ConnectionRefusedError, httpx.ConnectError):
        return "nimmt keine Verbindung an"
    except (OSError, httpx.HTTPError) as exc:
        return f"ist nicht erreichbar ({exc.__class__.__name__}: {exc})"


def main() -> int:
    problems = []
    for target in settings.healthcheck_targets:
        reason = probe(target, settings.HEALTHCHECK_TIMEOUT_SECONDS)
        if reason is None:
            print(f"In Ordnung: {describe(target)} antwortet.")
            return 0
        problems.append(f"{describe(target)} {reason}")
    print("Kein Dienst dieses Containers antwortet: " + "; ".join(problems) + ". Hinweise stehen im Log des "
          "Containers (docker compose logs). Läuft der Dienst unter einer anderen Adresse oder einem anderen Port, "
          "trage sie in HEALTHCHECK_TARGETS ein.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
