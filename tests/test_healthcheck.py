"""Health check of the container image: passes as soon as the service of the container answers."""
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from aiosmtpd.controller import Controller

from app import healthcheck
from app.config import settings
from tests.helpers import _free_port

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class _Health(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - name given by http.server
        self.send_response(200 if self.path == "/api/v1/health" else 503)
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def log_message(self, *args):
        pass


class _Reception:
    """Mail reception without hooks; the check only needs its greeting."""


@pytest.fixture
def web_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Health)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def mail_server():
    port = _free_port()
    controller = Controller(_Reception(), hostname="127.0.0.1", port=port)
    controller.start()
    yield port
    controller.stop()


@pytest.fixture
def closed_port():
    """A port nobody listens on."""
    return _free_port()


@pytest.fixture
def silent_port():
    """Takes the connection and never says a word."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(4)
        yield sock.getsockname()[1]


@pytest.fixture
def busy_mail_server():
    """Greets with 554 instead of 220."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)

    def greet():
        connection, _ = sock.accept()
        with connection:
            connection.sendall(b"554 5.3.2 Kein Dienst\r\n")

    thread = threading.Thread(target=greet, daemon=True)
    thread.start()
    yield sock.getsockname()[1]
    thread.join(timeout=5)
    sock.close()


def _targets(monkeypatch, *targets: str, timeout: float = 5.0) -> None:
    monkeypatch.setattr(settings, "HEALTHCHECK_TARGETS", ",".join(targets))
    monkeypatch.setattr(settings, "HEALTHCHECK_TIMEOUT_SECONDS", timeout)


def test_web_container_passes(monkeypatch, capsys, web_server, closed_port):
    _targets(monkeypatch, f"{web_server}/api/v1/health", f"smtp://127.0.0.1:{closed_port}")
    assert healthcheck.main() == 0
    assert f"In Ordnung: {web_server}/api/v1/health antwortet." in capsys.readouterr().out


def test_mail_container_passes(monkeypatch, capsys, closed_port, mail_server):
    _targets(monkeypatch, f"http://127.0.0.1:{closed_port}/api/v1/health", f"smtp://127.0.0.1:{mail_server}")
    assert healthcheck.main() == 0
    assert f"In Ordnung: smtp://127.0.0.1:{mail_server} antwortet." in capsys.readouterr().out


def test_smtp_target_without_port_uses_the_port_of_the_mail_reception(monkeypatch, capsys, mail_server):
    monkeypatch.setattr(settings, "SMTP_INBOUND_PORT", mail_server)
    _targets(monkeypatch, "smtp://127.0.0.1")
    assert healthcheck.main() == 0
    assert f"smtp://127.0.0.1:{mail_server} antwortet" in capsys.readouterr().out


def test_no_service_answers(monkeypatch, capsys, closed_port):
    _targets(monkeypatch, f"http://127.0.0.1:{closed_port}/api/v1/health", f"smtp://127.0.0.1:{closed_port}")
    assert healthcheck.main() == 1
    message = capsys.readouterr().err
    assert message.startswith("Kein Dienst dieses Containers antwortet: ")
    assert f"http://127.0.0.1:{closed_port}/api/v1/health nimmt keine Verbindung an" in message
    assert f"smtp://127.0.0.1:{closed_port} nimmt keine Verbindung an" in message
    assert "docker compose logs" in message and "HEALTHCHECK_TARGETS" in message


def test_web_answer_outside_2xx_fails(web_server):
    assert healthcheck.probe(f"{web_server}/anderswo", 5.0) == "antwortet mit Status 503"


def test_greeting_other_than_220_fails(busy_mail_server):
    assert healthcheck.probe(f"smtp://127.0.0.1:{busy_mail_server}", 5.0) == "begrüßt mit 554 statt 220"


@pytest.mark.parametrize("scheme", ["http", "smtp"])
def test_silent_target_fails_after_the_time_limit(silent_port, scheme):
    assert healthcheck.probe(f"{scheme}://127.0.0.1:{silent_port}/", 0.5) == \
        "antwortet nicht innerhalb von 0,5 Sekunden"


def test_time_limit_comes_from_the_settings(monkeypatch, capsys, silent_port):
    _targets(monkeypatch, f"smtp://127.0.0.1:{silent_port}", timeout=0.75)
    assert healthcheck.main() == 1
    assert "antwortet nicht innerhalb von 0,75 Sekunden" in capsys.readouterr().err


def test_module_runs_as_the_image_calls_it(web_server, closed_port):
    environment = {**os.environ, "HEALTHCHECK_TARGETS": f"smtp://127.0.0.1:{closed_port},{web_server}/api/v1/health"}
    passed = subprocess.run([sys.executable, "-m", "app.healthcheck"], cwd=PROJECT_ROOT, env=environment,
                            capture_output=True, text=True, timeout=60)
    assert passed.returncode == 0, passed.stderr
    assert "In Ordnung" in passed.stdout

    environment["HEALTHCHECK_TARGETS"] = f"smtp://127.0.0.1:{closed_port}"
    failed = subprocess.run([sys.executable, "-m", "app.healthcheck"], cwd=PROJECT_ROOT, env=environment,
                            capture_output=True, text=True, timeout=60)
    assert failed.returncode == 1
    assert "Kein Dienst dieses Containers antwortet" in failed.stderr
