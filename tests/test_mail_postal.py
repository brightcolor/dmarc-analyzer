"""Outgoing mail over the Postal API and the check without sending. A stand-in answers in place of Postal."""
import json

import httpx
import pytest

from app.config import settings
from app.mail_check import main as mail_check
from app.services import mailer


@pytest.fixture
def postal(monkeypatch):
    """Records each request and answers with the prepared answer."""
    calls = []
    state = {"answer": {"status": "success", "data": {"message_id": "m1", "messages": {}}}, "status": 200,
             "raise": None}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if state["raise"]:
            raise state["raise"]
        if isinstance(state["answer"], str):
            return httpx.Response(state["status"], text=state["answer"])
        return httpx.Response(state["status"], json=state["answer"])

    monkeypatch.setattr(settings, "MAIL_BACKEND", "postal")
    monkeypatch.setattr(settings, "POSTAL_API_URL", "https://postal.example.test")
    monkeypatch.setattr(settings, "POSTAL_API_KEY", "schluessel-1234")
    monkeypatch.setattr(settings, "MAIL_FROM", "DMARC Analyzer <alerts@example.test>")
    monkeypatch.setattr(mailer, "_postal_client", lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    return calls, state


def test_mail_goes_to_the_api(postal):
    calls, _ = postal
    mailer.send_mail(["admin@example.test"], "Betreff", "Text", "<p>HTML</p>")
    request = calls[0]
    assert str(request.url) == "https://postal.example.test/api/v1/send/message"
    assert request.headers["X-Server-API-Key"] == "schluessel-1234"
    body = json.loads(request.content)
    assert body["to"] == ["admin@example.test"]
    assert body["from"] == "DMARC Analyzer <alerts@example.test>"
    assert body["plain_body"] == "Text" and body["html_body"] == "<p>HTML</p>"
    assert body["tag"] == "dmarc-analyzer"
    assert body["headers"] == {"Auto-Submitted": "auto-generated"}


def test_other_tag_and_none(postal, monkeypatch):
    calls, _ = postal
    monkeypatch.setattr(settings, "POSTAL_MESSAGE_TAG", "alarme")
    mailer.send_mail(["admin@example.test"], "Betreff", "Text")
    assert json.loads(calls[0].content)["tag"] == "alarme"
    monkeypatch.setattr(settings, "POSTAL_MESSAGE_TAG", "")
    mailer.send_mail(["admin@example.test"], "Betreff", "Text")
    body = json.loads(calls[1].content)
    assert "tag" not in body and "html_body" not in body


@pytest.mark.parametrize(("code", "expected"), [
    ("InvalidServerAPIKey", "Prüfe POSTAL_API_KEY"),
    ("UnauthenticatedFromAddress", "alerts@example.test"),
    ("ServerSuspended", "gesperrt"),
    ("SomethingNew", "Postal hat die Mail abgelehnt: Neu (Code SomethingNew)."),
])
def test_refusals_are_explained(postal, code, expected):
    _, state = postal
    state["answer"] = {"status": "error", "data": {"code": code, "message": "Neu"}}
    with pytest.raises(mailer.MailDeliveryError) as exc:
        mailer.send_mail(["admin@example.test"], "Betreff", "Text")
    assert expected in str(exc.value)


def test_error_page_is_explained(postal):
    _, state = postal
    state["answer"], state["status"] = "<html>Bad Gateway</html>", 502
    with pytest.raises(mailer.MailDeliveryError) as exc:
        mailer.send_mail(["admin@example.test"], "Betreff", "Text")
    assert "HTTP 502" in str(exc.value) and "postal.example.test" in str(exc.value)


def test_timeout_is_explained(postal):
    _, state = postal
    state["raise"] = httpx.ReadTimeout("zu langsam")
    with pytest.raises(mailer.MailDeliveryError) as exc:
        mailer.send_mail(["admin@example.test"], "Betreff", "Text")
    assert "Sekunden" in str(exc.value) and "später erneut" in str(exc.value)


def test_postal_needs_url_and_key(monkeypatch):
    monkeypatch.setattr(settings, "MAIL_BACKEND", "postal")
    monkeypatch.setattr(settings, "POSTAL_API_URL", "https://postal.example.test")
    monkeypatch.setattr(settings, "POSTAL_API_KEY", "")
    assert not mailer.mail_configured()
    with pytest.raises(mailer.MailNotConfigured) as exc:
        mailer.send_mail(["admin@example.test"], "Betreff", "Text")
    assert "POSTAL_API_KEY" in str(exc.value)


def test_check_accepts_a_valid_key(postal, capsys):
    calls, state = postal
    state["answer"] = {"status": "error", "data": {"code": "MessageNotFound", "message": "No message found"}}
    assert mail_check() == 0
    assert calls[0].url.path == "/api/v1/messages/message"
    assert "nimmt den API-Schlüssel an" in capsys.readouterr().out


def test_check_reports_a_wrong_key(postal, capsys):
    _, state = postal
    state["answer"] = {"status": "error", "data": {"code": "InvalidServerAPIKey"}}
    assert mail_check() == 1
    assert "POSTAL_API_KEY" in capsys.readouterr().err


def test_check_over_smtp(smtp_server, capsys):
    assert mail_check() == 0
    assert "ohne Anmeldung" in capsys.readouterr().out
