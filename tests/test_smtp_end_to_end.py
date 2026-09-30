"""The mail reception from RCPT TO to the stored report, over a real SMTP connection."""
import email.policy
import gzip
import logging
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

import pytest
from aiosmtpd.controller import Controller

import app.database
from app.config import settings
from app.models import (
    DmarcFailureReport,
    DmarcReport,
    Domain,
    ImportJob,
    InboundMailAddress,
    Organization,
    SmtpInboundMessage,
    TlsReport,
)
from app.services.import_service import get_or_create_domain
from app.services.inbound_address import create_domain_address
from smtp_inbound import handler as handler_module
from smtp_inbound.handler import TEMPORARY_FAILURE, DmarcSmtpHandler
from smtp_inbound.server import tls_context
from tests.conftest import SAMPLE_DMARC_XML
from tests.helpers import _free_port
from tests.test_failure_reports import ORIGINAL_WITH_REPORT, arf_mail
from tests.test_tls_reports import HUGE_NUMBER, tls_mail


@pytest.fixture
def reception(session, tmp_path, monkeypatch):
    """SMTP server with the real handler on a free port, writing into the test database."""
    monkeypatch.setattr(app.database, "SessionLocal", session.info["factory"])
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path / "uploads"))
    org = Organization(name="Muster Farben", slug="muster-farben", is_active=True)
    session.add(org)
    session.flush()
    domain = get_or_create_domain(session, org.id, "example.com")
    address = create_domain_address(session, org, domain).address
    session.commit()
    port = _free_port()
    controller = Controller(DmarcSmtpHandler(), hostname="127.0.0.1", port=port,
                            server_hostname="reports.example.test")
    controller.start()
    yield port, address
    controller.stop()


def _report_mail(recipient: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "noreply-dmarc@mail.example"
    message["To"] = recipient
    message["Subject"] = "Report Domain: example.com"
    message.set_content("DMARC-Bericht")
    message.add_attachment(gzip.compress(SAMPLE_DMARC_XML), maintype="application", subtype="gzip",
                           filename="google.com!example.com!1700000000!1700086399.xml.gz")
    return message


def test_report_arrives(reception, session):
    port, address = reception
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as smtp:
        smtp.send_message(_report_mail(address))
    session.expire_all()
    report = session.query(DmarcReport).one()
    assert report.report_id == "test-report-001"
    assert report.import_source == "smtp_inbound"
    assert session.query(ImportJob).one().status == "completed"
    message = session.query(SmtpInboundMessage).one()
    assert message.import_status == "completed"
    assert message.inbound_address_id == session.query(InboundMailAddress).filter_by(address=address).one().id


def test_unknown_recipient_is_refused(reception):
    port, address = reception
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as smtp:
        smtp.ehlo()
        smtp.mail("noreply@mail.example")
        code, text = smtp.rcpt("gibt-es-nicht@reports.example.test")
    assert code == 550
    assert b"Recipient unknown" in text


def test_unexpected_error_asks_to_try_again(reception, monkeypatch):
    port, address = reception

    def broken(*args, **kwargs):
        raise RuntimeError("Datenbank weg")

    monkeypatch.setattr(handler_module, "validate_recipient", broken)
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as smtp:
        smtp.ehlo()
        smtp.mail("noreply@mail.example")
        code, text = smtp.rcpt(address)
    assert f"{code} {text.decode()}" == TEMPORARY_FAILURE
    assert b"Datenbank" not in text


def test_failed_storage_asks_to_try_again(reception, monkeypatch):
    port, address = reception
    monkeypatch.setattr(DmarcSmtpHandler, "_persist_and_process", lambda self, **kwargs: False)
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as smtp:
        with pytest.raises(smtplib.SMTPDataError) as caught:
            smtp.send_message(_report_mail(address))
    assert caught.value.smtp_code == 451


def _send_raw(port: int, address: str, raw: bytes) -> None:
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as smtp:
        smtp.sendmail("dmarc-noreply@receiver.example", [address], raw)


def test_failure_report_arrives(reception, session):
    port, address = reception
    _send_raw(port, address, arf_mail(address))
    session.expire_all()
    report = session.query(DmarcFailureReport).one()
    assert report.reported_domain == "example.com"
    assert report.domain_id == session.query(Domain).filter_by(name="example.com").one().id
    message = session.query(SmtpInboundMessage).one()
    assert message.import_status == "completed"
    assert report.smtp_message_id == message.id
    assert report.reporter == "Empfaenger <dmarc-noreply@receiver.example>"
    assert session.query(ImportJob).count() == 0


def test_attachment_inside_a_failure_report_is_not_imported(reception, session):
    port, address = reception
    _send_raw(port, address, arf_mail(address, original=ORIGINAL_WITH_REPORT))
    session.expire_all()
    assert session.query(DmarcFailureReport).count() == 1
    assert session.query(ImportJob).count() == 0
    assert session.query(DmarcReport).count() == 0


def test_failure_reports_can_be_switched_off(reception, session, monkeypatch):
    monkeypatch.setattr(settings, "FAILURE_REPORTS_ENABLED", False)
    port, address = reception
    _send_raw(port, address, arf_mail(address))
    session.expire_all()
    assert session.query(DmarcFailureReport).count() == 0
    assert session.query(SmtpInboundMessage).one().error_message == "Die Mail enthielt keinen DMARC-Bericht als Anhang."


# TLS reports ---------------------------------------------------------------------------------

def test_tls_report_arrives(reception, session):
    port, address = reception
    _send_raw(port, address, tls_mail(address))
    session.expire_all()
    report = session.query(TlsReport).one()
    message = session.query(SmtpInboundMessage).one()
    assert report.smtp_message_id == message.id
    assert report.domain_id == session.query(Domain).filter_by(name="example.com").one().id
    assert (report.successful_sessions, report.failed_sessions) == (5326, 303)
    assert (message.import_status, message.error_message, message.attachment_count) == ("completed", None, 1)
    assert session.query(ImportJob).count() == 0


def test_tls_report_delivered_twice_is_stored_once(reception, session):
    port, address = reception
    _send_raw(port, address, tls_mail(address))
    _send_raw(port, address, tls_mail(address))
    session.expire_all()
    assert session.query(TlsReport).count() == 1
    notes = sorted(m.error_message or "" for m in session.query(SmtpInboundMessage))
    assert notes == ["", "Diesen TLS-Bericht gab es schon; die Anwendung hat ihn einmal gespeichert."]


def test_unreadable_tls_report_is_noted(reception, session):
    port, address = reception
    _send_raw(port, address, tls_mail(address, data=b"{kaputt"))
    session.expire_all()
    message = session.query(SmtpInboundMessage).one()
    assert message.import_status == "failed"
    assert message.error_message.startswith("Der TLS-Bericht ließ sich nicht lesen und bleibt unberücksichtigt.")
    assert session.query(ImportJob).count() == 0


def test_odd_tls_report_is_noted_once(reception, session):
    """A report the parser cannot hold is recorded as failed; the sender gets no request to deliver again."""
    port, address = reception
    _send_raw(port, address, tls_mail(address, data=HUGE_NUMBER))
    session.expire_all()
    message = session.query(SmtpInboundMessage).one()
    assert (message.import_status, message.attachment_count) == ("failed", 1)
    assert "außerhalb des lesbaren Bereichs" in message.error_message


def test_raw_utf8_headers_are_stored(reception, session):
    """A report mail with raw UTF-8 bytes in its headers arrives; before, it ended in 451 on every attempt."""
    port, address = reception
    raw = _report_mail(address).as_bytes(policy=email.policy.SMTP)
    raw = raw.replace(b"Subject: Report Domain: example.com", "Subject: Bericht für example.com".encode())
    raw = raw.replace(b"From: noreply-dmarc@mail.example", "From: Grüße <noreply-dmarc@mail.example>".encode())
    assert "für".encode() in raw
    _send_raw(port, address, raw)
    session.expire_all()
    message = session.query(SmtpInboundMessage).one()
    assert message.subject == "Bericht für example.com"
    assert message.header_from == "Grüße <noreply-dmarc@mail.example>"
    assert session.query(DmarcReport).count() == 1


def test_announced_tls_report_without_file_counts_no_attachment(reception, session):
    port, address = reception
    _send_raw(port, address, tls_mail(address, attach=False))
    session.expire_all()
    message = session.query(SmtpInboundMessage).one()
    assert (message.import_status, message.attachment_count) == ("failed", 0)
    assert "kündigt einen TLS-Bericht an" in message.error_message


def test_tls_reports_can_be_switched_off(reception, session, monkeypatch):
    monkeypatch.setattr(settings, "TLS_REPORTS_ENABLED", False)
    port, address = reception
    _send_raw(port, address, tls_mail(address))
    session.expire_all()
    assert session.query(TlsReport).count() == 0
    assert session.query(SmtpInboundMessage).one().import_status == "failed"


# STARTTLS ------------------------------------------------------------------------------------

TLS_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tls"


@pytest.fixture
def tls_on(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_INBOUND_TLS_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_INBOUND_TLS_CERT_PATH", str(TLS_FIXTURES / "localhost.crt"))
    monkeypatch.setattr(settings, "SMTP_INBOUND_TLS_KEY_PATH", str(TLS_FIXTURES / "localhost.key"))


def test_report_arrives_over_starttls(session, tmp_path, monkeypatch, tls_on):
    monkeypatch.setattr(app.database, "SessionLocal", session.info["factory"])
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path / "uploads"))
    org = Organization(name="Muster Farben", slug="muster-farben", is_active=True)
    session.add(org)
    session.flush()
    domain = get_or_create_domain(session, org.id, "example.com")
    address = create_domain_address(session, org, domain).address
    session.commit()
    port = _free_port()
    controller = Controller(DmarcSmtpHandler(), hostname="127.0.0.1", port=port, server_hostname="reports.example.test",
                            tls_context=tls_context(), require_starttls=False)
    controller.start()
    try:
        with smtplib.SMTP("127.0.0.1", port, timeout=10) as smtp:
            smtp.ehlo()
            assert smtp.has_extn("starttls")
            client = ssl.create_default_context(cafile=str(TLS_FIXTURES / "localhost.crt"))
            client.check_hostname = False
            smtp.starttls(context=client)
            assert smtp.sock.version() in ("TLSv1.2", "TLSv1.3")
            smtp.send_message(_report_mail(address))
    finally:
        controller.stop()
    session.expire_all()
    assert session.query(DmarcReport).one().report_id == "test-report-001"


def test_minimum_version_comes_from_the_settings(tls_on, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_INBOUND_TLS_MIN_VERSION", "TLSv1.3")
    assert tls_context().minimum_version == ssl.TLSVersion.TLSv1_3


def test_tls_off_offers_no_starttls():
    assert tls_context() is None


@pytest.mark.parametrize("problem", ["missing path", "unreadable file"])
def test_broken_certificate_keeps_reception_running(tls_on, monkeypatch, caplog, problem):
    if problem == "missing path":
        monkeypatch.setattr(settings, "SMTP_INBOUND_TLS_KEY_PATH", None)
    else:
        monkeypatch.setattr(settings, "SMTP_INBOUND_TLS_KEY_PATH", str(TLS_FIXTURES / "gibt-es-nicht.key"))
    with caplog.at_level(logging.ERROR, logger="smtp_inbound.server"):
        assert tls_context() is None
    assert "Der Empfang läuft ohne Verschlüsselung weiter" in caplog.text
