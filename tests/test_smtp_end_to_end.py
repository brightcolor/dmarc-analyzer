"""The mail reception from RCPT TO to the stored report, over a real SMTP connection."""
import gzip
import smtplib
from email.message import EmailMessage

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
)
from app.services.inbound_address import create_domain_address
from app.services.import_service import get_or_create_domain
from smtp_inbound import handler as handler_module
from smtp_inbound.handler import TEMPORARY_FAILURE, DmarcSmtpHandler
from tests.conftest import SAMPLE_DMARC_XML
from tests.helpers import _free_port
from tests.test_failure_reports import ORIGINAL_WITH_REPORT, arf_mail


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
