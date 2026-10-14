"""Failure reports (ruf): reading ARF mails, storing, retention, pages and API. All data is invented."""
import base64
from datetime import timedelta

import pytest

from app.config import load_settings, settings
from app.models import AuditLog, DmarcFailureReport, Domain, Organization, User
from app.services.auth import create_api_token
from app.services.failure_reports import parse_failure_report, store_failure_report
from app.services.retention import run_retention
from tests.helpers import NOW, aware, make_domain, make_org
from tests.test_web import _login, _seed

FEEDBACK = (
    "Feedback-Type: auth-failure\r\n"
    "User-Agent: EmpfaengerFBL/1.0\r\n"
    "Version: 1\r\n"
    "Original-Mail-From: <bounce@mailer.example>\r\n"
    "Original-Rcpt-To: <kunde@receiver.example>\r\n"
    "Arrival-Date: Mon, 28 Sep 2026 10:15:00 +0000\r\n"
    "Reporting-MTA: dns; mx.receiver.example\r\n"
    "Source-IP: 192.0.2.25\r\n"
    "Incidents: 2\r\n"
    "Delivery-Result: spam\r\n"
    "Auth-Failure: dmarc\r\n"
    "Identity-Alignment: none\r\n"
    "Authentication-Results: mx.receiver.example; dmarc=fail header.from=example.com;\r\n"
    " spf=pass smtp.mailfrom=mailer.example; dkim=fail header.d=example.com\r\n"
    "DKIM-Domain: example.com\r\n"
    "DKIM-Selector: s1\r\n"
    "Reported-Domain: example.com\r\n"
)

ORIGINAL = (
    "From: Muster Farben <info@example.com>\r\n"
    "To: kunde@receiver.example\r\n"
    "Subject: =?utf-8?q?Deine_Rechnung_f=C3=BCr_September?=\r\n"
    "Message-ID: <abc123@mailer.example>\r\n"
    "Date: Mon, 28 Sep 2026 10:14:55 +0000\r\n"
    "\r\n"
    "Vertraulicher Inhalt der Mail, der nie gespeichert werden darf.\r\n"
)

ORIGINAL_WITH_REPORT = (
    "From: Muster Farben <info@example.com>\r\n"
    "Subject: Bericht als Anhang\r\n"
    "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/mixed; boundary="innen"\r\n'
    "\r\n"
    "--innen\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "Anbei.\r\n"
    "--innen\r\n"
    'Content-Type: application/xml; name="report.xml"\r\n'
    'Content-Disposition: attachment; filename="report.xml"\r\n'
    "\r\n"
    "<feedback><report_metadata><report_id>darf-nicht-importiert-werden</report_id></report_metadata></feedback>\r\n"
    "--innen--\r\n"
)


def arf_mail(recipient: str = "ruf@reports.example.test", original: str = ORIGINAL,
             original_type: str = "message/rfc822", feedback: str = FEEDBACK, feedback_base64: bool = False) -> bytes:
    feedback_head = "Content-Type: message/feedback-report\r\n"
    if feedback_base64:
        feedback_head += "Content-Transfer-Encoding: base64\r\n"
        feedback = base64.encodebytes(feedback.encode()).decode().replace("\n", "\r\n")
    return (
        "From: Empfaenger <dmarc-noreply@receiver.example>\r\n"
        f"To: {recipient}\r\n"
        "Subject: DMARC-Fehlerbericht fuer example.com\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/report; report-type=feedback-report; boundary="grenze"\r\n'
        "\r\n"
        "--grenze\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Dies ist ein Fehlerbericht.\r\n"
        "--grenze\r\n"
        f"{feedback_head}"
        "\r\n"
        f"{feedback}"
        "\r\n"
        "--grenze\r\n"
        f"Content-Type: {original_type}\r\n"
        "\r\n"
        f"{original}"
        "--grenze--\r\n"
    ).encode()


class TestParser:
    def test_fields_of_an_arf_report(self):
        report = parse_failure_report(arf_mail())
        assert report.feedback_type == "auth-failure"
        assert report.auth_failure == "dmarc"
        assert report.identity_alignment == "none"
        assert report.delivery_result == "spam"
        assert report.reported_domain == "example.com"
        assert report.source_ip == "192.0.2.25"
        assert report.incidents == 2
        assert report.arrival_date == NOW.replace(minute=15)
        assert report.original_mail_from == "bounce@mailer.example"
        assert report.original_rcpt_to == "kunde@receiver.example"
        assert report.reporting_mta == "mx.receiver.example"
        assert report.dkim_domain == "example.com" and report.dkim_selector == "s1"
        assert "spf=pass" in report.authentication_results

    def test_reported_mail_keeps_its_header_and_loses_its_body(self):
        report = parse_failure_report(arf_mail())
        assert report.header_from == "Muster Farben <info@example.com>"
        assert report.subject == "Deine Rechnung für September"
        assert report.message_id == "<abc123@mailer.example>"
        assert "Subject: Deine Rechnung für September" in report.original_headers
        assert "Vertraulicher Inhalt" not in report.original_headers

    def test_header_only_variant(self):
        headers_only = ORIGINAL.split("\r\n\r\n")[0] + "\r\n"
        report = parse_failure_report(arf_mail(original=headers_only, original_type="text/rfc822-headers"))
        assert report.header_from == "Muster Farben <info@example.com>"
        assert "Message-ID: <abc123@mailer.example>" in report.original_headers

    def test_base64_feedback_part(self):
        report = parse_failure_report(arf_mail(feedback_base64=True))
        assert report.auth_failure == "dmarc"
        assert report.source_ip == "192.0.2.25"

    def test_reported_domain_falls_back_to_the_sender(self):
        feedback = "\r\n".join(line for line in FEEDBACK.split("\r\n") if not line.startswith("Reported-Domain"))
        assert parse_failure_report(arf_mail(feedback=feedback)).reported_domain == "example.com"

    def test_aggregate_report_mail_is_no_failure_report(self):
        mail = (b"From: a@receiver.example\r\nTo: b@reports.example.test\r\nSubject: Report\r\n"
                b"Content-Type: text/plain\r\n\r\nNur Text.\r\n")
        assert parse_failure_report(mail) is None

    def test_headers_can_stay_unsaved(self, monkeypatch):
        monkeypatch.setattr(settings, "FAILURE_REPORT_STORE_HEADERS", False)
        report = parse_failure_report(arf_mail())
        assert report.original_headers is None
        assert report.subject == "Deine Rechnung für September"

    def test_header_size_limit(self, monkeypatch):
        monkeypatch.setattr(settings, "FAILURE_REPORT_MAX_HEADER_BYTES", 1024)
        long_subject = "Subject: " + "x" * 3000 + "\r\n"
        report = parse_failure_report(arf_mail(original=long_subject + ORIGINAL))
        assert len(report.original_headers.encode()) <= 1024 + len("\n[gekürzt]".encode())
        assert report.original_headers.endswith("[gekürzt]")


class TestStorage:
    def test_domain_from_the_reported_domain(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        record = store_failure_report(session, parse_failure_report(arf_mail()), organization_id=org.id,
                                      reporter="dmarc-noreply@receiver.example")
        assert record.domain_id == domain.id
        assert record.failed_checks == ["dmarc"]

    def test_unknown_domain_stays_open(self, session):
        org = make_org(session)
        make_domain(session, org, "anders.example")
        record = store_failure_report(session, parse_failure_report(arf_mail()), organization_id=org.id)
        assert record.domain_id is None

    def test_domain_of_another_organisation_is_not_used(self, session):
        org = make_org(session)
        other = make_org(session, "Andere", "andere")
        make_domain(session, other, "example.com")
        record = store_failure_report(session, parse_failure_report(arf_mail()), organization_id=org.id)
        assert record.domain_id is None


class TestRetention:
    def _report(self, session, org, days_old: int) -> DmarcFailureReport:
        record = store_failure_report(session, parse_failure_report(arf_mail()), organization_id=org.id)
        record.created_at = NOW - timedelta(days=days_old)
        session.flush()
        return record

    def test_setting_decides(self, session, monkeypatch):
        monkeypatch.setattr(settings, "FAILURE_REPORT_RETENTION_DAYS", 3)
        org = make_org(session)
        old, fresh = self._report(session, org, 5), self._report(session, org, 1)
        result = run_retention(session, now=NOW)
        assert result.failure_reports == 1
        assert [r.id for r in session.query(DmarcFailureReport)] == [fresh.id]
        assert old not in session.query(DmarcFailureReport).all()

    def test_shorter_organisation_retention_wins(self, session, monkeypatch):
        monkeypatch.setattr(settings, "FAILURE_REPORT_RETENTION_DAYS", 30)
        org = make_org(session)
        org.report_retention_days = 2
        self._report(session, org, 3)
        assert run_retention(session, now=NOW).failure_reports == 1


class TestPages:
    def _stored(self, session_factory, org_id: str) -> str:
        db = session_factory()
        record = store_failure_report(db, parse_failure_report(arf_mail()), organization_id=org_id,
                                      reporter="dmarc-noreply@receiver.example")
        db.commit()
        report_id = record.id
        db.close()
        return report_id

    def test_list_and_detail(self, web, session_factory):
        ids = _seed(session_factory)
        report_id = self._stored(session_factory, ids["org"])
        _login(web, ids["org"])
        listing = web.get("/failure-reports")
        assert listing.status_code == 200
        assert "192.0.2.25" in listing.text and "als Spam einsortiert" in listing.text
        assert "Fehlerberichte" in listing.text
        detail = web.get(f"/failure-reports/{report_id}")
        assert detail.status_code == 200
        assert "weder DKIM noch SPF passen zur Domain" in detail.text
        assert "Deine Rechnung für September" in detail.text
        assert "Vertraulicher Inhalt" not in detail.text

    def test_filters(self, web, session_factory):
        ids = _seed(session_factory)
        self._stored(session_factory, ids["org"])
        _login(web, ids["org"])
        assert "192.0.2.25" in web.get("/failure-reports?check=dmarc").text
        assert "192.0.2.25" not in web.get("/failure-reports?check=spf").text
        assert "192.0.2.25" in web.get("/failure-reports?search=192.0.2").text
        assert "Keine Fehlerberichte zu diesem Filter" in web.get("/failure-reports?search=nirgends").text

    def test_manager_deletes(self, web, session_factory):
        ids = _seed(session_factory, role="manager", superadmin=False)
        report_id = self._stored(session_factory, ids["org"])
        _login(web, ids["org"])
        response = web.post(f"/failure-reports/{report_id}/delete")
        assert response.status_code == 303
        db = session_factory()
        assert db.query(DmarcFailureReport).count() == 0
        assert db.query(AuditLog).filter_by(action="failure_report.delete").count() == 1
        db.close()

    def test_analyst_cannot_delete(self, web, session_factory):
        ids = _seed(session_factory, role="analyst", superadmin=False)
        report_id = self._stored(session_factory, ids["org"])
        _login(web, ids["org"])
        assert "Fehlerbericht löschen" not in web.get(f"/failure-reports/{report_id}").text
        assert web.post(f"/failure-reports/{report_id}/delete").status_code == 403

    def test_other_organisation_sees_nothing(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        other = Organization(name="Andere", slug="andere", is_active=True)
        db.add(other)
        db.commit()
        other_id = other.id
        db.close()
        report_id = self._stored(session_factory, other_id)
        _login(web, ids["org"])
        assert web.get(f"/failure-reports/{report_id}").status_code == 404
        assert "192.0.2.25" not in web.get("/failure-reports").text

    def test_api_lists_reports(self, web, session_factory):
        ids = _seed(session_factory)
        self._stored(session_factory, ids["org"])
        db = session_factory()
        user = db.query(User).filter_by(email="admin@example.test").one()
        raw, _ = create_api_token(db, ids["org"], user.id, "Automatik")
        db.commit()
        db.close()
        body = web.get("/api/v1/failure-reports", headers={"Authorization": f"Bearer {raw}"}).json()
        assert body["total"] == 1
        result = body["results"][0]
        assert result["source_ip"] == "192.0.2.25" and result["auth_failure"] == ["dmarc"]
        assert "original_headers" not in result


@pytest.mark.parametrize(("name", "value", "reason"), [
    ("FAILURE_REPORT_MAX_HEADER_BYTES", "100", "muss mindestens 1024 sein"),
    ("FAILURE_REPORT_RETENTION_DAYS", "0", "muss mindestens 1 sein"),
    ("POSTAL_API_URL", "postal.example.com", "muss mit http:// oder https:// beginnen"),
])
def test_settings_have_bounds(name, value, reason, monkeypatch):
    monkeypatch.setenv(name, value)
    with pytest.raises(SystemExit) as exc:
        load_settings()
    assert f"{name}: {reason}" in str(exc.value)


def test_domain_link_survives_on_the_model(session):
    org = make_org(session)
    domain = make_domain(session, org, "example.com")
    record = store_failure_report(session, parse_failure_report(arf_mail()), organization_id=org.id)
    assert record.domain.name == domain.name
    assert aware(record.arrival_date) == NOW.replace(minute=15)
    assert session.query(Domain).count() == 1
