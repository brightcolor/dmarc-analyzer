"""TLS reports (TLS-RPT, RFC 8460): reading, storing, alerts, retention, pages and API. All data is invented."""
import base64
import copy
import gzip
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import StaticPool

from app.config import load_settings, settings
from app.migrate import run_migrations
from app.models import (
    AuditLog,
    Base,
    Domain,
    Organization,
    SmtpInboundMessage,
    TlsReport,
    TlsReportFailure,
    TlsReportPolicy,
    User,
)
from app.services.alert_service import alert_type_hints, evaluate_rules_for_org
from app.services.auth import create_api_token
from app.services.inbound_address import create_domain_address
from app.services.mime_parser import ZipBombError
from app.services.retention import run_retention
from app.services.tls_reports import (
    find_tls_reports,
    mail_outcome,
    parse_tls_report,
    store_tls_report,
    summarize,
)
from tests.helpers import NOW, aware, make_domain, make_org, make_rule
from tests.test_web import _login, _seed

# Built after the example in RFC 8460, 4.8, with documentation addresses and example names
REPORT = {
    "organization-name": "Beispiel-Mail AG",
    "date-range": {"start-datetime": "2026-09-27T00:00:00Z", "end-datetime": "2026-09-27T23:59:59Z"},
    "contact-info": "tls-reports@mail.example",
    "report-id": "2026-09-27T00:00:00Z_example.com",
    "policies": [{
        "policy": {
            "policy-type": "sts",
            "policy-string": ["version: STSv1", "mode: enforce", "mx: mx.example.com", "max_age: 604800"],
            "policy-domain": "example.com",
            "mx-host": ["mx.example.com"],
        },
        "summary": {"total-successful-session-count": 5326, "total-failure-session-count": 303},
        "failure-details": [
            {"result-type": "certificate-expired", "sending-mta-ip": "2001:db8:abcd:12::1",
             "receiving-mx-hostname": "mx.example.com", "failed-session-count": 100},
            {"result-type": "starttls-not-supported", "sending-mta-ip": "2001:db8:abcd:13::1",
             "receiving-mx-hostname": "mx2.example.com", "receiving-ip": "203.0.113.56",
             "failed-session-count": 200, "additional-information": "https://reports.mail.example/info?id=1"},
            {"result-type": "sts-policy-fetch-error", "sending-mta-ip": "198.51.100.62",
             "receiving-ip": "203.0.113.58", "receiving-mx-hostname": "mx-backup.example.com",
             "failed-session-count": 3, "failure-reason-code": "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"},
        ],
    }],
}


def report_json(**changes) -> bytes:
    document = copy.deepcopy(REPORT)
    document.update(changes)
    return json.dumps(document).encode()


def tls_mail(recipient: str = "tls@reports.example.test", data: bytes | None = None, compressed: bool = True,
             content_type: str | None = None, filename: str | None = None, report_type: str | None = "tlsrpt",
             attach: bool = True) -> bytes:
    """A report mail after RFC 8460, 5.3: multipart/report with the JSON file, mostly compressed."""
    data = report_json() if data is None else data
    payload = gzip.compress(data) if compressed else data
    content_type = content_type or ("application/tlsrpt+gzip" if compressed else "application/tlsrpt+json")
    filename = filename or ("mail.example!example.com!1790467200!1790553599!001.json" + (".gz" if compressed else ""))
    outer = f'multipart/report; report-type="{report_type}"' if report_type else "multipart/mixed"
    body = base64.encodebytes(payload).decode().replace("\n", "\r\n")
    attachment = (
        "--grenze\r\n"
        f"Content-Type: {content_type}\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        "\r\n"
        f"{body}"
    ) if attach else ""
    return (
        "From: TLS-Berichte <tls-reports@mail.example>\r\n"
        f"To: {recipient}\r\n"
        "Subject: Report Domain: example.com Submitter: mail.example Report-ID: <2026-09-27T00:00:00Z_example.com>\r\n"
        "TLS-Report-Domain: example.com\r\n"
        "TLS-Report-Submitter: mail.example\r\n"
        "MIME-Version: 1.0\r\n"
        f'Content-Type: {outer}; boundary="grenze"\r\n'
        "\r\n"
        "--grenze\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Dies ist ein TLS-Bericht.\r\n"
        f"{attachment}"
        "--grenze--\r\n"
    ).encode()


def plain_mail(filename: str, data: bytes, content_type: str = "application/json") -> bytes:
    """Some other mail with an attachment and none of the marks of a TLS report."""
    body = base64.encodebytes(data).decode().replace("\n", "\r\n")
    return (
        "From: jemand@mail.example\r\nTo: tls@reports.example.test\r\nSubject: Anhang\r\nMIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="grenze"\r\n\r\n'
        "--grenze\r\nContent-Type: text/plain\r\n\r\nAnbei.\r\n"
        f'--grenze\r\nContent-Type: {content_type}\r\nContent-Transfer-Encoding: base64\r\n'
        f'Content-Disposition: attachment; filename="{filename}"\r\n\r\n{body}'
        "--grenze--\r\n"
    ).encode()


class TestParser:
    def test_fields_of_a_report(self):
        report = parse_tls_report(report_json())
        assert report.report_id == "2026-09-27T00:00:00Z_example.com"
        assert report.organization_name == "Beispiel-Mail AG"
        assert report.contact_info == "tls-reports@mail.example"
        assert report.period_begin == datetime(2026, 9, 27, tzinfo=UTC)
        assert report.period_end == datetime(2026, 9, 27, 23, 59, 59, tzinfo=UTC)
        assert report.policy_domain == "example.com"
        assert (report.successful_sessions, report.failed_sessions) == (5326, 303)
        policy = report.policies[0]
        assert policy.policy_type == "sts"
        assert policy.policy_strings[1] == "mode: enforce"
        assert policy.mx_hosts == ["mx.example.com"]
        expired, missing, fetch = policy.failures
        assert (expired.result_type, expired.failed_sessions) == ("certificate-expired", 100)
        assert missing.receiving_ip == "203.0.113.56"
        assert missing.additional_information == "https://reports.mail.example/info?id=1"
        assert fetch.failure_reason_code == "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"

    def test_other_time_zones_become_utc(self):
        report = parse_tls_report(report_json(**{"date-range": {"start-datetime": "2026-09-27T02:00:00+02:00",
                                                                "end-datetime": "2026-09-27T23:59:59"}}))
        assert report.period_begin == datetime(2026, 9, 27, tzinfo=UTC)
        assert report.period_end == datetime(2026, 9, 27, 23, 59, 59, tzinfo=UTC)

    def test_single_values_instead_of_lists(self):
        document = json.loads(report_json())
        document["policies"][0]["policy"]["mx-host"] = "MX.Example.com."
        document["policies"][0]["policy"]["policy-string"] = "version: STSv1"
        policy = parse_tls_report(json.dumps(document).encode()).policies[0]
        assert policy.mx_hosts == ["MX.Example.com."]
        assert policy.policy_strings == ["version: STSv1"]

    def test_report_without_policy_found(self):
        document = json.loads(report_json())
        document["policies"] = [{"policy": {"policy-type": "no-policy-found", "policy-domain": "Example.com."},
                                 "summary": {"total-successful-session-count": 12,
                                             "total-failure-session-count": 0}}]
        report = parse_tls_report(json.dumps(document).encode())
        assert report.policy_domain == "example.com"
        assert report.policies[0].failures == []
        assert report.failed_sessions == 0

    @pytest.mark.parametrize(("data", "reason"), [
        (b"{nicht json", "kein gültiges JSON (Zeile 1, Spalte 2)"),
        (b"[]", "kein JSON-Objekt"),
        (b"\xff\xfe", "kein UTF-8-Text"),
        (report_json(**{"report-id": ""}), "fehlt die Kennung (report-id)"),
        (report_json(policies={"a": 1}), "fehlt die Liste der Richtlinien (policies)"),
        (report_json(policies=[{"summary": {"total-successful-session-count": -4}}]), "ist negativ (-4)"),
        (report_json(policies=[{"summary": {"total-failure-session-count": "viele"}}]), "ist keine Zahl ('viele')"),
        (report_json(**{"date-range": {"start-datetime": "gestern"}}), "kein Zeitpunkt nach RFC 3339"),
    ])
    def test_unreadable_reports_say_why(self, data, reason):
        with pytest.raises(ValueError) as caught:
            parse_tls_report(data)
        assert reason in str(caught.value)

    @pytest.mark.parametrize("limit", [1, 2])
    def test_policy_limit_comes_from_the_settings(self, monkeypatch, limit):
        monkeypatch.setattr(settings, "TLS_REPORT_MAX_POLICIES", limit)
        policies = REPORT["policies"] * 3
        with pytest.raises(ValueError) as caught:
            parse_tls_report(report_json(policies=policies))
        assert f"enthält 3 Richtlinien, erlaubt sind höchstens {limit} (TLS_REPORT_MAX_POLICIES)" in str(caught.value)

    @pytest.mark.parametrize(("limit", "kept"), [(2, [200, 100]), (1, [200])])
    def test_failure_detail_limit_keeps_the_largest(self, monkeypatch, limit, kept):
        monkeypatch.setattr(settings, "TLS_REPORT_MAX_FAILURE_DETAILS", limit)
        report = parse_tls_report(report_json())
        assert sorted((f.failed_sessions for f in report.policies[0].failures), reverse=True) == kept
        assert report.failure_details_omitted == 3 - limit
        assert report.failed_sessions == 303


# A number with more digits than Python converts (limit 4300)
HUGE_NUMBER = (b'{"report-id": "r1", "policies": [{"summary": {"total-successful-session-count": '
               + b"9" * 5000 + b"}}]}")


class TestOddReports:
    """Findings of the review from 30.09.2026: every odd input ends as a readable error."""

    @pytest.mark.parametrize(("data", "reason"), [
        (HUGE_NUMBER, "einen Wert außerhalb des lesbaren Bereichs"),
        (report_json(**{"date-range": {"start-datetime": "9999-12-31T23:59:59-01:00"}}),
         "kein Zeitpunkt nach RFC 3339"),
        (report_json(policies=[{"summary": {"total-failure-session-count": 3_000_000_000}}]), "unplausibel groß"),
        (report_json(policies=[{"summary": {"total-successful-session-count": 2_000_000_000}}] * 2),
         "Die Summe erfolgreicher Verbindungen ist unplausibel groß"),
    ])
    def test_rejected_with_a_reason(self, data, reason):
        with pytest.raises(ValueError) as caught:
            parse_tls_report(data)
        assert reason in str(caught.value)
        found = find_tls_reports(tls_mail(data=data))
        assert found.reports == [] and reason in found.errors[0]

    def test_unexpected_error_becomes_a_note(self, monkeypatch):
        from app.services import tls_reports

        def broken(data):
            raise RuntimeError("kaputt")

        monkeypatch.setattr(tls_reports, "parse_tls_report", broken)
        found = find_tls_reports(tls_mail())
        assert found.errors == ["mail.example!example.com!1790467200!1790553599!001.json.gz: Der TLS-Bericht ließ "
                                "sich nicht lesen (RuntimeError); der Betreiber findet den Grund im Log der Anwendung."]

    def test_files_are_counted(self):
        assert find_tls_reports(tls_mail()).files == 1
        assert find_tls_reports(tls_mail(attach=False)).files == 0


class TestFindingReports:
    def test_compressed_report(self):
        found = find_tls_reports(tls_mail())
        assert found.errors == []
        assert [r.report_id for r in found.reports] == ["2026-09-27T00:00:00Z_example.com"]

    def test_plain_json_report(self):
        found = find_tls_reports(tls_mail(compressed=False))
        assert len(found.reports) == 1 and found.errors == []

    def test_report_with_a_general_media_type(self):
        mail = tls_mail(content_type="application/gzip", report_type=None)
        found = find_tls_reports(mail.replace(b"TLS-Report-Domain", b"X-Domain").replace(b"TLS-Report-Submitter",
                                                                                         b"X-Submitter"))
        assert len(found.reports) == 1

    def test_other_json_files_stay_with_the_dmarc_import(self):
        assert find_tls_reports(plain_mail("daten.json", b'{"a": 1}')) is None
        assert find_tls_reports(plain_mail("daten.json.gz", gzip.compress(b"[1, 2]"), "application/gzip")) is None

    def test_dmarc_report_is_no_tls_report(self):
        assert find_tls_reports(plain_mail("google.com!example.com!1!2.xml.gz", gzip.compress(b"<feedback/>"),
                                           "application/gzip")) is None

    def test_announced_report_that_cannot_be_read(self):
        found = find_tls_reports(tls_mail(data=b"{kaputt"))
        assert found.reports == []
        assert found.errors == ["mail.example!example.com!1790467200!1790553599!001.json.gz: Der TLS-Bericht ist "
                                "kein gültiges JSON (Zeile 1, Spalte 2)."]

    def test_broken_gzip(self):
        mail = tls_mail(compressed=False, content_type="application/tlsrpt+gzip", filename="bericht.json.gz")
        found = find_tls_reports(mail)
        assert "bericht.json.gz: Die Datei ließ sich nicht entpacken: Die Datei ist keine GZ-Datei." in found.errors

    def test_announced_report_without_file(self):
        found = find_tls_reports(tls_mail(attach=False))
        assert found.reports == []
        assert "kündigt einen TLS-Bericht an, enthält aber keine Datei" in found.errors[0]

    def test_archive_bomb_is_passed_on(self, monkeypatch):
        monkeypatch.setattr(settings, "ARCHIVE_MAX_UNPACKED_BYTES", 1000)
        with pytest.raises(ZipBombError):
            find_tls_reports(tls_mail(data=report_json(padding="x" * 5000)))


class TestStorage:
    def test_domain_from_the_policy_domain(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        stored = store_tls_report(session, parse_tls_report(report_json()), organization_id=org.id)
        session.expire_all()
        record = session.get(TlsReport, stored.id)
        assert record.domain_id == domain.id
        assert (record.successful_sessions, record.failed_sessions, record.total_sessions) == (5326, 303, 5629)
        assert round(record.failure_rate, 2) == 5.38
        policy = record.policies[0]
        assert policy.policy_lines[0] == "version: STSv1" and policy.mx_host_list == ["mx.example.com"]
        assert [f.failed_sessions for f in policy.failures] == [200, 100, 3]

    def test_receiving_address_names_an_unknown_domain(self, session):
        org = make_org(session)
        other = make_domain(session, org, "example.org")
        record = store_tls_report(session, parse_tls_report(report_json()), organization_id=org.id,
                                  domain_id=other.id)
        assert record.domain_id == other.id

    def test_domain_of_another_organisation_is_not_used(self, session):
        org = make_org(session)
        make_domain(session, make_org(session, "Andere", "andere"), "example.com")
        assert store_tls_report(session, parse_tls_report(report_json()), organization_id=org.id).domain_id is None

    def test_same_report_is_stored_once_per_organisation(self, session):
        org = make_org(session)
        other = make_org(session, "Andere", "andere")
        report = parse_tls_report(report_json())
        assert store_tls_report(session, report, organization_id=org.id) is not None
        assert store_tls_report(session, report, organization_id=org.id) is None
        assert store_tls_report(session, report, organization_id=other.id) is not None
        assert session.query(TlsReport).count() == 2

    @pytest.mark.parametrize(("stored", "duplicates", "errors", "status", "note"), [
        (1, 0, [], "completed", None),
        (0, 1, [], "completed", "Diesen TLS-Bericht gab es schon; die Anwendung hat ihn einmal gespeichert."),
        (0, 0, ["a.json: kaputt."], "failed",
         "Der TLS-Bericht ließ sich nicht lesen und bleibt unberücksichtigt. a.json: kaputt."),
        (1, 0, ["b.json: kaputt."], "completed", "Ein Teil ließ sich nicht lesen: b.json: kaputt."),
    ])
    def test_outcome_of_the_mail(self, stored, duplicates, errors, status, note):
        assert mail_outcome(stored, duplicates, errors) == (status, note)


def _stored(db, org, successful: int, failed: int, created_at: datetime = NOW, domain: str = "example.com",
            report_id: str | None = None, reason: str = "certificate-expired") -> TlsReport:
    document = json.loads(report_json(**{"report-id": report_id or f"r-{domain}-{created_at.timestamp()}"}))
    policy = document["policies"][0]
    policy["policy"]["policy-domain"] = domain
    policy["summary"] = {"total-successful-session-count": successful, "total-failure-session-count": failed}
    policy["failure-details"] = [{"result-type": reason, "failed-session-count": failed}] if failed else []
    record = store_tls_report(db, parse_tls_report(json.dumps(document).encode()), organization_id=org.id)
    record.created_at = created_at
    db.flush()
    return record


class TestAlerts:
    def test_rule_for_all_domains_names_the_domain(self, session):
        org = make_org(session)
        make_domain(session, org, "example.com")
        make_domain(session, org, "example.org")
        make_rule(session, org, "tls_failure_rate", window=1440)
        _stored(session, org, 900, 100)
        _stored(session, org, 1000, 0, domain="example.org")
        events = evaluate_rules_for_org(session, org.id, now=NOW)
        assert [e.title for e in events] == ["10 % der TLS-Verbindungen gescheitert für example.com"]
        assert "100 von 1.000 Verbindungen" in events[0].description
        assert "Häufigster Grund: Zertifikat abgelaufen (100)" in events[0].description
        assert json.loads(events[0].metrics)["top_result"] == "certificate-expired"

    @pytest.mark.parametrize(("default", "fires"), [(5.0, True), (10.0, True), (12.5, False)])
    def test_default_threshold_comes_from_the_settings(self, session, monkeypatch, default, fires):
        monkeypatch.setattr(settings, "ALERT_DEFAULT_TLS_FAIL_RATE", default)
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        make_rule(session, org, "tls_failure_rate", window=1440, domain=domain)
        _stored(session, org, 900, 100)
        assert bool(evaluate_rules_for_org(session, org.id, now=NOW)) is fires

    def test_own_threshold_and_minimum(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        make_rule(session, org, "tls_failure_rate", threshold=20, window=1440, domain=domain)
        make_rule(session, org, "tls_failure_rate", threshold=1, window=1440, domain=domain, min_messages=5000)
        _stored(session, org, 900, 100)
        assert evaluate_rules_for_org(session, org.id, now=NOW) == []

    def test_reports_outside_the_window_do_not_count(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        make_rule(session, org, "tls_failure_rate", window=1440, domain=domain)
        _stored(session, org, 0, 50, created_at=NOW - timedelta(days=2))
        assert evaluate_rules_for_org(session, org.id, now=NOW) == []

    def test_hint_names_the_default(self, monkeypatch):
        assert "Vorgabe 5 %" in alert_type_hints()["tls_failure_rate"]
        monkeypatch.setattr(settings, "ALERT_DEFAULT_TLS_FAIL_RATE", 7.5)
        assert "Vorgabe 7,5 %" in alert_type_hints()["tls_failure_rate"]

    def test_summary(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        _stored(session, org, 900, 60, reason="starttls-not-supported")
        _stored(session, org, 100, 40, created_at=NOW - timedelta(hours=1))
        summary = summarize(session, org.id, NOW - timedelta(days=1), NOW + timedelta(seconds=1), domain.id)
        assert (summary.reports, summary.total, summary.failed) == (2, 1100, 100)
        assert (summary.top_result, summary.top_result_sessions) == ("starttls-not-supported", 60)


class TestRetention:
    @pytest.mark.parametrize("days", [3, 10])
    def test_organisation_retention_decides(self, session, days):
        org = make_org(session)
        org.report_retention_days = days
        old = _stored(session, org, 10, 5, created_at=NOW - timedelta(days=days + 1), report_id="alt")
        fresh = _stored(session, org, 10, 5, created_at=NOW - timedelta(days=days - 1), report_id="neu")
        old_id = old.id
        result = run_retention(session, now=NOW)
        assert result.tls_reports == 1
        assert [r.id for r in session.query(TlsReport)] == [fresh.id]
        assert session.query(TlsReportPolicy).filter_by(report_id=old_id).count() == 0
        assert session.query(TlsReportFailure).count() == 1

    def test_removed_mail_keeps_the_report(self, session):
        org = make_org(session)
        message = SmtpInboundMessage(organization_id=org.id, envelope_recipient="tls@reports.example.test",
                                     received_at=NOW - timedelta(days=400), size_bytes=10, import_status="completed")
        session.add(message)
        session.flush()
        report = _stored(session, org, 10, 0)
        report.smtp_message_id = message.id
        session.flush()
        run_retention(session, now=NOW)
        session.refresh(report)
        assert report.smtp_message_id is None


class TestPages:
    def _stored(self, session_factory, org_id: str) -> str:
        db = session_factory()
        record = store_tls_report(db, parse_tls_report(report_json()), organization_id=org_id)
        db.commit()
        report_id = record.id
        db.close()
        return report_id

    def test_list_and_detail(self, web, session_factory):
        ids = _seed(session_factory)
        report_id = self._stored(session_factory, ids["org"])
        _login(web, ids["org"])
        listing = web.get("/tls-reports")
        assert listing.status_code == 200
        assert '<a class="bc-row-title" href="/tls-reports/' in listing.text
        assert "Beispiel-Mail AG" in listing.text and "27.09.2026" in listing.text
        assert 'href="/tls-reports" aria-current="page">TLS-Berichte</a>' in listing.text
        detail = web.get(f"/tls-reports/{report_id}")
        assert detail.status_code == 200
        text = detail.text
        assert "MTA-STS für example.com" in text
        assert "Zertifikat abgelaufen" in text and "STARTTLS fehlt" in text
        assert "https://mta-sts.example.com/.well-known/mta-sts.txt" in text
        assert "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED" in text
        assert "27.09.2026 00:00 UTC bis 27.09.2026 23:59 UTC" in text

    def test_filters(self, web, session_factory):
        ids = _seed(session_factory)
        self._stored(session_factory, ids["org"])
        _login(web, ids["org"])
        assert "Beispiel-Mail AG" in web.get("/tls-reports?outcome=failed").text
        assert "Beispiel-Mail AG" not in web.get("/tls-reports?outcome=clean").text
        assert "Beispiel-Mail AG" in web.get("/tls-reports?search=beispiel").text
        assert "Keine TLS-Berichte zu diesem Filter" in web.get("/tls-reports?search=nirgends").text

    def test_domain_page_shows_the_dns_record_and_figures(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        org = db.get(Organization, ids["org"])
        domain = db.query(Domain).filter_by(organization_id=org.id, name="example.com").one()
        address = create_domain_address(db, org, domain).address
        record = store_tls_report(db, parse_tls_report(report_json()), organization_id=org.id)
        record.created_at = datetime.now(UTC)
        db.commit()
        domain_id = domain.id
        db.close()
        _login(web, ids["org"])
        page = web.get(f"/domains/{domain_id}").text
        assert "_smtp._tls.example.com" in page
        assert f"v=TLSRPTv1; rua=mailto:{address}" in page
        assert "1 Bericht über 5.629 Verbindungen" in page
        assert "303 gescheitert" in page and "Häufigster Grund: STARTTLS fehlt" in page

    def test_domain_page_without_reports_explains_the_record(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        assert "Noch keine TLS-Berichte" in web.get(f"/domains/{ids['domain']}").text

    def test_switched_off(self, web, session_factory, monkeypatch):
        monkeypatch.setattr(settings, "TLS_REPORTS_ENABLED", False)
        ids = _seed(session_factory)
        _login(web, ids["org"])
        assert 'id="tls-titel"' not in web.get(f"/domains/{ids['domain']}").text

    def test_received_mail_links_to_its_report(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        message = SmtpInboundMessage(organization_id=ids["org"], envelope_recipient="tls@reports.example.test",
                                     received_at=datetime.now(UTC), size_bytes=10, import_status="completed")
        db.add(message)
        db.flush()
        record = store_tls_report(db, parse_tls_report(report_json()), organization_id=ids["org"],
                                  smtp_message_id=message.id)
        db.commit()
        report_id = record.id
        db.close()
        _login(web, ids["org"])
        assert f'href="/tls-reports/{report_id}">TLS-Bericht ansehen' in web.get("/smtp/messages").text

    def test_manager_deletes(self, web, session_factory):
        ids = _seed(session_factory, role="manager", superadmin=False)
        report_id = self._stored(session_factory, ids["org"])
        _login(web, ids["org"])
        assert web.post(f"/tls-reports/{report_id}/delete").status_code == 303
        db = session_factory()
        assert db.query(TlsReport).count() == 0
        assert db.query(TlsReportFailure).count() == 0
        assert db.query(AuditLog).filter_by(action="tls_report.delete").count() == 1
        db.close()

    def test_analyst_cannot_delete(self, web, session_factory):
        ids = _seed(session_factory, role="analyst", superadmin=False)
        report_id = self._stored(session_factory, ids["org"])
        _login(web, ids["org"])
        assert "TLS-Bericht löschen" not in web.get(f"/tls-reports/{report_id}").text
        assert web.post(f"/tls-reports/{report_id}/delete").status_code == 403

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
        assert web.get(f"/tls-reports/{report_id}").status_code == 404
        assert web.post(f"/tls-reports/{report_id}/delete").status_code == 404
        assert "Beispiel-Mail AG" not in web.get("/tls-reports").text

    def test_api_lists_reports(self, web, session_factory):
        ids = _seed(session_factory)
        self._stored(session_factory, ids["org"])
        db = session_factory()
        user = db.query(User).filter_by(email="admin@example.test").one()
        raw, _ = create_api_token(db, ids["org"], user.id, "Automatik")
        db.commit()
        db.close()
        body = web.get("/api/v1/tls-reports", headers={"Authorization": f"Bearer {raw}"}).json()
        assert body["total"] == 1
        result = body["results"][0]
        assert (result["successful_sessions"], result["failed_sessions"]) == (5326, 303)
        policy = result["policies"][0]
        assert policy["policy_type"] == "sts" and policy["mx_host"] == ["mx.example.com"]
        assert policy["failure_details"][0] == {
            "result_type": "starttls-not-supported", "sending_mta_ip": "2001:db8:abcd:13::1",
            "receiving_mx_hostname": "mx2.example.com", "receiving_mx_helo": None, "receiving_ip": "203.0.113.56",
            "failed_sessions": 200, "failure_reason_code": None,
            "additional_information": "https://reports.mail.example/info?id=1",
        }


@pytest.mark.parametrize(("name", "value", "reason"), [
    ("TLS_REPORT_MAX_POLICIES", "0", "muss mindestens 1 sein"),
    ("TLS_REPORT_MAX_FAILURE_DETAILS", "200000", "darf höchstens 100000 sein"),
    ("ALERT_DEFAULT_TLS_FAIL_RATE", "150", "darf höchstens 100.0 sein"),
    ("TLS_REPORTS_ENABLED", "vielleicht", "muss true oder false sein"),
])
def test_settings_have_bounds(name, value, reason, monkeypatch):
    monkeypatch.setenv(name, value)
    with pytest.raises(SystemExit) as exc:
        load_settings()
    assert f"{name}: {reason}" in str(exc.value)


def test_migration_matches_the_model():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    run_migrations(engine)
    inspector = inspect(engine)
    for table in ("tls_reports", "tls_report_policies", "tls_report_failures"):
        migrated = {c["name"] for c in inspector.get_columns(table)}
        assert migrated == set(Base.metadata.tables[table].columns.keys()), table
    engine.dispose()


def test_period_is_stored_in_utc(session):
    org = make_org(session)
    record = store_tls_report(session, parse_tls_report(report_json()), organization_id=org.id)
    session.expire_all()
    stored = session.get(TlsReport, record.id)
    assert aware(stored.period_begin) == datetime(2026, 9, 27, tzinfo=UTC)
