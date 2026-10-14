"""Findings of the second code review (30.09.2026): text from outside, isolation of rules and organisations,
report periods, the check on request. All data is invented."""
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import String, event

from app import scheduler
from app.config import load_settings, settings
from app.models import AlertEvent, TlsReport
from app.services import alert_service, dns_check
from app.services.dns_check import CheckRefused, _claim, _seconds, run_check, run_manual_check
from app.services.text import clean_text
from app.services.tls_reports import parse_tls_report, store_tls_report
from app.templates_config import _day_span
from tests.helpers import NOW, add_report, make_domain, make_org, make_rule
from tests.test_dns_check import ADDRESS, _dkim_row, _our_address, good_txt, resolver, run
from tests.test_tls_reports import report_json
from tests.test_web import _login, _seed


@pytest.fixture
def refuses_nul(session):
    """The test database refuses NUL in text the way PostgreSQL (psycopg2) does."""
    def check(conn, cursor, statement, parameters, context, executemany):
        rows = parameters if isinstance(parameters, list) else [parameters]
        for row in rows:
            values = row.values() if isinstance(row, dict) else (row or ())
            if any(isinstance(value, str) and "\x00" in value for value in values):
                raise ValueError("A string literal cannot contain NUL (0x00) characters.")

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", check)
    yield
    event.remove(engine, "before_cursor_execute", check)


class TestCleanText:
    def test_control_characters_go(self):
        assert clean_text("a\x00b\x07c\td\x7f") == "abc\td"
        assert clean_text("a \x00 b\n c", single_line=True) == "a b c"

    def test_raw_utf8_bytes_come_back(self):
        assert clean_text("Bericht f\udcc3\udcbcr") == "Bericht für"
        assert clean_text("kaputt \ud800") == "kaputt ?"

    def test_lowercase_before_the_cut(self):
        assert len("İ".lower()) == 2
        assert len(clean_text("İ" * 10, 10, lower=True)) == 10


class TestNulInDns:
    def test_rua_with_nul_leaves_no_nul(self):
        record = "v=DMARC1; p=reject; rua=mailto:x%00y@reports.example.test"
        check = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))["rua"]
        assert "\x00" not in check.message and "\x00" not in (check.found or "")

    def test_alert_job_goes_on(self, session, refuses_nul):
        attacker, victim = make_org(session, "Angreifer", "angreifer"), make_org(session, "Opfer", "opfer")
        bad, broken = make_domain(session, attacker, "angreifer.example"), make_domain(session, victim, "opfer.example")
        make_rule(session, attacker, "dns_problem")
        make_rule(session, victim, "dns_problem")
        session.commit()
        nul = "v=DMARC1; p=reject; rua=mailto:x%00y@reports.example.test"
        run_check(session, bad, resolver(txt={"_dmarc.angreifer.example": [nul]}), NOW)
        run_check(session, broken, resolver(txt={}), NOW)
        session.commit()
        scheduler._run_alerts(session, NOW)
        assert session.query(AlertEvent).filter_by(organization_id=victim.id).count() == 1
        assert session.query(AlertEvent).filter_by(organization_id=attacker.id).count() == 1

    def test_one_rule_that_breaks_leaves_the_others(self, session, monkeypatch):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        broken_rule = make_rule(session, org, "dns_problem")
        run_check(session, domain, resolver(txt={}), NOW)
        make_rule(session, org, "reports_missing", window=60, domain=domain)
        add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)], created_at=NOW - timedelta(days=5))
        real = alert_service.raise_event

        def raise_event(db, **kwargs):
            if kwargs.get("rule") is broken_rule:
                raise RuntimeError("kaputt")
            return real(db, **kwargs)

        monkeypatch.setattr(alert_service, "raise_event", raise_event)
        events = alert_service.evaluate_rules_for_org(session, org.id, NOW)
        assert [e.alert_type for e in events] == ["reports_missing"]

    def test_one_organisation_that_breaks_leaves_the_others(self, session, monkeypatch):
        first, second = make_org(session, "Erste", "erste"), make_org(session, "Zweite", "zweite")
        session.commit()
        seen = []

        def evaluate(db, org_id, now):
            seen.append(org_id)
            if org_id == first.id:
                raise RuntimeError("kaputt")
            return ["ein Alarm"]

        monkeypatch.setattr(alert_service, "evaluate_rules_for_org", evaluate)
        assert scheduler._run_alerts(session, NOW) == 1
        assert set(seen) == {first.id, second.id}


def _string_limits(obj) -> list[str]:
    problems = []
    for column in obj.__table__.columns:
        value = getattr(obj, column.key)
        if isinstance(value, str):
            if "\x00" in value:
                problems.append(f"{column.key} enthält NUL")
            if isinstance(column.type, String) and column.type.length and len(value) > column.type.length:
                problems.append(f"{column.key}: {len(value)} > {column.type.length}")
    return problems


class TestTlsValuesFitTheColumns:
    def test_growing_lowercase_and_nul(self, session):
        long = "İ" * 300
        document = json.loads(report_json(**{"organization-name": "Beispiel\x00 Mail AG"}))
        policy = document["policies"][0]
        policy["policy"].update({"policy-type": long, "policy-domain": long + ".example"})
        policy["failure-details"][0].update({"result-type": long, "receiving-mx-hostname": long,
                                             "receiving-mx-helo": long, "sending-mta-ip": "192.0.2.1\x00"})
        org = make_org(session)
        record = store_tls_report(session, parse_tls_report(json.dumps(document).encode()), organization_id=org.id)
        rows = [record, *record.policies, *[f for p in record.policies for f in p.failures]]
        assert [problem for row in rows for problem in _string_limits(row)] == []
        assert record.organization_name == "Beispiel Mail AG"

    def test_failure_detail_count_beyond_the_column(self):
        document = json.loads(report_json())
        document["policies"][0]["failure-details"][0]["failed-session-count"] = 3_000_000_000
        with pytest.raises(ValueError) as caught:
            parse_tls_report(json.dumps(document).encode())
        assert "unplausibel groß" in str(caught.value)

    def test_infinite_number(self):
        with pytest.raises(ValueError) as caught:
            parse_tls_report(b'{"report-id": "r", "policies": [{"summary": {"total-failure-session-count": 1e400}}]}')
        assert "ist keine Zahl" in str(caught.value)


class TestReportPeriods:
    @pytest.mark.parametrize(("begin", "end", "reason"), [
        ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00.5Z", "außerhalb der Zeit, die ein Tagesbericht nennen kann"),
        ("2099-01-01T00:00:00Z", "2099-01-02T00:00:00Z", "außerhalb der Zeit"),
        ("2026-09-27T00:00:00Z", "2026-09-26T00:00:00Z", "Das Ende des Zeitraums liegt vor seinem Beginn"),
    ])
    def test_implausible_periods(self, begin, end, reason):
        with pytest.raises(ValueError) as caught:
            parse_tls_report(report_json(**{"date-range": {"start-datetime": begin, "end-datetime": end}}),
                             now=NOW)
        assert reason in str(caught.value)

    def test_window_comes_from_the_settings(self, monkeypatch):
        data = report_json(**{"date-range": {"start-datetime": "2026-09-25T00:00:00Z",
                                             "end-datetime": "2026-09-28T11:00:00Z"}})
        assert parse_tls_report(data, now=NOW).period_begin.day == 25
        monkeypatch.setattr(settings, "TLS_REPORT_MAX_AGE_DAYS", 2)
        with pytest.raises(ValueError):
            parse_tls_report(data, now=NOW)
        monkeypatch.setattr(settings, "TLS_REPORT_MAX_AGE_DAYS", 400)
        monkeypatch.setattr(settings, "TLS_REPORT_FUTURE_TOLERANCE_HOURS", 0)
        with pytest.raises(ValueError):
            parse_tls_report(data, now=NOW)

    def test_display_of_a_period_at_the_start_of_the_calendar(self):
        begin = datetime(1, 1, 1, tzinfo=UTC)
        # strftime writes year 1 as "1" on Linux and as "0001" on Windows
        assert _day_span(begin, begin + timedelta(microseconds=500_000)).startswith("01.01.")

    def test_pages_with_such_a_report(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        begin = datetime(1, 1, 1, tzinfo=UTC)
        record = TlsReport(organization_id=ids["org"], report_id="alt", policy_domain="example.com",
                           period_begin=begin, period_end=begin + timedelta(microseconds=500_000),
                           successful_sessions=1, failed_sessions=0)
        db.add(record)
        db.commit()
        report_id = record.id
        db.close()
        _login(web, ids["org"])
        assert web.get("/tls-reports").status_code == 200
        assert web.get(f"/tls-reports/{report_id}").status_code == 200


class TestDkimByReportedPeriod:
    def test_upload_of_old_reports(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        old = add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)], created_at=NOW)
        old.period_end = NOW - timedelta(days=20)
        _dkim_row(session, old, "alt")
        older = add_report(session, org, domain, [("192.0.2.2", 5, True, True, True)], created_at=NOW)
        older.period_end = NOW - timedelta(days=40)
        _dkim_row(session, older, "uralt")
        session.flush()
        found = dns_check.gather_input(session, domain, NOW)
        assert found.dkim_selectors == ["alt"]
        last = found.dkim_last_pass["alt"]
        assert (last.replace(tzinfo=UTC) if last.tzinfo is None else last) == NOW - timedelta(days=20)
        result = dns_check.check_domain(found, resolver(txt=good_txt(**{"alt._domainkey.example.com": None})), NOW)
        assert next(c for c in result.checks if c.key == "dkim:alt").state == "warning"


class TestCheckOnRequest:
    def test_claim_holds_before_the_result_is_stored(self, session, monkeypatch):
        monkeypatch.setattr(settings, "DNS_CHECK_MANUAL_COOLDOWN_SECONDS", 60)
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        session.commit()
        assert _claim(session, domain, NOW) == 0
        assert _claim(session, domain, NOW + timedelta(seconds=1)) == 59
        assert _claim(session, domain, NOW + timedelta(seconds=61)) == 0

    def test_parallel_limit(self, session, monkeypatch):
        monkeypatch.setattr(settings, "DNS_CHECK_MANUAL_PARALLEL", 2)
        monkeypatch.setattr(dns_check, "_manual_running", 2)
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        with pytest.raises(CheckRefused) as caught:
            run_manual_check(session, domain, resolver(txt={}), NOW)
        assert str(caught.value).startswith("Gerade laufen schon 2 Prüfungen auf Knopfdruck.")
        assert domain.dns_checked_at is None

    def test_slot_comes_back(self, session, monkeypatch):
        monkeypatch.setattr(settings, "DNS_CHECK_MANUAL_COOLDOWN_SECONDS", 0)
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        _our_address(session, org, domain)
        run_manual_check(session, domain, resolver(), NOW)
        assert dns_check._manual_running == 0

        def broken(*args, **kwargs):
            raise RuntimeError("kaputt")

        monkeypatch.setattr(dns_check, "run_check", broken)
        with pytest.raises(RuntimeError):
            run_manual_check(session, domain, resolver(), NOW)
        assert dns_check._manual_running == 0

    def test_seconds_in_words(self):
        assert (_seconds(1), _seconds(30)) == ("1 Sekunde", "30 Sekunden")


class TestSmallerPoints:
    def test_tls_reporting_ignores_a_lowercase_twin(self):
        records = [f"v=TLSRPTv1; rua=mailto:{ADDRESS}", "v=tlsrptv1; rua=mailto:x@y.example"]
        assert run(resolver(txt=good_txt(**{"_smtp._tls.example.com": records})))["tlsrpt"].state == "ok"

    def test_ri_beyond_32_bit(self):
        record = f"v=DMARC1; p=reject; ri=4294967296; rua=mailto:{ADDRESS}; ruf=mailto:{ADDRESS}; fo=1"
        assert "ri=4294967296 ist ungültig" in run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))[
            "syntax"].message

    def test_active_days_within_the_window(self, monkeypatch):
        monkeypatch.setenv("DNS_CHECK_DKIM_DAYS", "5")
        monkeypatch.setenv("DNS_CHECK_DKIM_ACTIVE_DAYS", "7")
        with pytest.raises(SystemExit) as exc:
            load_settings()
        assert "DNS_CHECK_DKIM_ACTIVE_DAYS darf nicht über DNS_CHECK_DKIM_DAYS liegen" in str(exc.value)

    @pytest.mark.parametrize(("name", "value", "reason"), [
        ("DNS_CHECK_MANUAL_PARALLEL", "0", "muss mindestens 1 sein"),
        ("TLS_REPORT_MAX_AGE_DAYS", "0", "muss mindestens 1 sein"),
        ("TLS_REPORT_FUTURE_TOLERANCE_HOURS", "1000", "darf höchstens 720 sein"),
    ])
    def test_settings_have_bounds(self, name, value, reason, monkeypatch):
        monkeypatch.setenv(name, value)
        with pytest.raises(SystemExit) as exc:
            load_settings()
        assert f"{name}: {reason}" in str(exc.value)
