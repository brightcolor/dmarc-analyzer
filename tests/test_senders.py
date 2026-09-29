"""Senders with names: catalog, evidence, DNS lookups, decisions and their effect on alerts."""
import json
from datetime import timedelta

import pytest

from app.config import settings
from app.models import AlertEvent, DmarcAuthResult, DmarcRecord, SenderApproval, SourceIp
from app.services import sender_lookup, senders
from app.services.alert_service import evaluate_rules_for_org
from app.services.sender_lookup import LookupResult, asn_name, lookup
from app.services.senders import (
    auth_evidence,
    classify_manually,
    decide,
    identify,
    load_catalog,
    parse_catalog,
    refresh_sources,
)
from tests.helpers import NOW, add_report, add_source, make_domain, make_org, make_rule, minutes_ago


def _auth(session, report, ip, kind, domain, result="pass"):
    record = session.query(DmarcRecord).filter_by(report_id=report.id, source_ip=ip).first()
    session.add(DmarcAuthResult(record_id=record.id, auth_type=kind, domain=domain, result=result))
    session.flush()


@pytest.fixture
def dns(monkeypatch):
    """Answers for the lookups in app.services.senders, per IP address."""
    answers: dict[str, LookupResult] = {}
    monkeypatch.setattr(settings, "SENDER_LOOKUP_ENABLED", True)
    monkeypatch.setattr(senders, "lookup", lambda ip: answers.get(ip, LookupResult()))
    return answers


class TestCatalog:
    def test_builtin_catalog_is_clean(self):
        catalog = load_catalog()
        assert catalog.problems == []
        assert len(catalog.senders) >= 20
        for sender in catalog.senders.values():
            assert sender.rdns or sender.dkim or sender.spf, sender.key

    def test_extra_file_adds_and_replaces(self, tmp_path, monkeypatch):
        extra = tmp_path / "katalog.json"
        extra.write_text(json.dumps({"senders": [
            {"key": "google", "name": "Google Workspace", "kind": "mailbox", "rdns": ["google.com"]},
            {"key": "beispiel-crm", "name": "Beispiel-CRM", "kind": "app", "dkim": ["crm.example.net"]},
        ]}), encoding="utf-8")
        monkeypatch.setattr(settings, "SENDER_CATALOG_PATH", str(extra))
        catalog = load_catalog()
        assert catalog.problems == []
        assert catalog.name("google") == "Google Workspace"
        assert catalog.get("beispiel-crm").dkim == ("crm.example.net",)
        assert catalog.get("amazon-ses") is not None

    def test_problems_are_explained(self):
        senders_found, problems = parse_catalog({"senders": [
            {"key": "X Y", "name": "Leerzeichen", "kind": "esp"},
            {"key": "ok-1", "name": "", "kind": "esp"},
            {"key": "ok-2", "name": "Falsche Art", "kind": "bank"},
            {"key": "ok-3", "name": "Falsche Domain", "kind": "esp", "dkim": ["kein domain"]},
        ]}, "test.json")
        assert list(senders_found) == ["ok-3"]
        assert senders_found["ok-3"].dkim == ()
        assert "darf nur Kleinbuchstaben" in problems[0]
        assert "fehlt der Name" in problems[1]
        assert "Die Art „bank“ gibt es nicht" in problems[2]
        assert "ist keine Domain" in problems[3]

    def test_broken_or_missing_extra_file(self, tmp_path, monkeypatch):
        broken = tmp_path / "kaputt.json"
        broken.write_text("{senders: ", encoding="utf-8")
        monkeypatch.setattr(settings, "SENDER_CATALOG_PATH", str(broken))
        catalog = load_catalog()
        assert "ließ sich nicht lesen" in catalog.problems[0]
        assert catalog.get("google") is not None
        monkeypatch.setattr(settings, "SENDER_CATALOG_PATH", str(tmp_path / "fehlt.json"))
        assert "fehlt" in load_catalog().problems[0]


class TestIdentify:
    def test_confirmed_host_name(self):
        found = identify(load_catalog(), "mail-sor-f41.google.com", True, [], [])
        assert (found.sender.key, found.evidence) == ("google", "Hostname mail-sor-f41.google.com")

    @pytest.mark.parametrize("host", ["mail.evilgoogle.com", "google.com.evil.example", "googlecom"])
    def test_look_alike_names_do_not_count(self, host):
        assert identify(load_catalog(), host, True, [], []).sender is None

    def test_unconfirmed_host_name_does_not_count(self):
        assert identify(load_catalog(), "mail-sor-f41.google.com", False, [], []).sender is None

    def test_dkim_and_spf(self):
        catalog = load_catalog()
        assert identify(catalog, None, False, ["em123.sendgrid.info"], []).sender.key == "sendgrid"
        found = identify(catalog, None, False, ["example.org"], ["bounce.mcsv.net"])
        assert (found.sender.key, found.evidence) == ("mailchimp", "SPF für bounce.mcsv.net")

    def test_host_name_comes_first(self):
        found = identify(load_catalog(), "a8-1.smtp-out.amazonses.com", True, ["em1.sendgrid.info"], [])
        assert found.sender.key == "amazon-ses"


class TestEvidence:
    def test_only_passing_results_of_the_address(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        report = add_report(session, org, domain, [("192.0.2.1", 5, True, True, True),
                                                   ("192.0.2.2", 5, True, True, True)])
        _auth(session, report, "192.0.2.1", "dkim", "Mail.AmazonSES.com")
        _auth(session, report, "192.0.2.1", "dkim", "fail.example", result="fail")
        _auth(session, report, "192.0.2.1", "spf", "bounce.example.org")
        _auth(session, report, "192.0.2.2", "dkim", "other.example")
        assert auth_evidence(session, org.id, "192.0.2.1") == (["mail.amazonses.com"], ["bounce.example.org"])


class TestLookup:
    @pytest.fixture
    def answers(self, monkeypatch):
        table: dict[tuple[str, str], list[str]] = {}
        monkeypatch.setattr(settings, "SENDER_LOOKUP_ENABLED", True)
        monkeypatch.setattr(sender_lookup, "_query", lambda resolver, name, kind: table.get((name, kind), []))
        return table

    def test_confirmed_name_and_operator(self, answers):
        answers[("10.2.0.192.in-addr.arpa.", "PTR")] = ["mail-a.google.com."]
        answers[("mail-a.google.com", "A")] = ["192.0.2.10"]
        answers[("10.2.0.192.origin.asn.cymru.com", "TXT")] = ['"15169 | 192.0.2.0/24 | US | arin | 2005-09-21"']
        answers[("AS15169.asn.cymru.com", "TXT")] = ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"']
        assert lookup("192.0.2.10") == LookupResult("mail-a.google.com", True, "15169", "GOOGLE - Google LLC", "US")

    def test_name_that_points_elsewhere(self, answers):
        answers[("11.2.0.192.in-addr.arpa.", "PTR")] = ["mail.google.com."]
        answers[("mail.google.com", "A")] = ["198.51.100.1"]
        result = lookup("192.0.2.11")
        assert (result.reverse_dns, result.reverse_dns_confirmed) == ("mail.google.com", False)

    def test_nothing_found(self, answers):
        assert lookup("192.0.2.12") == LookupResult()

    def test_switched_off(self, answers, monkeypatch):
        answers[("10.2.0.192.in-addr.arpa.", "PTR")] = ["mail-a.google.com."]
        monkeypatch.setattr(settings, "SENDER_LOOKUP_ENABLED", False)
        assert lookup("192.0.2.10") == LookupResult()

    def test_zones_come_from_the_settings(self, monkeypatch):
        monkeypatch.setattr(settings, "SENDER_ASN_ZONE_V4", "origin.asn.example.net")
        monkeypatch.setattr(settings, "SENDER_ASN_ZONE_V6", "origin6.asn.example.net")
        assert asn_name("192.0.2.10") == "10.2.0.192.origin.asn.example.net"
        assert asn_name("2001:db8::1").endswith(".8.b.d.0.1.0.0.2.origin6.asn.example.net")


class TestRefresh:
    def test_sources_get_their_sender(self, session, dns):
        org = make_org(session)
        google = add_source(session, org, "192.0.2.1", total=10)
        unknown = add_source(session, org, "192.0.2.2", total=5)
        dns["192.0.2.1"] = LookupResult("mail-sor-f41.google.com", True, "15169", "GOOGLE - Google LLC", "US")
        result = refresh_sources(session, NOW)
        assert (result.checked, result.identified) == (2, 1)
        assert (google.sender_key, google.sender_evidence) == ("google", "Hostname mail-sor-f41.google.com")
        assert (google.asn, google.country_code) == ("15169", "US")
        assert unknown.sender_key is None
        assert unknown.enriched_at is not None

    def test_batch_and_refresh_interval(self, session, dns, monkeypatch):
        monkeypatch.setattr(settings, "SENDER_LOOKUP_BATCH_SIZE", 1)
        monkeypatch.setattr(settings, "SENDER_LOOKUP_REFRESH_DAYS", 10)
        org = make_org(session)
        big = add_source(session, org, "192.0.2.1", total=100)
        small = add_source(session, org, "192.0.2.2", total=1)
        assert refresh_sources(session, NOW).checked == 1
        assert big.enriched_at is not None and small.enriched_at is None
        assert refresh_sources(session, NOW).checked == 1
        assert refresh_sources(session, NOW + timedelta(days=5)).checked == 0
        assert refresh_sources(session, NOW + timedelta(days=11)).checked == 1

    def test_failed_lookup_keeps_earlier_answers(self, session, dns):
        org = make_org(session)
        source = add_source(session, org, "192.0.2.1", total=10, reverse_dns="mail-sor-f41.google.com")
        source.reverse_dns_confirmed = True
        refresh_sources(session, NOW)
        assert (source.reverse_dns, source.sender_key) == ("mail-sor-f41.google.com", "google")


class TestDecisions:
    def _sources(self, session, dns):
        org = make_org(session)
        first = add_source(session, org, "192.0.2.1", total=10)
        second = add_source(session, org, "192.0.2.2", total=10)
        manual = add_source(session, org, "192.0.2.3", total=10, classification="suspicious")
        manual.classification_source = "manual"
        for ip in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
            dns[ip] = LookupResult(f"a{ip[-1]}.smtp-out.amazonses.com", True)
        refresh_sources(session, NOW)
        return org, first, second, manual

    def test_approval_covers_all_addresses_but_manual_ones(self, session, dns):
        org, first, second, manual = self._sources(session, dns)
        assert decide(session, org.id, "amazon-ses", "trusted", None) == 2
        assert (first.classification, first.classification_source) == ("trusted", "sender")
        assert first.classification_reason == "Freigabe für Amazon SES"
        assert manual.classification == "suspicious"

    def test_new_address_of_an_approved_sender(self, session, dns):
        org, *_ = self._sources(session, dns)
        decide(session, org.id, "amazon-ses", "trusted", None)
        newcomer = add_source(session, org, "192.0.2.9", total=3)
        dns["192.0.2.9"] = LookupResult("a9.smtp-out.amazonses.com", True)
        refresh_sources(session, NOW)
        assert (newcomer.classification, newcomer.classification_source) == ("trusted", "sender")

    def test_reset_and_change(self, session, dns):
        org, first, second, manual = self._sources(session, dns)
        decide(session, org.id, "amazon-ses", "trusted", None)
        decide(session, org.id, "amazon-ses", "suspicious", None)
        assert first.classification == "suspicious"
        assert first.classification_reason == "Amazon SES als verdächtig eingestuft"
        assert decide(session, org.id, "amazon-ses", "reset", None) == 2
        assert (first.classification, first.classification_source) == ("unknown", None)
        assert session.query(SenderApproval).count() == 0

    def test_manual_unknown_hands_back_to_the_sender_decision(self, session, dns):
        org, first, second, manual = self._sources(session, dns)
        decide(session, org.id, "amazon-ses", "trusted", None)
        classify_manually(first, "ignored", None, session)
        assert (first.classification, first.classification_source) == ("ignored", "manual")
        decide(session, org.id, "amazon-ses", "suspicious", None)
        assert first.classification == "ignored"
        classify_manually(first, "unknown", None, session)
        assert (first.classification, first.classification_source) == ("suspicious", "sender")


class TestAlerts:
    def test_new_source_waits_for_its_sender(self, session, dns, monkeypatch):
        monkeypatch.setattr(settings, "SCHEDULER_ENABLED", True)
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)], created_at=minutes_ago(5))
        add_source(session, org, "192.0.2.1", total=5, first_seen=minutes_ago(5))
        make_rule(session, org, "new_unknown_source", cooldown=0)
        assert evaluate_rules_for_org(session, org.id, NOW) == []
        dns["192.0.2.1"] = LookupResult("mail1.us4.mcsv.net", True)
        refresh_sources(session, NOW)
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert [e.title for e in events] == ["Neue unbekannte Quelle 192.0.2.1 (Mailchimp und Mandrill)"]
        assert "gib ihn unter „Absender“ frei" in events[0].description

    def test_approved_sender_stays_quiet(self, session, dns, monkeypatch):
        monkeypatch.setattr(settings, "SCHEDULER_ENABLED", True)
        org = make_org(session)
        decide(session, org.id, "mailchimp", "trusted", None)
        add_source(session, org, "192.0.2.1", total=5, first_seen=minutes_ago(5))
        make_rule(session, org, "new_unknown_source")
        dns["192.0.2.1"] = LookupResult("mail1.us4.mcsv.net", True)
        refresh_sources(session, NOW)
        assert evaluate_rules_for_org(session, org.id, NOW) == []
        assert session.query(AlertEvent).count() == 0
        assert session.query(SourceIp).one().classification == "trusted"


# Pages ------------------------------------------------------------------------------------

from tests.test_web import _login, _seed  # noqa: E402


class TestSenderPages:
    def _identify(self, session_factory, org_id):
        db = session_factory()
        for source in db.query(SourceIp).filter_by(organization_id=org_id):
            source.reverse_dns, source.reverse_dns_confirmed = f"mail-{source.ip_address[-1]}.google.com", True
        refresh_sources(db, everything=True)
        db.commit()
        db.close()

    def test_list_decide_and_filter(self, web, session_factory):
        ids = _seed(session_factory)
        self._identify(session_factory, ids["org"])
        _login(web, ids["org"])
        page = web.get("/senders")
        assert page.status_code == 200
        assert "Google" in page.text
        response = web.post("/senders/google/decide", data={"decision": "trusted"})
        assert response.status_code == 303
        page = web.get("/senders")
        assert "Google ist freigegeben" in page.text
        listing = web.get("/source-ips?sender=google")
        assert "über den Absender" in listing.text
        assert web.get("/source-ips?sender=none").status_code == 200

    def test_unknown_sender_or_decision(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        assert web.post("/senders/gibt-es-nicht/decide", data={"decision": "trusted"}).status_code == 404
        assert web.post("/senders/google/decide", data={"decision": "vielleicht"}).status_code == 400

    def test_refresh_now(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        assert "warten auf die Zuordnung" in web.get("/senders").text
        web.post("/senders/refresh")
        page = web.get("/senders")
        assert "IP-Adressen geprüft" in page.text
        assert "warten auf die Zuordnung" not in page.text

    def test_detail_names_the_sender(self, web, session_factory):
        ids = _seed(session_factory)
        self._identify(session_factory, ids["org"])
        _login(web, ids["org"])
        page = web.get(f"/source-ips/{ids['source']}")
        assert "erkannt über Hostname" in page.text
