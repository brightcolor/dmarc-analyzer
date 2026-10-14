"""Source rules: networks, countries and host names from the settings classify new sources."""
import pytest

from app.config import load_settings, settings
from app.models import SourceIp
from app.services import senders, source_rules
from app.services.alert_service import evaluate_rules_for_org
from app.services.sender_lookup import LookupResult
from app.services.senders import classify_manually, decide, refresh_sources
from app.services.source_rules import apply_rules, apply_rules_all, match
from tests.helpers import NOW, add_report, add_source, make_domain, make_org, make_rule, minutes_ago


@pytest.fixture(autouse=True)
def _fresh_rules(monkeypatch):
    """Rules from the settings of the test, and no memory of an earlier full pass."""
    monkeypatch.setattr(source_rules, "_applied", None)
    monkeypatch.setattr(settings, "SOURCE_RULES_ENABLED", True)
    monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "")
    monkeypatch.setattr(settings, "SOURCE_RULE_COUNTRIES", "")
    monkeypatch.setattr(settings, "SOURCE_RULE_RDNS_PATTERNS", "")
    monkeypatch.setattr(settings, "SOURCE_RULE_CLASSIFICATION", "suspicious")
    monkeypatch.setattr(settings, "SOURCE_RULE_MAX_PASSED_MESSAGES", 0)


@pytest.fixture
def dns(monkeypatch):
    answers: dict[str, LookupResult] = {}
    monkeypatch.setattr(settings, "SENDER_LOOKUP_ENABLED", True)
    monkeypatch.setattr(senders, "lookup", lambda ip: answers.get(ip, LookupResult()))
    return answers


def _source(session, org, ip="192.0.2.1", total=2, failed=2, **fields):
    source = add_source(session, org, ip, total=total, failed=failed)
    for name, value in fields.items():
        setattr(source, name, value)
    return source


class TestMatch:
    def test_nothing_configured_matches_nothing(self, session):
        source = _source(session, make_org(session), asn="8193", country_code="UZ", reverse_dns="x.dialup.example.net")
        assert match(source) is None

    @pytest.mark.parametrize("configured", ["8193", "AS8193", "as8193", "1, 8193 ,2"])
    def test_asn_in_both_spellings(self, session, monkeypatch, configured):
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", configured)
        source = _source(session, make_org(session), asn="8193", asn_org="BRM-AS - Uzbektelekom")
        assert match(source) == "Das Netz AS8193 (BRM-AS - Uzbektelekom) steht in den Quellenregeln"
        assert match(_source(session, make_org(session, "B", "b"), ip="192.0.2.2", asn="15169")) is None

    def test_country(self, session, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_COUNTRIES", "kz, UZ")
        org = make_org(session)
        assert "Land KZ" in match(_source(session, org, country_code="KZ"))
        assert match(_source(session, org, ip="192.0.2.2", country_code="DE")) is None

    def test_word_pattern_matches_a_part_of_the_host_name(self, session, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_RDNS_PATTERNS", "dynamic, pool")
        org = make_org(session)
        assert match(_source(session, org, reverse_dns="host-1-2-3-4.dynamic.example.net"))
        assert match(_source(session, org, ip="192.0.2.2", reverse_dns="5-6-7-8.POOL.example.net."))
        assert match(_source(session, org, ip="192.0.2.3", reverse_dns="carpool.example.net")) is None
        assert match(_source(session, org, ip="192.0.2.4", reverse_dns="mail.example.net")) is None

    def test_domain_pattern_matches_the_domain_and_below(self, session, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_RDNS_PATTERNS", "telecom.kz")
        org = make_org(session)
        assert match(_source(session, org, reverse_dns="x.telecom.kz"))
        assert match(_source(session, org, ip="192.0.2.2", reverse_dns="telecom.kz"))
        assert match(_source(session, org, ip="192.0.2.3", reverse_dns="x.nottelecom.kz")) is None

    def test_passed_messages_protect_a_source(self, session, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        org = make_org(session)
        good = _source(session, org, total=10, failed=9, asn="8193")
        assert match(good) is None
        monkeypatch.setattr(settings, "SOURCE_RULE_MAX_PASSED_MESSAGES", 1)
        assert match(good) is not None

    def test_switch_off(self, session, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        monkeypatch.setattr(settings, "SOURCE_RULES_ENABLED", False)
        assert match(_source(session, make_org(session), asn="8193")) is None


class TestApply:
    def test_classification_and_reason(self, session, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        source = _source(session, make_org(session), asn="8193")
        assert apply_rules(source) is True
        assert (source.classification, source.classification_source) == ("suspicious", "rule")
        assert "AS8193" in source.classification_reason
        assert source.classified_at is not None
        assert apply_rules(source) is False

    def test_other_classification_from_the_settings(self, session, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        monkeypatch.setattr(settings, "SOURCE_RULE_CLASSIFICATION", "ignored")
        source = _source(session, make_org(session), asn="8193")
        apply_rules(source)
        assert source.classification == "ignored"

    @pytest.mark.parametrize(("classification", "origin"), [("trusted", "manual"), ("suspicious", "manual"),
                                                            ("trusted", "sender"), ("ignored", None)])
    def test_decisions_come_first(self, session, monkeypatch, classification, origin):
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        source = _source(session, make_org(session), asn="8193", classification=classification,
                         classification_source=origin)
        assert apply_rules(source) is False
        assert (source.classification, source.classification_source) == (classification, origin)

    def test_rule_hands_back_when_it_no_longer_applies(self, session, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        source = _source(session, make_org(session), asn="8193")
        apply_rules(source)
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "")
        assert apply_rules(source) is True
        assert (source.classification, source.classification_source, source.classification_reason) == (
            "unknown", None, None)


class TestAllSources:
    def test_changed_settings_reach_known_sources_once(self, session, monkeypatch):
        org = make_org(session)
        first = _source(session, org, asn="8193")
        second = _source(session, org, ip="192.0.2.2", asn="15169")
        assert apply_rules_all(session) == 0
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        assert apply_rules_all(session) == 1
        assert (first.classification, second.classification) == ("suspicious", "unknown")
        first.classification, first.classification_source = "unknown", None
        assert apply_rules_all(session) == 0  # unchanged settings: no second pass
        assert apply_rules_all(session, force=True) == 1

    def test_refresh_applies_changed_rules_without_dns(self, session, dns, monkeypatch):
        org = make_org(session)
        source = _source(session, org, asn="8193")
        refresh_sources(session, NOW)
        assert source.classification == "unknown"
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        refresh_sources(session, NOW)
        assert source.classification == "suspicious"


class TestWithSenders:
    def test_new_source_is_classified_when_it_is_identified(self, session, dns, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        source = _source(session, make_org(session))
        dns["192.0.2.1"] = LookupResult("pool-5.example.uz", False, "8193", "BRM-AS - Uzbektelekom", "UZ")
        refresh_sources(session, NOW)
        assert (source.classification, source.classification_source) == ("suspicious", "rule")

    def test_decision_about_the_sender_beats_the_rule_and_reset_hands_back(self, session, dns, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_RDNS_PATTERNS", "amazonses.com")
        org = make_org(session)
        source = _source(session, org)
        dns["192.0.2.1"] = LookupResult("a1.smtp-out.amazonses.com", True)
        refresh_sources(session, NOW)
        assert source.classification_source == "rule"
        decide(session, org.id, "amazon-ses", "trusted", None)
        assert (source.classification, source.classification_source) == ("trusted", "sender")
        decide(session, org.id, "amazon-ses", "reset", None)
        assert (source.classification, source.classification_source) == ("suspicious", "rule")

    def test_person_beats_the_rule(self, session, dns, monkeypatch):
        monkeypatch.setattr(settings, "SOURCE_RULE_ASNS", "8193")
        source = _source(session, make_org(session), asn="8193")
        apply_rules(source)
        classify_manually(source, "trusted", None, session)
        assert (source.classification, source.classification_source) == ("trusted", "manual")
        refresh_sources(session, NOW, everything=True)
        assert source.classification == "trusted"
        classify_manually(source, "unknown", None, session)
        assert (source.classification, source.classification_source) == ("suspicious", "rule")


class TestAlerts:
    def test_ruled_source_raises_no_unknown_source_alert(self, session, dns, monkeypatch):
        monkeypatch.setattr(settings, "SCHEDULER_ENABLED", True)
        monkeypatch.setattr(settings, "SOURCE_RULE_COUNTRIES", "UZ")
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 2, False, False, False), ("192.0.2.2", 2, False, False, False)],
                   created_at=minutes_ago(5))
        add_source(session, org, "192.0.2.1", total=2, failed=2, first_seen=minutes_ago(5))
        add_source(session, org, "192.0.2.2", total=2, failed=2, first_seen=minutes_ago(5))
        make_rule(session, org, "new_unknown_source", cooldown=0)
        dns["192.0.2.1"] = LookupResult("a.example.uz", False, "8193", "BRM-AS", "UZ")
        dns["192.0.2.2"] = LookupResult("a.example.de", False, "3320", "DTAG", "DE")
        refresh_sources(session, NOW)
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert [e.source_ip for e in events] == ["192.0.2.2"]
        assert session.query(SourceIp).filter_by(ip_address="192.0.2.1").one().classification == "suspicious"


class TestSettingsChecks:
    @pytest.mark.parametrize(("name", "value", "reason"), [
        ("SOURCE_RULE_ASNS", "8193,Telekom", "'Telekom' ist keine AS-Nummer"),
        ("SOURCE_RULE_COUNTRIES", "KZ,Kasachstan", "'Kasachstan' ist kein Ländercode"),
        ("SOURCE_RULE_RDNS_PATTERNS", "dynamic,*.kz", "'*.kz' ist kein Hostnamen-Muster"),
        ("SOURCE_RULE_CLASSIFICATION", "trusted", "'trusted' gibt es nicht"),
        ("SOURCE_RULE_MAX_PASSED_MESSAGES", "-1", "muss mindestens 0 sein"),
    ])
    def test_invalid_values_are_explained(self, monkeypatch, name, value, reason):
        monkeypatch.setenv(name, value)
        with pytest.raises(SystemExit) as exc:
            load_settings()
        assert f"{name}:" in str(exc.value)
        assert reason in str(exc.value)

    def test_valid_values_load(self, monkeypatch):
        monkeypatch.setenv("SOURCE_RULE_ASNS", "8193, AS9198")
        monkeypatch.setenv("SOURCE_RULE_COUNTRIES", "kz")
        loaded = load_settings()
        assert loaded.source_rule_asns == {"8193", "9198"}
        assert loaded.source_rule_countries == {"KZ"}
