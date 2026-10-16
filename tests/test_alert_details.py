"""Details of alerts about failing mail: sources, causes, receivers, and the detail page."""
import json
from datetime import timedelta

import pytest

from app.config import settings
from app.models import AlertEvent, DmarcAuthResult, DmarcFailureReport, DmarcRecord, SourceIp
from app.services import alert_details
from app.services.alert_details import (
    FailedSource,
    build,
    categorize,
    causes_text,
    diagnose,
    provider_name,
    source_context,
    source_label,
    source_text,
    spf_snippet,
    summarize,
    window_minutes,
)
from app.services.alert_service import evaluate_rules_for_org, raise_event, refresh_event_texts
from tests.helpers import NOW, add_report, add_source, make_domain, make_org, make_rule, minutes_ago
from tests.test_web import _login, _seed


def _fail_event(db, org, domain, window=1440, **kwargs):
    return raise_event(db, org_id=org.id, alert_type="dmarc_fail_rate", severity="warning", title="Fehlerquote",
                       domain_id=domain.id, metrics={"window_minutes": window}, now=NOW, **kwargs)


def _setup(session):
    org = make_org(session)
    domain = make_domain(session, org, "piste.de")
    add_source(session, org, "198.51.100.1", total=10, failed=8, reverse_dns="mail.hoster.example")
    add_source(session, org, "198.51.100.2", total=3, failed=3)
    add_report(session, org, domain, [("198.51.100.1", 6, False, False, False), ("198.51.100.1", 2, True, True, True),
                                      ("198.51.100.2", 3, False, False, False)],
               created_at=minutes_ago(60), reporting_org="Google")
    add_report(session, org, domain, [("198.51.100.1", 2, False, True, False)], created_at=minutes_ago(30),
               reporting_org="Microsoft")
    return org, domain


class TestWindow:
    def test_stored_window_wins(self, session):
        org, domain = _setup(session)
        rule = make_rule(session, org, "dmarc_fail_rate", window=120)
        event = _fail_event(session, org, domain, window=600)
        assert window_minutes(event, rule) == 600

    def test_rule_or_one_day_without_stored_window(self, session):
        org, domain = _setup(session)
        rule = make_rule(session, org, "dmarc_fail_rate", window=120)
        event = raise_event(session, org_id=org.id, alert_type="dmarc_fail_rate", severity="info", title="x",
                            domain_id=domain.id, now=NOW)
        assert window_minutes(event, rule) == 120
        assert window_minutes(event, None) == 1440

    def test_broken_metrics_fall_back(self, session):
        org, domain = _setup(session)
        event = _fail_event(session, org, domain)
        event.metrics = "kein json"
        assert window_minutes(event, None) == 1440


class TestBuild:
    def test_failing_sources_with_numbers(self, session):
        org, domain = _setup(session)
        result = build(session, _fail_event(session, org, domain))
        assert [s.ip for s in result.sources] == ["198.51.100.1", "198.51.100.2"]
        first = result.sources[0]
        assert (first.failed, first.total) == (8, 10)
        assert first.reporters == ["Google", "Microsoft"]
        assert (result.failed, result.total) == (11, 13)

    def test_reporters_are_the_receiving_providers(self, session):
        org, domain = _setup(session)
        shares = {r.name: (r.failed, r.total) for r in build(session, _fail_event(session, org, domain)).reporters}
        assert shares == {"Google": (9, 11), "Microsoft": (2, 2)}

    def test_window_limits_the_reports(self, session):
        org, domain = _setup(session)
        result = build(session, _fail_event(session, org, domain, window=45))
        assert [s.ip for s in result.sources] == ["198.51.100.1"]
        assert result.sources[0].failed == 2

    def test_other_domain_and_other_organisation_stay_out(self, session):
        org, domain = _setup(session)
        other_domain = make_domain(session, org, "andere.example")
        add_report(session, org, other_domain, [("203.0.113.5", 9, False, False, False)], created_at=minutes_ago(10))
        stranger = make_org(session, "Fremd", "fremd")
        foreign = make_domain(session, stranger, "piste.de")
        add_report(session, stranger, foreign, [("203.0.113.6", 9, False, False, False)], created_at=minutes_ago(10))
        ips = {s.ip for s in build(session, _fail_event(session, org, domain)).sources}
        assert ips == {"198.51.100.1", "198.51.100.2"}

    def test_auth_results_name_domains_and_selectors(self, session):
        org, domain = _setup(session)
        record = session.query(DmarcRecord).filter_by(source_ip="198.51.100.2").one()
        record.spf_result, record.dkim_result = "fail", "none"
        record.header_from, record.envelope_from = "piste.de", "bounce.hoster.example"
        session.add_all([
            DmarcAuthResult(record_id=record.id, auth_type="spf", domain="bounce.hoster.example", result="fail"),
            DmarcAuthResult(record_id=record.id, auth_type="dkim", domain="hoster.example", selector="s1",
                            result="pass"),
        ])
        session.flush()
        item = [s for s in build(session, _fail_event(session, org, domain)).sources if s.ip == "198.51.100.2"][0]
        assert item.spf == "fail" and item.dkim == "none"
        assert item.header_from == ["piste.de"] and item.envelope_from == ["bounce.hoster.example"]
        assert item.spf_domains == ["bounce.hoster.example (fehlgeschlagen)"]
        assert item.dkim_checks == ["hoster.example · s1 (bestanden)"]

    def test_limit_from_the_settings(self, session, monkeypatch):
        monkeypatch.setattr(settings, "UI_ALERT_DETAIL_SOURCES", 5)
        org = make_org(session)
        domain = make_domain(session, org, "piste.de")
        rows = [(f"198.51.100.{n}", n, False, False, False) for n in range(1, 9)]
        add_report(session, org, domain, rows, created_at=minutes_ago(5))
        result = build(session, _fail_event(session, org, domain))
        assert len(result.sources) == 5 and result.more_sources == 3
        assert result.sources[0].ip == "198.51.100.8"

    def test_other_alert_types_have_no_breakdown(self, session):
        org, domain = _setup(session)
        event = raise_event(session, org_id=org.id, alert_type="reports_missing", severity="info", title="x",
                            domain_id=domain.id, now=NOW)
        assert build(session, event) is None

    def test_single_source_alert_looks_at_its_address(self, session):
        org, domain = _setup(session)
        event = raise_event(session, org_id=org.id, alert_type="new_source_dmarc_fail", severity="warning",
                            title="x", domain_id=domain.id, source_ip="198.51.100.2", now=NOW,
                            metrics={"window_minutes": 1440})
        assert [s.ip for s in build(session, event).sources] == ["198.51.100.2"]

    def test_failure_reports_are_counted(self, session):
        org, domain = _setup(session)
        session.add(DmarcFailureReport(organization_id=org.id, domain_id=domain.id, import_source="web_upload",
                                       incidents=1, created_at=minutes_ago(20)))
        session.flush()
        assert build(session, _fail_event(session, org, domain)).failure_reports == 1


class TestDiagnose:
    def _item(self, **fields):
        item = FailedSource(ip="198.51.100.1", header_from=["piste.de"], failed=1, total=1)
        for key, value in fields.items():
            setattr(item, key, value)
        return item

    def test_unknown_source_that_never_passed_is_spoofing(self, session):
        org = make_org(session)
        source = add_source(session, org, "198.51.100.9", total=2, failed=2)
        assert "Spoofing" in diagnose(self._item(source=source))

    def test_known_service_needs_setup(self):
        text = diagnose(self._item(sender_name="Mailchimp und Mandrill"))
        assert "Mailchimp und Mandrill" in text and "DKIM für piste.de" in text

    def test_own_unknown_address_gets_both_options(self):
        assert "SPF-Eintrag" in diagnose(self._item())

    def test_spf_passing_for_another_domain(self):
        text = diagnose(self._item(spf="pass", spf_domains=["bounce.example (bestanden)"], dkim_aligned=True))
        assert "andere Domain" in text and "bounce.example" in text

    def test_spf_failing_but_dkim_carries(self):
        assert "nicht im SPF-Eintrag" in diagnose(self._item(spf="fail", dkim_aligned=True))

    def test_missing_dkim_signature(self):
        assert "keine DKIM-Signatur" in diagnose(self._item(dkim="none", spf_aligned=True))

    def test_invalid_dkim_signature_names_the_selector(self):
        text = diagnose(self._item(dkim="fail", dkim_checks=["piste.de · s1 (fehlgeschlagen)"], spf_aligned=True))
        assert "s1" in text and "ungültig" in text

    def test_result_text_is_german(self):
        assert alert_details.result_text("softfail") == "weich fehlgeschlagen"
        assert alert_details.result_text(None) == "unbekannt"
        assert alert_details.result_text("eigenartig") == "eigenartig"


class TestAlertText:
    def _run(self, session):
        org, domain = _setup(session)
        make_rule(session, org, "dmarc_fail_rate", threshold=10, window=1440, cooldown=0)
        return evaluate_rules_for_org(session, org.id, NOW)

    def test_description_names_the_sources_and_the_page(self, session):
        event = self._run(session)[0]
        assert "Häufigste Quellen: 198.51.100.1 (mail.hoster.example): 8, 198.51.100.2: 3." in event.description
        assert "Detailseite des Alarms" in event.description
        assert json.loads(event.metrics)["window_minutes"] == 1440

    def test_number_of_named_sources_comes_from_the_settings(self, session, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_DESCRIPTION_SOURCES", 1)
        assert "und 1 weitere" in self._run(session)[0].description

    def test_sentence_can_be_switched_off(self, session, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_DESCRIPTION_SOURCES", 0)
        event = self._run(session)[0]
        assert "Häufigste Quellen" not in event.description and "Detailseite" in event.description


class TestPages:
    @pytest.fixture
    def seeded(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        from app.models import Domain, Organization
        org = db.get(Organization, ids["org"])
        domain = db.query(Domain).filter_by(organization_id=org.id).first()
        source = add_source(db, org, "198.51.100.1", total=10, failed=8, reverse_dns="mail.hoster.example")
        add_report(db, org, domain, [("198.51.100.1", 8, False, False, False)], created_at=NOW - timedelta(minutes=5),
                   reporting_org="Google")
        event = raise_event(db, org_id=org.id, alert_type="dmarc_fail_rate", severity="warning",
                            title="80 % scheitern an DMARC", description="Beschreibung des Alarms.",
                            domain_id=domain.id, metrics={"window_minutes": 1440}, now=NOW)
        stranger = make_org(db, "Fremd", "fremd")
        foreign = raise_event(db, org_id=stranger.id, alert_type="reports_missing", severity="info", title="Fremd",
                              now=NOW)
        db.commit()
        out = {"event": event.id, "foreign": foreign.id, "source": source.id, "org": ids["org"],
               "domain": domain.id, "name": domain.name}
        db.close()
        _login(web, ids["org"])
        return out

    def test_detail_page_answers_who_what_and_how_to_fix(self, web, seeded):
        page = web.get(f"/alerts/events/{seeded['event']}")
        assert page.status_code == 200
        assert "Was du tun kannst" in page.text and "Quelle ohne passendes SPF oder DKIM" in page.text
        assert f'href="/source-ips/{seeded["source"]}"' in page.text
        assert "mail.hoster.example" in page.text and "Google" in page.text
        assert "SPF-Eintrag: <code>ip4:198.51.100.1</code>" in page.text
        assert "keine einzelnen Empfänger" in page.text
        assert page.text.count("Beschreibung des Alarms.") == 1  # once as the notification text, not in the overview

    def test_breadcrumb_names_the_alert_and_actions_return_to_it(self, web, seeded):
        page = web.get(f"/alerts/events/{seeded['event']}").text
        assert 'aria-current="page">Fehlerquote' in page or 'aria-current="page">DMARC-Fehlerquote' in page
        assert f'name="next" value="/alerts/events/{seeded["event"]}"' in page

    def test_detail_page_of_another_organisation_is_not_found(self, web, seeded):
        assert web.get(f"/alerts/events/{seeded['foreign']}").status_code == 404
        assert web.get("/alerts/events/gibt-es-nicht").status_code == 404

    def test_other_alert_types_show_their_values(self, web, seeded, session_factory):
        db = session_factory()
        event = db.query(AlertEvent).filter_by(id=seeded["event"]).one()
        event.alert_type, event.metrics = "reports_missing", json.dumps({"window_minutes": 2880})
        db.commit()
        db.close()
        page = web.get(f"/alerts/events/{seeded['event']}")
        assert page.status_code == 200 and "2880" in page.text and "Wer hat die Mails verschickt?" not in page.text

    def test_list_links_to_the_detail_page(self, web, seeded):
        assert f'href="/alerts/events/{seeded["event"]}"' in web.get("/alerts/events").text


    def test_mail_link_points_to_the_event(self, session):
        from app.services.notification import event_url
        org = make_org(session)
        event = raise_event(session, org_id=org.id, alert_type="reports_missing", severity="info", title="x", now=NOW)
        assert event_url(event).endswith(f"/alerts/events/{event.id}")


class TestCauses:
    def test_causes_are_grouped_with_their_numbers(self, session):
        org, domain = _setup(session)
        causes = build(session, _fail_event(session, org, domain)).causes
        assert sorted((c.key, c.messages, c.sources) for c in causes) == [("spoof", 3, 1), ("unknown", 8, 1)]
        assert all(c.advice for c in causes)

    def test_text_names_the_causes(self, session):
        org, domain = _setup(session)
        text = causes_text(build(session, _fail_event(session, org, domain)).causes)
        assert text.startswith("Ursachen: ") and "Nachrichten von 1 Quelle" in text

    def test_known_service_and_passing_source(self):
        item = FailedSource(ip="198.51.100.1", failed=2, total=2, sender_name="Mailchimp und Mandrill")
        assert categorize(item) == "service"
        assert categorize(FailedSource(ip="198.51.100.1", failed=0, total=4)) == "passing"
        assert summarize([item])[0].examples == ["Mailchimp und Mandrill"]

    def test_concrete_spf_entry_for_both_address_families(self):
        assert spf_snippet("198.51.100.1") == "ip4:198.51.100.1"
        assert spf_snippet("2001:db8::1") == "ip6:2001:db8::1"
        item = FailedSource(ip="198.51.100.1", failed=1, total=1, header_from=["piste.de"])
        assert "ip4:198.51.100.1" in diagnose(item)

    def test_alert_text_carries_the_causes_and_metrics(self, session):
        org, domain = _setup(session)
        make_rule(session, org, "dmarc_fail_rate", threshold=10, window=1440, cooldown=0)
        event = evaluate_rules_for_org(session, org.id, NOW)[0]
        assert "Ursachen: " in event.description
        assert {c["key"] for c in json.loads(event.metrics)["causes"]} == {"spoof", "unknown"}


class TestSourceAlerts:
    def _alert(self, session, rule_type="new_unknown_source", **kwargs):
        org = make_org(session)
        first, second = make_domain(session, org, "crust-y.com"), make_domain(session, org, "hsp-events.de")
        source = add_source(session, org, "109.187.92.220", total=3, failed=3, first_seen=minutes_ago(5),
                            reverse_dns="host.dyn.example.ru")
        source.asn, source.asn_org, source.country_code = "12389", "Rostelecom", "RU"
        add_report(session, org, first, [("109.187.92.220", 2, False, False, False)], created_at=minutes_ago(5),
                   reporting_org="Google")
        add_report(session, org, second, [("109.187.92.220", 1, False, False, False)], created_at=minutes_ago(5),
                   reporting_org="Microsoft")
        make_rule(session, org, rule_type, cooldown=0, **kwargs)
        return org, evaluate_rules_for_org(session, org.id, NOW)[0]

    def test_title_names_the_domains(self, session):
        _, event = self._alert(session)
        assert event.title == (
            "Neue unbekannte Quelle 109.187.92.220 (host.dyn.example.ru, Rostelecom) für crust-y.com, hsp-events.de")

    def test_text_gives_context(self, session):
        _, event = self._alert(session)
        for part in ("Sie verschickt Mails für crust-y.com (2), hsp-events.de (1).",
                     "SPF passt bei 0 von 3 Nachrichten", "Hostname host.dyn.example.ru",
                     "Netz AS12389 (Rostelecom)", "Land RU",
                     "Angenommen von: Google, Microsoft.", "Detailseite des Alarms"):
            assert part in event.description

    def test_many_domains_are_counted(self, session, monkeypatch):
        org = make_org(session)
        source = add_source(session, org, "109.187.92.220", total=9, failed=9, first_seen=minutes_ago(5))
        for n in range(4):
            domain = make_domain(session, org, f"kunde{n}.example")
            add_report(session, org, domain, [("109.187.92.220", n + 1, False, False, False)],
                       created_at=minutes_ago(5))
        make_rule(session, org, "new_unknown_source", cooldown=0)
        event = evaluate_rules_for_org(session, org.id, NOW)[0]
        assert event.title.endswith("für kunde3.example, kunde2.example und 2 weitere")
        monkeypatch.setattr(settings, "ALERT_DESCRIPTION_DOMAINS", 1)
        context = source_context(session, org.id, source.ip_address)
        assert context.domains_text() == "kunde3.example (4) und 3 weitere"
        monkeypatch.setattr(settings, "ALERT_DESCRIPTION_DOMAINS", 0)
        assert "Sie verschickt Mails für" not in source_text(session, org.id, source)

    @pytest.mark.parametrize("rule_type", ["high_volume_source", "new_source_dmarc_fail"])
    def test_other_source_alerts_name_the_domains_too(self, session, rule_type):
        _, event = self._alert(session, rule_type, threshold=1)
        assert "crust-y.com" in event.title and "Sie verschickt Mails für crust-y.com" in event.description

    def test_detail_page_explains_the_source(self, session):
        org, event = self._alert(session)
        result = build(session, event, None)
        assert [s.ip for s in result.sources] == ["109.187.92.220"]
        assert result.causes[0].key == "spoof"


class TestSourceLabel:
    def test_provider_name_drops_the_registry_label(self):
        assert provider_name("UZMOBILE-AS - _Uzbektelekom_ Joint Stock Company") == "Uzbektelekom Joint Stock Company"
        assert provider_name("OVH") == "OVH"
        assert provider_name(None) == "" and provider_name("") == ""

    def test_label_is_host_name_and_provider(self, session):
        org = make_org(session)
        source = add_source(session, org, "198.51.100.1", total=1, reverse_dns="mail.hoster.example")
        source.asn_org = "HETZNER-AS - Hetzner Online GmbH"
        assert source_label(source) == "mail.hoster.example, Hetzner Online GmbH"

    def test_known_service_replaces_the_host_name(self, session):
        org = make_org(session)
        source = add_source(session, org, "198.51.100.1", total=1, reverse_dns="mail1.us4.mcsv.net")
        source.sender_key, source.asn_org = "mailchimp", "THE-RISE-TECH - The Rocket Science Group"
        assert source_label(source) == "Mailchimp und Mandrill, The Rocket Science Group"

    def test_provider_is_not_repeated_in_the_name(self, session):
        org = make_org(session)
        source = add_source(session, org, "198.51.100.1", total=1, reverse_dns="mail.hetzner.example")
        source.asn_org = "HETZNER-AS - Hetzner"
        assert source_label(source) == "mail.hetzner.example"

    def test_name_contained_in_the_provider_is_not_repeated(self, session):
        org = make_org(session)
        source = add_source(session, org, "198.51.100.1", total=1)
        source.sender_key, source.asn_org = "google", "GOOGLE - Google LLC"
        assert source_label(source) == "Google"

    def test_label_of_nothing_is_empty(self, session):
        assert source_label(None) == ""
        source = add_source(session, make_org(session), "198.51.100.1", total=1)
        assert source_label(source) == ""

    def test_text_names_the_network_by_its_operator(self, session):
        org = make_org(session)
        source = add_source(session, org, "198.51.100.1", total=1)
        source.asn, source.asn_org = "28812", "JSCBIS-AS - PJSC _Bashinformsvyaz_"
        assert "Netz AS28812 (PJSC Bashinformsvyaz)" in source_text(session, org.id, source)

    def test_text_says_when_the_address_has_no_host_name(self, session):
        org = make_org(session)
        source = add_source(session, org, "198.51.100.1", total=1)
        source.enriched_at = NOW
        assert "kein Hostname (rDNS) eingetragen" in source_text(session, org.id, source)
        source.enriched_at = None
        assert "rDNS" not in source_text(session, org.id, source)

    def test_fail_rate_text_names_host_and_provider(self, session):
        org, domain = _setup(session)
        source = session.query(SourceIp).filter_by(ip_address="198.51.100.1").one()
        source.asn_org = "HETZNER-AS - Hetzner Online GmbH"
        make_rule(session, org, "dmarc_fail_rate", threshold=10, window=1440, cooldown=0)
        event = evaluate_rules_for_org(session, org.id, NOW)[0]
        assert "198.51.100.1 (mail.hoster.example, Hetzner Online GmbH): 8" in event.description


class TestRefreshTexts:
    OLD = ("102.244.98.191 verschickt Mails für deine Domains und ist noch nicht eingestuft. Bisher 1 Nachrichten, "
           "davon 0 % bestanden. Stufe sie unter „Quellen“ ein.")

    def _old_alert(self, session, status="open"):
        org = make_org(session)
        domain = make_domain(session, org, "crust-y.com")
        source = add_source(session, org, "102.244.98.191", total=1, failed=1, reverse_dns="host.example.za")
        source.asn_org, source.country_code = "AS37 - Beispiel Telecom", "ZA"
        add_report(session, org, domain, [("102.244.98.191", 1, False, False, False)], created_at=minutes_ago(5),
                   reporting_org="Google")
        event = raise_event(session, org_id=org.id, alert_type="new_unknown_source", severity="warning",
                            title="Neue unbekannte Quelle 102.244.98.191", description=self.OLD, domain_id=None,
                            source_ip="102.244.98.191", now=NOW)
        event.status = status
        return org, event

    def test_open_alert_gets_domains_host_and_provider(self, session):
        _, event = self._old_alert(session)
        assert refresh_event_texts(session) == 1
        assert event.title == (
            "Neue unbekannte Quelle 102.244.98.191 (host.example.za, Beispiel Telecom) für crust-y.com")
        for part in ("Sie verschickt Mails für crust-y.com (1).", "Hostname host.example.za", "Land ZA",
                     "Angenommen von: Google."):
            assert part in event.description

    def test_second_run_changes_nothing(self, session):
        self._old_alert(session)
        refresh_event_texts(session)
        assert refresh_event_texts(session) == 0

    def test_resolved_alerts_keep_their_text(self, session):
        _, event = self._old_alert(session, status="resolved")
        assert refresh_event_texts(session) == 0
        assert event.description == self.OLD

    def test_only_the_given_organisation(self, session):
        org, event = self._old_alert(session)
        other = make_org(session, "Fremd", "fremd")
        assert refresh_event_texts(session, other.id) == 0 and event.description == self.OLD
        assert refresh_event_texts(session, org.id) == 1

    def test_old_fail_rate_text_gets_the_causes(self, session):
        org, domain = _setup(session)
        rule = make_rule(session, org, "dmarc_fail_rate", threshold=10, window=1440, cooldown=0)
        event = raise_event(
            session, org_id=org.id, alert_type="dmarc_fail_rate", severity="warning", title="x", rule=rule,
            domain_id=domain.id, now=NOW,
            description="11 von 13 Nachrichten der letzten 24 Stunden bestehen DMARC nicht (Schwelle 10 %). "
                        "Prüfe die fehlschlagenden Quellen.")
        assert refresh_event_texts(session) == 1
        assert event.description.startswith("11 von 13 Nachrichten der letzten 24 Stunden bestehen DMARC nicht "
                                            "(Schwelle 10 %). Ursachen: ")
        assert "Prüfe die fehlschlagenden Quellen" not in event.description
        assert refresh_event_texts(session) == 0

    def test_setting_can_switch_the_start_run_off(self, monkeypatch):
        from app import main
        from app.services import alert_service

        calls = []
        monkeypatch.setattr(alert_service, "refresh_event_texts", lambda db: calls.append(db) or 0)
        monkeypatch.setattr(settings, "ALERT_REFRESH_TEXTS_ON_START", False)
        main._refresh_alert_texts()
        assert calls == []
        monkeypatch.setattr(settings, "ALERT_REFRESH_TEXTS_ON_START", True)
        main._refresh_alert_texts()
        assert len(calls) == 1


class TestTrustedAndStates:
    def test_trusted_source_is_not_called_abuse(self, session):
        org = make_org(session)
        source = add_source(session, org, "198.51.100.1", total=2, failed=2, classification="trusted")
        item = FailedSource(ip="198.51.100.1", failed=2, total=2, header_from=["piste.de"], source=source)
        assert categorize(item) == "trusted"
        text = diagnose(item)
        assert "freigegebene Quelle" in text and "Missbrauch" not in text and "ip4:198.51.100.1" in text

    def test_auth_state_words(self):
        from app.services.alert_details import auth_state

        assert auth_state("pass", True) == ("passt", True)
        assert auth_state("pass", False) == ("andere Domain", False)
        assert auth_state("none", False) == ("fehlt", False)
        assert auth_state("", False) == ("fehlt", False)
        assert auth_state("fail", False) == ("fehlgeschlagen", False)

    def test_sources_are_grouped_by_cause(self, session):
        org, domain = _setup(session)
        groups = build(session, _fail_event(session, org, domain)).groups
        assert [(c.key, [s.ip for s in members]) for c, members in groups] == [
            ("unknown", ["198.51.100.1"]), ("spoof", ["198.51.100.2"])] or sorted(
            (c.key, tuple(s.ip for s in members)) for c, members in groups) == [
            ("spoof", ("198.51.100.2",)), ("unknown", ("198.51.100.1",))]


class TestRefreshKeepsCauses:
    def test_causes_reach_the_metrics_of_alerts_that_already_name_them(self, session):
        org, domain = _setup(session)
        rule = make_rule(session, org, "dmarc_fail_rate", threshold=10, window=1440, cooldown=0)
        event = raise_event(
            session, org_id=org.id, alert_type="dmarc_fail_rate", severity="warning", title="x", rule=rule,
            domain_id=domain.id, now=NOW, metrics={"window_minutes": 1440},
            description="11 von 13 Nachrichten der letzten 24 Stunden bestehen DMARC nicht (Schwelle 10 %). "
                        "Ursachen: Alter Text.")
        assert refresh_event_texts(session) == 1
        assert {c["key"] for c in json.loads(event.metrics)["causes"]} == {"spoof", "unknown"}
        assert "Alter Text" not in event.description
        assert refresh_event_texts(session) == 0
