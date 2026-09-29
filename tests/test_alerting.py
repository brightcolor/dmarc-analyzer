"""Alert rules, events, notification queue and delivery over every channel type."""
import json
from datetime import timedelta

import httpx
import pytest

from app.config import settings
from app.models import AlertEvent, ImportJob, NotificationDelivery, SmtpInboundRejection
from app.services import alert_service, notification
from app.services.alert_service import (
    ALERT_TYPES,
    EVALUATORS,
    create_system_alert,
    evaluate_rules_for_org,
)
from app.services.notification import (
    ChannelError,
    build_channel_config,
    channel_summary,
    dispatch_pending,
)
from tests.helpers import (
    NOW,
    add_report,
    add_source,
    aware,
    make_channel,
    make_domain,
    make_org,
    make_rule,
    minutes_ago,
)


def _events(db, org):
    return db.query(AlertEvent).filter_by(organization_id=org.id).order_by(AlertEvent.created_at).all()


class TestRegistry:
    def test_every_type_has_an_evaluator_and_a_hint(self):
        assert set(EVALUATORS) == set(ALERT_TYPES)
        assert set(alert_service.alert_type_hints()) == set(ALERT_TYPES)


class TestRates:
    def test_fail_rate_above_threshold_fires(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 70, True, True, True), ("192.0.2.2", 30, False, False, False)],
                   created_at=minutes_ago(10))
        make_rule(session, org, "dmarc_fail_rate", threshold=25)
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert len(events) == 1
        assert events[0].title == "30 % scheitern an DMARC für example.org"
        assert events[0].domain_id == domain.id
        assert "30 von 100 Nachrichten" in events[0].description
        assert json.loads(events[0].metrics)["failed"] == 30

    def test_fail_rate_below_threshold_stays_quiet(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 95, True, True, True), ("192.0.2.2", 5, False, False, False)],
                   created_at=minutes_ago(10))
        make_rule(session, org, "dmarc_fail_rate", threshold=25)
        assert evaluate_rules_for_org(session, org.id, NOW) == []

    def test_default_threshold_comes_from_the_settings(self, session, monkeypatch):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 96, True, True, True), ("192.0.2.2", 4, False, False, False)],
                   created_at=minutes_ago(10))
        make_rule(session, org, "dmarc_fail_rate")
        assert evaluate_rules_for_org(session, org.id, NOW) == []  # 4 % < 10 %
        monkeypatch.setattr(settings, "ALERT_DEFAULT_FAIL_RATE", 3.0)
        assert len(evaluate_rules_for_org(session, org.id, NOW)) == 1

    def test_reports_outside_the_window_do_not_count(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.2", 50, False, False, False)], created_at=minutes_ago(120))
        make_rule(session, org, "dmarc_fail_rate", threshold=10, window=60)
        assert evaluate_rules_for_org(session, org.id, NOW) == []

    def test_min_message_count_is_respected(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.2", 3, False, False, False)], created_at=minutes_ago(5))
        make_rule(session, org, "dmarc_fail_rate", threshold=10, min_messages=10)
        assert evaluate_rules_for_org(session, org.id, NOW) == []

    def test_domain_rule_only_sees_its_domain(self, session):
        org = make_org(session)
        watched = make_domain(session, org, "example.org")
        other = make_domain(session, org, "example.net")
        add_report(session, org, other, [("192.0.2.2", 50, False, False, False)], created_at=minutes_ago(5))
        add_report(session, org, watched, [("192.0.2.1", 50, True, True, True)], created_at=minutes_ago(5))
        make_rule(session, org, "dmarc_fail_rate", threshold=10, domain=watched)
        assert evaluate_rules_for_org(session, org.id, NOW) == []

    @pytest.mark.parametrize(("alert_type", "label"), [("spf_fail_rate", "SPF"), ("dkim_fail_rate", "DKIM")])
    def test_spf_and_dkim_rates(self, session, alert_type, label):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 60, True, True, True), ("192.0.2.2", 40, True, False, False)],
                   created_at=minutes_ago(5))
        make_rule(session, org, alert_type, threshold=30)
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert [e.title for e in events] == [f"40 % ohne passendes {label} für example.org"]


class TestVolume:
    def _history(self, session, org, domain, per_window: int, windows: int = 7):
        for index in range(1, windows + 1):
            add_report(session, org, domain, [("192.0.2.1", per_window, True, True, True)],
                       created_at=NOW - timedelta(minutes=60 * index + 30))

    def test_spike(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        self._history(session, org, domain, 100)
        add_report(session, org, domain, [("192.0.2.1", 400, True, True, True)], created_at=minutes_ago(10))
        make_rule(session, org, "volume_spike", threshold=200)
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert len(events) == 1
        assert json.loads(events[0].metrics) == {"current": 400, "baseline": 100.0, "threshold": 200}

    def test_no_spike_without_history(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 400, True, True, True)], created_at=minutes_ago(10))
        make_rule(session, org, "volume_spike")
        assert evaluate_rules_for_org(session, org.id, NOW) == []

    def test_drop(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        self._history(session, org, domain, 100)
        add_report(session, org, domain, [("192.0.2.1", 10, True, True, True)], created_at=minutes_ago(10))
        make_rule(session, org, "volume_drop", threshold=80)
        assert len(evaluate_rules_for_org(session, org.id, NOW)) == 1

    def test_small_drop_stays_quiet(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        self._history(session, org, domain, 100)
        add_report(session, org, domain, [("192.0.2.1", 60, True, True, True)], created_at=minutes_ago(10))
        make_rule(session, org, "volume_drop", threshold=80)
        assert evaluate_rules_for_org(session, org.id, NOW) == []

    def test_baseline_windows_come_from_the_settings(self, session, monkeypatch):
        org = make_org(session)
        domain = make_domain(session, org)
        # Only the window right before counts with one baseline window: 400 → 400 is no spike
        add_report(session, org, domain, [("192.0.2.1", 400, True, True, True)], created_at=NOW - timedelta(minutes=90))
        add_report(session, org, domain, [("192.0.2.1", 10, True, True, True)], created_at=NOW - timedelta(minutes=150))
        add_report(session, org, domain, [("192.0.2.1", 400, True, True, True)], created_at=minutes_ago(10))
        make_rule(session, org, "volume_spike", threshold=100)
        assert len(evaluate_rules_for_org(session, org.id, NOW)) == 1  # average of 7 windows is low
        session.query(AlertEvent).delete()
        rule = session.query(alert_service.AlertRule).one()
        rule.next_allowed_at = None
        monkeypatch.setattr(settings, "ALERT_VOLUME_BASELINE_WINDOWS", 1)
        assert evaluate_rules_for_org(session, org.id, NOW) == []


class TestReportsMissing:
    def test_fires_without_reports(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)], created_at=NOW - timedelta(days=3))
        make_rule(session, org, "reports_missing", window=2880)
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert [e.title for e in events] == ["Seit 2 Tagen keine Berichte für example.org"]

    def test_quiet_with_a_recent_report(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)], created_at=NOW - timedelta(hours=5))
        make_rule(session, org, "reports_missing", window=2880)
        assert evaluate_rules_for_org(session, org.id, NOW) == []


def _sent_for(session, org, *ips, name="example.org"):
    """The sources sent for one domain in the window; a rule for all domains checks each domain."""
    domain = make_domain(session, org, name)
    add_report(session, org, domain, [(ip, 1, True, True, True) for ip in ips], created_at=minutes_ago(5))
    return domain


class TestSources:
    def test_new_unknown_source_once_per_ip(self, session):
        org = make_org(session)
        _sent_for(session, org, "198.51.100.7", "198.51.100.8", "198.51.100.9")
        add_source(session, org, "198.51.100.7", total=12, failed=12, first_seen=minutes_ago(5))
        add_source(session, org, "198.51.100.8", total=5, first_seen=minutes_ago(5), classification="trusted")
        add_source(session, org, "198.51.100.9", total=5, first_seen=NOW - timedelta(days=5))
        make_rule(session, org, "new_unknown_source")
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert [e.source_ip for e in events] == ["198.51.100.7"]
        assert "noch nicht eingestuft" in events[0].description

    def test_high_volume_source_uses_threshold(self, session, monkeypatch):
        org = make_org(session)
        _sent_for(session, org, "198.51.100.7")
        add_source(session, org, "198.51.100.7", total=300, first_seen=minutes_ago(5))
        make_rule(session, org, "high_volume_source")
        assert evaluate_rules_for_org(session, org.id, NOW) == []  # default 500
        monkeypatch.setattr(settings, "ALERT_DEFAULT_HIGH_VOLUME", 250)
        assert [e.source_ip for e in evaluate_rules_for_org(session, org.id, NOW)] == ["198.51.100.7"]

    def test_new_source_with_failures(self, session):
        org = make_org(session)
        _sent_for(session, org, "198.51.100.7", "198.51.100.8")
        add_source(session, org, "198.51.100.7", total=10, failed=4, first_seen=minutes_ago(5))
        add_source(session, org, "198.51.100.8", total=10, failed=0, first_seen=minutes_ago(5))
        make_rule(session, org, "new_source_dmarc_fail")
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert [e.source_ip for e in events] == ["198.51.100.7"]


class TestImportAndPolicy:
    def test_failed_imports(self, session):
        org = make_org(session)
        for _ in range(2):
            session.add(ImportJob(organization_id=org.id, status="failed", created_at=minutes_ago(5)))
        session.flush()
        make_rule(session, org, "import_failed", threshold=2)
        assert [e.title for e in evaluate_rules_for_org(session, org.id, NOW)] == ["2 Importe fehlgeschlagen"]

    def test_policy_tighten_ready(self, session, monkeypatch):
        from app.security import utcnow

        monkeypatch.setattr(settings, "RECOMMENDATION_MIN_MESSAGES", 10)
        org = make_org(session)
        domain = make_domain(session, org, policy="none")
        now = utcnow()
        add_report(session, org, domain, [("192.0.2.1", 200, True, True, True)], created_at=now - timedelta(hours=1))
        make_rule(session, org, "policy_tighten_ready")
        events = evaluate_rules_for_org(session, org.id, now)
        assert [e.title for e in events] == ["example.org ist bereit für p=quarantine"]


class TestSmtpRules:
    def test_invalid_recipients_and_rate_limit(self, session):
        org = make_org(session)
        for code in ("550", "550", "421"):
            session.add(SmtpInboundRejection(remote_ip="203.0.113.9", attempted_recipient="x@reports.example.test",
                                             rejection_code=code, rejection_reason="Test", created_at=minutes_ago(5)))
        session.flush()
        make_rule(session, org, "smtp_invalid_recipient", threshold=2)
        make_rule(session, org, "smtp_rate_limit", threshold=1)
        titles = sorted(e.title for e in evaluate_rules_for_org(session, org.id, NOW))
        assert titles == ["1-mal Grenze für eingehende Mails erreicht", "2 Mails an unbekannte Adressen abgelehnt"]


class TestRulesForAllDomains:
    def test_each_domain_gets_its_own_event(self, session):
        org = make_org(session)
        failing = make_domain(session, org, "example.org")
        fine = make_domain(session, org, "example.net")
        also_failing = make_domain(session, org, "example.com")
        add_report(session, org, failing, [("192.0.2.2", 40, False, False, False)], created_at=minutes_ago(5))
        add_report(session, org, fine, [("192.0.2.1", 400, True, True, True)], created_at=minutes_ago(5))
        add_report(session, org, also_failing, [("192.0.2.3", 30, False, False, False)], created_at=minutes_ago(5))
        make_rule(session, org, "dmarc_fail_rate", threshold=10)
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert sorted(e.title for e in events) == ["100 % scheitern an DMARC für example.com",
                                                   "100 % scheitern an DMARC für example.org"]

    def test_pause_counts_per_domain(self, session):
        org = make_org(session)
        first = make_domain(session, org, "example.org")
        second = make_domain(session, org, "example.net")
        add_report(session, org, first, [("192.0.2.2", 40, False, False, False)], created_at=minutes_ago(5))
        make_rule(session, org, "dmarc_fail_rate", threshold=10, cooldown=600, window=240)
        assert len(evaluate_rules_for_org(session, org.id, NOW)) == 1
        # The second domain starts failing later; the pause of the first one does not hold it back
        add_report(session, org, second, [("192.0.2.3", 40, False, False, False)], created_at=NOW + timedelta(minutes=5))
        later = evaluate_rules_for_org(session, org.id, NOW + timedelta(minutes=10))
        assert [e.domain_id for e in later] == [second.id]

    def test_domains_without_any_report_stay_quiet(self, session):
        org = make_org(session)
        reporting = make_domain(session, org, "example.org")
        make_domain(session, org, "geparkt.example")
        add_report(session, org, reporting, [("192.0.2.1", 5, True, True, True)], created_at=NOW - timedelta(days=3))
        make_rule(session, org, "reports_missing", window=2880)
        assert [e.domain_id for e in evaluate_rules_for_org(session, org.id, NOW)] == [reporting.id]

    def test_inactive_domains_are_left_out(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.2", 40, False, False, False)], created_at=minutes_ago(5))
        domain.is_active = False
        make_rule(session, org, "dmarc_fail_rate", threshold=10)
        assert evaluate_rules_for_org(session, org.id, NOW) == []

    def test_domain_rule_reports_never_seen_domains(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        make_rule(session, org, "reports_missing", window=2880, domain=domain)
        assert [e.domain_id for e in evaluate_rules_for_org(session, org.id, NOW)] == [domain.id]


class TestDeduplicationAndCooldown:
    def _setup(self, session, cooldown=60):
        org = make_org(session)
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.2", 50, False, False, False)], created_at=minutes_ago(5))
        rule = make_rule(session, org, "dmarc_fail_rate", threshold=10, cooldown=cooldown, window=240)
        return org, rule

    def test_open_event_blocks_a_second_one(self, session):
        org, rule = self._setup(session, cooldown=0)
        assert len(evaluate_rules_for_org(session, org.id, NOW)) == 1
        assert evaluate_rules_for_org(session, org.id, NOW + timedelta(minutes=10)) == []
        _events(session, org)[0].status = "acknowledged"
        assert evaluate_rules_for_org(session, org.id, NOW + timedelta(minutes=20)) == []

    def test_resolved_event_allows_a_new_one_after_the_pause(self, session):
        org, rule = self._setup(session, cooldown=60)
        evaluate_rules_for_org(session, org.id, NOW)
        _events(session, org)[0].status = "resolved"
        assert evaluate_rules_for_org(session, org.id, NOW + timedelta(minutes=30)) == []  # pause runs
        assert len(evaluate_rules_for_org(session, org.id, NOW + timedelta(minutes=61))) == 1

    def test_inactive_rule_is_skipped(self, session):
        org, rule = self._setup(session)
        rule.is_active = False
        assert evaluate_rules_for_org(session, org.id, NOW) == []


class TestQueue:
    def test_rule_event_goes_to_its_channels(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        chosen = make_channel(session, org, name="Gewählt")
        make_channel(session, org, name="Andere")
        switched_off = make_channel(session, org, name="Aus", active=False)
        add_report(session, org, domain, [("192.0.2.2", 50, False, False, False)], created_at=minutes_ago(5))
        make_rule(session, org, "dmarc_fail_rate", threshold=10, channels=[chosen, switched_off])
        event = evaluate_rules_for_org(session, org.id, NOW)[0]
        assert [d.channel_id for d in event.deliveries] == [chosen.id]

    def test_system_alert_goes_to_every_active_channel(self, session):
        org = make_org(session)
        first = make_channel(session, org, name="Eins")
        second = make_channel(session, org, name="Zwei")
        make_channel(session, org, name="Aus", active=False)
        event = create_system_alert(session, org_id=org.id, alert_type="import_failed", title="Archivbombe abgewehrt",
                                    severity="critical")
        assert sorted(d.channel_id for d in event.deliveries) == sorted([first.id, second.id])


# Delivery ------------------------------------------------------------------------------

@pytest.fixture
def http_calls(monkeypatch):
    """Answers every HTTP request with the status in http_calls['status'] and records it."""
    calls = {"status": 200, "requests": []}
    real_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        calls["requests"].append(request)
        if calls["status"] == "timeout":
            raise httpx.ConnectTimeout("timeout", request=request)
        return httpx.Response(calls["status"], json={})

    monkeypatch.setattr(notification.httpx, "Client",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    return calls


def _queued_event(session, channel_type="webhook", config=None, severity="warning"):
    org = make_org(session)
    domain = make_domain(session, org)
    channel = make_channel(session, org, channel_type, config)
    event = create_system_alert(session, org_id=org.id, alert_type="dmarc_fail_rate", severity=severity,
                                title="12 % scheitern an DMARC für example.org",
                                description="Prüfe die Quellen unter „Quellen“.", domain_id=domain.id)
    return org, channel, event


class TestDispatch:
    def test_webhook(self, session, http_calls):
        _, _, event = _queued_event(session)
        assert dispatch_pending(session, NOW) == {"sent": 1, "failed": 0, "skipped": 0}
        body = json.loads(http_calls["requests"][0].content)
        assert body["title"] == event.title
        assert body["domain"] == "example.org"
        assert body["url"].endswith("/alerts/events?status=open")
        assert event.deliveries[0].status == "sent"

    def test_ntfy_sends_json_with_umlauts(self, session, http_calls):
        _queued_event(session, "ntfy", {"topic": "dmarc-alarme", "token": "tk_test"}, severity="critical")
        dispatch_pending(session, NOW)
        request = http_calls["requests"][0]
        assert str(request.url) == settings.NTFY_DEFAULT_URL
        assert request.headers["Authorization"] == "Bearer tk_test"
        body = json.loads(request.content.decode("utf-8"))
        assert body["topic"] == "dmarc-alarme"
        assert body["priority"] == 5
        assert body["message"] == "Prüfe die Quellen unter „Quellen“."

    def test_ntfy_uses_own_server(self, session, http_calls):
        _queued_event(session, "ntfy", {"topic": "alarme", "url": "https://ntfy.example.test"})
        dispatch_pending(session, NOW)
        assert str(http_calls["requests"][0].url) == "https://ntfy.example.test"

    def test_slack(self, session, http_calls):
        _queued_event(session, "slack", {"url": "https://hooks.example.test/services/T0/B0/geheim"})
        dispatch_pending(session, NOW)
        body = json.loads(http_calls["requests"][0].content)
        assert body["text"].startswith("Warnung: 12 %")
        assert body["attachments"][0]["color"] == "#fed329"

    def test_failure_is_explained_and_retried_later(self, session, http_calls, monkeypatch):
        monkeypatch.setattr(settings, "NOTIFICATION_RETRY_DELAY_SECONDS", 120)
        http_calls["status"] = 403
        _, _, event = _queued_event(session)
        assert dispatch_pending(session, NOW)["failed"] == 1
        delivery = event.deliveries[0]
        assert delivery.status == "failed"
        assert delivery.retry_count == 1
        assert "Status 403" in delivery.error_message
        assert "hooks.example.test" in delivery.error_message
        assert aware(delivery.next_attempt_at) == NOW + timedelta(seconds=120)
        # Not due before the pause is over
        assert dispatch_pending(session, NOW + timedelta(seconds=60)) == {"sent": 0, "failed": 0, "skipped": 0}
        http_calls["status"] = 200
        assert dispatch_pending(session, NOW + timedelta(seconds=121))["sent"] == 1
        assert delivery.status == "sent"
        assert delivery.error_message is None

    def test_pause_doubles_and_attempts_end(self, session, http_calls, monkeypatch):
        monkeypatch.setattr(settings, "NOTIFICATION_RETRY_DELAY_SECONDS", 60)
        monkeypatch.setattr(settings, "NOTIFICATION_RETRY_MAX", 2)
        http_calls["status"] = "timeout"
        _, _, event = _queued_event(session)
        delivery = event.deliveries[0]
        moment = NOW
        for expected_pause in (60, 120, 240):
            assert dispatch_pending(session, moment)["failed"] == 1
            assert aware(delivery.next_attempt_at) == moment + timedelta(seconds=expected_pause)
            moment = aware(delivery.next_attempt_at)
        assert delivery.retry_count == 3
        assert "nicht innerhalb von" in delivery.error_message
        assert dispatch_pending(session, moment + timedelta(days=1))["failed"] == 0

    def test_switched_off_channel_is_skipped(self, session, http_calls):
        _, channel, event = _queued_event(session)
        channel.is_active = False
        assert dispatch_pending(session, NOW)["skipped"] == 1
        assert http_calls["requests"] == []
        assert event.deliveries[0].status == "skipped"

    def test_batch_size(self, session, http_calls, monkeypatch):
        monkeypatch.setattr(settings, "NOTIFICATION_BATCH_SIZE", 1)
        org, channel, _ = _queued_event(session)
        create_system_alert(session, org_id=org.id, alert_type="import_failed", title="Noch einer")
        assert dispatch_pending(session, NOW)["sent"] == 1
        assert session.query(NotificationDelivery).filter_by(status="pending").count() == 1

    def test_email_without_mail_server(self, session):
        _, _, event = _queued_event(session, "email", {"to": ["technik@example.test"]})
        dispatch_pending(session, NOW)
        assert "nicht eingerichtet" in event.deliveries[0].error_message

    def test_email(self, session, smtp_server):
        _, _, event = _queued_event(session, "email", {"to": ["technik@example.test", "chefin@example.test"]})
        assert dispatch_pending(session, NOW)["sent"] == 1
        envelope = smtp_server.envelopes[0]
        assert envelope.rcpt_tos == ["technik@example.test", "chefin@example.test"]
        message = smtp_server.messages[0]
        assert message["Subject"] == "Warnung: 12 % scheitern an DMARC für example.org"
        assert message["Auto-Submitted"] == "auto-generated"
        text = message.get_body(("plain",)).get_content().replace("\r\n", "\n")
        html = message.get_body(("html",)).get_content()
        assert text.startswith("Hallo,")
        assert "Prüfe die Quellen unter „Quellen“." in text
        assert "\n-- \n" in text
        assert all(len(line) <= 78 or "://" in line for line in text.splitlines())
        assert "DMARC-Fehlerquote über der Schwelle" in html
        assert "Alarm ansehen" in html


class TestChannelConfig:
    def test_valid_configs(self):
        assert build_channel_config("email", recipients="a@example.test\nb@example.test; c@example.test") == {
            "to": ["a@example.test", "b@example.test", "c@example.test"]}
        assert build_channel_config("ntfy", topic="dmarc_alarme", url="https://ntfy.example.test/", token=" t ") == {
            "topic": "dmarc_alarme", "url": "https://ntfy.example.test", "token": "t"}
        assert build_channel_config("webhook", url="https://hooks.example.test/x") == {
            "url": "https://hooks.example.test/x"}

    @pytest.mark.parametrize(("channel_type", "fields", "message"), [
        ("email", {"recipients": ""}, "mindestens eine Empfängeradresse"),
        ("email", {"recipients": "kaputt"}, "kaputt"),
        ("ntfy", {"topic": "mit leerzeichen"}, "nur Buchstaben, Ziffern"),
        ("webhook", {"url": "ftp://example.test"}, "http:// oder https://"),
        ("pushover", {}, "Diese Kanalart gibt es nicht"),
    ])
    def test_invalid_configs_are_explained(self, channel_type, fields, message):
        with pytest.raises(ChannelError, match=message):
            build_channel_config(channel_type, **fields)

    def test_summary_hides_secrets(self, session):
        org = make_org(session)
        slack = make_channel(session, org, "slack", {"url": "https://hooks.example.test/services/T0/B0/geheim"})
        ntfy = make_channel(session, org, "ntfy", {"topic": "alarme", "token": "tk_geheim"})
        assert channel_summary(slack) == "hooks.example.test"
        assert "geheim" not in channel_summary(ntfy)
        assert channel_summary(ntfy) == "ntfy.sh · Thema alarme"
