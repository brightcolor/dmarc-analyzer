"""Weekly digest: numbers, recipients, schedule, mail text and the settings page."""
from datetime import UTC, datetime, timedelta

import pytest

from app.config import settings
from app.models import AlertEvent, Organization, OrganizationMembership
from app.services.auth import create_user
from app.services.digest import (
    DigestError,
    Recipient,
    build_digest,
    digest_due,
    digest_recipients,
    last_slot,
    next_slot,
    send_digest,
    send_due_digests,
)
from app.services.mail_render import render_digest_mail
from tests.helpers import (
    NOW,
    add_report,
    add_source,
    aware,
    make_domain,
    make_org,
)


def _filled_org(session):
    org = make_org(session, created_at=NOW - timedelta(days=60))
    domain = make_domain(session, org, "example.org", policy="none")
    make_domain(session, org, "example.net")
    # This week: 90 of 100 pass
    add_report(session, org, domain, [("192.0.2.1", 90, True, True, True), ("203.0.113.5", 10, False, False, False)],
               created_at=NOW - timedelta(days=1), report_format="rfc9990", reporting_org="Empfänger A")
    # The week before: 80 of 100 pass
    add_report(session, org, domain, [("192.0.2.1", 80, True, True, True), ("203.0.113.5", 20, False, False, False)],
               created_at=NOW - timedelta(days=9), reporting_org="Empfänger B")
    add_source(session, org, "203.0.113.5", total=30, failed=30, first_seen=NOW - timedelta(days=2),
               reverse_dns="mail.example.test")
    session.add(AlertEvent(organization_id=org.id, alert_type="dmarc_fail_rate", severity="warning",
                           title="10 % scheitern an DMARC", status="open", created_at=NOW - timedelta(hours=3)))
    session.flush()
    return org


def _admin(session, org, email="chefin@example.test", name="Erika Muster", role="org_admin", active=True):
    user = create_user(session, email, "Testpasswort-2026", full_name=name)
    session.add(OrganizationMembership(user_id=user.id, organization_id=org.id, role=role, is_active=active))
    session.flush()
    return user


class TestNumbers:
    def test_totals_and_comparison(self, session):
        data = build_digest(session, _filled_org(session), NOW)
        assert (data.total, data.failed, data.passed) == (100, 10, 90)
        assert data.rate == 90
        assert data.previous_rate == 80
        assert data.rate_change == 10
        assert (data.reports, data.reporters) == (1, 1)
        assert data.formats == [("RFC 9990", 1)]

    def test_domains_sources_alerts(self, session):
        data = build_digest(session, _filled_org(session), NOW)
        assert [(d.name, d.total, d.failed) for d in data.domains] == [("example.org", 100, 10), ("example.net", 0, 0)]
        assert [(s.ip, s.name, s.failed) for s in data.failing_sources] == [("203.0.113.5", "mail.example.test", 10)]
        assert data.new_source_count == 1
        assert data.open_alert_count == 1

    def test_list_limit_comes_from_the_settings(self, session, monkeypatch):
        org = _filled_org(session)
        domain = make_domain(session, org, "example.com")
        add_report(session, org, domain, [("198.51.100.1", 5, False, False, False),
                                          ("198.51.100.2", 4, False, False, False)], created_at=NOW - timedelta(days=1))
        assert len(build_digest(session, org, NOW).failing_sources) == 3
        monkeypatch.setattr(settings, "DIGEST_LIST_LIMIT", 1)
        assert [s.ip for s in build_digest(session, org, NOW).failing_sources] == ["203.0.113.5"]

    def test_period_length_comes_from_the_settings(self, session, monkeypatch):
        org = _filled_org(session)
        monkeypatch.setattr(settings, "DIGEST_PERIOD_DAYS", 14)
        data = build_digest(session, org, NOW)
        assert data.total == 200
        assert data.days == 14

    def test_empty_period(self, session):
        org = make_org(session)
        make_domain(session, org)
        data = build_digest(session, org, NOW)
        assert data.total == 0
        assert data.rate is None
        assert data.rate_change is None


class TestRecipients:
    def test_administrators_by_default(self, session):
        org = make_org(session)
        _admin(session, org)
        _admin(session, org, "analyst@example.test", role="analyst")
        _admin(session, org, "ehemalig@example.test", active=False)
        recipients = digest_recipients(session, org)
        assert [(r.address, r.name, r.listed) for r in recipients] == [("chefin@example.test", "Erika", False)]

    def test_entered_addresses_win(self, session):
        org = make_org(session)
        _admin(session, org)
        org.digest_recipients = "team@example.test\nleitung@example.test"
        assert [(r.address, r.listed) for r in digest_recipients(session, org)] == [
            ("team@example.test", True), ("leitung@example.test", True)]


class TestSchedule:
    def test_default_is_monday_eight_in_berlin(self):
        # Monday 28.09.2026, 08:00 in Berlin is 06:00 UTC
        assert last_slot(NOW) == datetime(2026, 9, 28, 6, 0, tzinfo=UTC)
        assert last_slot(datetime(2026, 9, 28, 5, 59, tzinfo=UTC)) == datetime(2026, 9, 21, 6, 0, tzinfo=UTC)
        assert next_slot(NOW) == datetime(2026, 10, 5, 6, 0, tzinfo=UTC)

    def test_winter_time(self):
        # After the clock change on 25.10.2026, 08:00 in Berlin is 07:00 UTC
        assert last_slot(datetime(2026, 10, 27, 12, 0, tzinfo=UTC)) == datetime(2026, 10, 26, 7, 0, tzinfo=UTC)

    def test_other_weekday_and_hour(self, monkeypatch):
        monkeypatch.setattr(settings, "DIGEST_WEEKDAY", 4)
        monkeypatch.setattr(settings, "DIGEST_HOUR", 17)
        monkeypatch.setattr(settings, "DISPLAY_TIMEZONE", "UTC")
        assert last_slot(NOW) == datetime(2026, 9, 25, 17, 0, tzinfo=UTC)

    def test_due_once_per_week(self, session):
        org = make_org(session, created_at=NOW - timedelta(days=30))
        assert digest_due(org, NOW) is True
        org.digest_last_sent_at = NOW - timedelta(hours=1)
        assert digest_due(org, NOW) is False
        assert digest_due(org, NOW + timedelta(days=7)) is True

    def test_new_organisation_waits_for_the_next_slot(self, session):
        org = make_org(session, created_at=NOW - timedelta(hours=1))
        assert digest_due(org, NOW) is False

    def test_switched_off(self, session):
        org = make_org(session, created_at=NOW - timedelta(days=30))
        org.digest_enabled = False
        assert digest_due(org, NOW) is False


class TestMail:
    def test_text_and_html(self, session):
        data = build_digest(session, _filled_org(session), NOW)
        subject, text, html = render_digest_mail(data, Recipient("chefin@example.test", "Erika"))
        # Numbers and their unit stay together through a no-break space
        subject, text, html = (part.replace(" ", " ") for part in (subject, text, html))
        assert subject == "DMARC-Wochenbericht Muster Farben: 90,0 % bestanden"
        assert text.startswith("Hallo Erika,")
        assert "+10,0 Prozentpunkte gegenüber der Vorwoche" in text
        assert "203.0.113.5 (mail.example.test): 10 von 100 nicht bestanden" not in text
        assert "203.0.113.5 (mail.example.test): 10 von 10 nicht bestanden" in text
        assert "RFC 9990: 1 Bericht" in text
        assert "weil du Administrator von Muster Farben bist" in text
        assert all(len(line) <= 78 or "://" in line for line in text.splitlines())
        assert "Deine DMARC-Woche" in html
        assert "90,0 %" in html
        assert "Hallo Erika," in html

    def test_without_reports(self, session):
        org = make_org(session)
        make_domain(session, org)
        subject, text, _ = render_digest_mail(build_digest(session, org, NOW), Recipient("a@example.test", listed=True))
        assert subject.endswith("keine Berichte eingegangen")
        assert text.startswith("Hallo,")
        assert "kam kein DMARC-Bericht an" in text
        assert "als Empfänger des Wochenberichts" in text


class TestSending:
    def test_needs_a_mail_server(self, session):
        org = _filled_org(session)
        _admin(session, org)
        with pytest.raises(DigestError, match="nicht eingerichtet"):
            send_digest(session, org, NOW)

    def test_needs_a_recipient(self, session, smtp_server):
        with pytest.raises(DigestError, match="keinen Empfänger"):
            send_digest(session, _filled_org(session), NOW)

    def test_one_mail_per_recipient(self, session, smtp_server):
        org = _filled_org(session)
        org.digest_recipients = "team@example.test\nleitung@example.test"
        result = send_digest(session, org, NOW)
        assert result.sent == ["team@example.test", "leitung@example.test"]
        assert [e.rcpt_tos for e in smtp_server.envelopes] == [["team@example.test"], ["leitung@example.test"]]
        assert aware(org.digest_last_sent_at) == NOW

    def test_due_digests_go_out_once(self, session, smtp_server):
        org = _filled_org(session)
        _admin(session, org)
        empty = make_org(session, "Ohne Domains", "ohne-domains", created_at=NOW - timedelta(days=60))
        _admin(session, empty, "leer@example.test")
        session.commit()
        assert send_due_digests(session, NOW) == 1
        assert send_due_digests(session, NOW + timedelta(minutes=15)) == 0
        assert len(smtp_server.envelopes) == 1
        assert session.get(Organization, empty.id).digest_last_sent_at is None


# Settings page -----------------------------------------------------------------------------

from tests.test_web import _login, _seed  # noqa: E402


class TestDigestPage:
    def test_save_and_validate(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/alerts/digest", data={"enabled": "1", "recipients": "team@example.test\nkaputt"})
        assert response.status_code == 400
        assert "kaputt" in response.text
        response = web.post("/alerts/digest", data={"recipients": "team@example.test"})
        assert response.status_code == 303
        page = web.get("/alerts/digest")
        assert "Wochenbericht ausgeschaltet" in page.text
        db = session_factory()
        org = db.get(Organization, ids["org"])
        assert (org.digest_enabled, org.digest_recipients) == (False, "team@example.test")
        db.close()

    def test_send_now_without_mail_server_is_explained(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        web.post("/alerts/digest/send")
        page = web.get("/alerts/digest")
        assert "Der Wochenbericht wurde nicht verschickt" in page.text
        assert "MAIL_SMTP_HOST" in page.text

    def test_send_now(self, web, session_factory, smtp_server):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        web.post("/alerts/digest/send")
        assert "Wochenbericht verschickt" in web.get("/alerts/digest").text
        assert smtp_server.envelopes[0].rcpt_tos == ["admin@example.test"]

    def test_preview_shows_the_mail(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.get("/alerts/digest/preview")
        assert "Deine DMARC-Woche" in response.text
        assert "Hallo Max," in response.text

    def test_analyst_may_look_but_not_change(self, web, session_factory):
        ids = _seed(session_factory, role="analyst", superadmin=False)
        _login(web, ids["org"])
        assert "Einstellen dürfen den Wochenbericht die Administratoren" in web.get("/alerts/digest").text
        assert web.post("/alerts/digest", data={"recipients": ""}).status_code == 403
        assert web.post("/alerts/channels/new", data={"channel_type": "webhook",
                                                      "url": "https://hooks.example.test"}).status_code == 403
