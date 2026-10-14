"""Further recipients per domain: entering them, alerts by mail and a weekly digest for their domains only."""
from datetime import timedelta

import pytest

from app.config import settings
from app.models import AuditLog, Domain, DomainRecipient, NotificationDelivery, Organization
from app.services.alert_service import raise_event
from app.services.digest import build_digest, send_due_digests
from app.services.domain_recipients import RecipientError, add_recipient, alert_addresses, update_recipient
from app.services.notification import dispatch_pending
from tests.helpers import NOW, add_report, aware, make_domain, make_org
from tests.test_digest import _admin
from tests.test_web import _login, _seed


def _entered_earlier(session, *recipients):
    """Entered a month ago; a new entry waits for the next digest slot like a new organisation."""
    for recipient in recipients:
        recipient.created_at = NOW - timedelta(days=30)
    session.flush()


def _two_domains(session):
    org = make_org(session, created_at=NOW - timedelta(days=60))
    first = make_domain(session, org, "example.org")
    second = make_domain(session, org, "example.net")
    add_report(session, org, first, [("192.0.2.1", 90, True, True, True), ("203.0.113.5", 10, False, False, False)],
               created_at=NOW - timedelta(days=1))
    add_report(session, org, second, [("198.51.100.7", 50, False, False, False)], created_at=NOW - timedelta(days=2))
    session.flush()
    return org, first, second


class TestEntering:
    def test_address_is_normalized(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        recipient = add_recipient(session, domain, "  Team@Example.TEST ", "Team Technik")
        assert (recipient.email, recipient.name, recipient.alerts, recipient.digest) == \
            ("team@example.test", "Team Technik", True, True)

    @pytest.mark.parametrize(("email", "alerts", "digest", "reason"), [
        ("", True, True, "Trage eine E-Mail-Adresse ein"),
        ("kein-at-zeichen", True, True, "keine gültige E-Mail-Adresse"),
        ("team@example.test", False, False, "Wähle Alarme, Wochenbericht oder beides"),
    ])
    def test_wrong_entries_are_explained(self, session, email, alerts, digest, reason):
        domain = make_domain(session, make_org(session))
        with pytest.raises(RecipientError) as exc:
            add_recipient(session, domain, email, alerts=alerts, digest=digest)
        assert reason in str(exc.value)

    def test_same_address_once_per_domain(self, session):
        org = make_org(session)
        domain, other = make_domain(session, org, "example.org"), make_domain(session, org, "example.net")
        add_recipient(session, domain, "team@example.test")
        add_recipient(session, other, "team@example.test")
        with pytest.raises(RecipientError) as exc:
            add_recipient(session, domain, "TEAM@example.test")
        assert "steht schon bei example.org" in str(exc.value)

    def test_limit_comes_from_the_settings(self, session, monkeypatch):
        monkeypatch.setattr(settings, "DOMAIN_RECIPIENTS_MAX", 2)
        domain = make_domain(session, make_org(session))
        add_recipient(session, domain, "a@example.test")
        add_recipient(session, domain, "b@example.test")
        with pytest.raises(RecipientError) as exc:
            add_recipient(session, domain, "c@example.test")
        assert "DOMAIN_RECIPIENTS_MAX" in str(exc.value)

    def test_update_needs_one_choice(self, session):
        recipient = add_recipient(session, make_domain(session, make_org(session)), "team@example.test")
        update_recipient(recipient, alerts=False, digest=True)
        assert (recipient.alerts, recipient.digest) == (False, True)
        with pytest.raises(RecipientError):
            update_recipient(recipient, alerts=False, digest=False)


class TestAlerts:
    def test_event_of_the_domain_queues_a_mail(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_recipient(session, domain, "team@example.test")
        add_recipient(session, domain, "nur-bericht@example.test", alerts=False)
        event = raise_event(session, org_id=org.id, alert_type="dmarc_fail_rate", severity="warning",
                            title="12 % scheitern", domain_id=domain.id)
        assert [(d.channel_id, d.recipient) for d in session.query(NotificationDelivery)] == \
            [(None, "team@example.test")]
        assert event.deliveries[0].status == "pending"

    def test_event_without_domain_queues_nothing(self, session):
        org = make_org(session)
        add_recipient(session, make_domain(session, org), "team@example.test")
        raise_event(session, org_id=org.id, alert_type="import_failed", severity="warning", title="Import")
        assert session.query(NotificationDelivery).count() == 0

    def test_inactive_domain_gets_nothing(self, session):
        org = make_org(session)
        domain = make_domain(session, org)
        add_recipient(session, domain, "team@example.test")
        domain.is_active = False
        assert alert_addresses(session, domain.id) == []

    def test_mail_goes_out_and_says_why(self, session, smtp_server):
        org = make_org(session)
        domain = make_domain(session, org)
        add_recipient(session, domain, "team@example.test")
        raise_event(session, org_id=org.id, alert_type="dmarc_fail_rate", severity="critical",
                    title="30 % scheitern an DMARC", domain_id=domain.id)
        assert dispatch_pending(session, NOW) == {"sent": 1, "failed": 0, "skipped": 0}
        assert smtp_server.envelopes[0].rcpt_tos == ["team@example.test"]
        mail = smtp_server.messages[0]
        assert mail["Subject"] == "Kritisch: 30 % scheitern an DMARC"
        text = mail.get_body(("plain",)).get_content()
        assert "bei example.org als Empfänger für Alarme eingetragen" in " ".join(text.split())

    def test_removed_address_is_skipped(self, session, smtp_server):
        org = make_org(session)
        domain = make_domain(session, org)
        recipient = add_recipient(session, domain, "team@example.test")
        raise_event(session, org_id=org.id, alert_type="dmarc_fail_rate", severity="warning", title="Alarm",
                    domain_id=domain.id)
        session.delete(recipient)
        session.flush()
        assert dispatch_pending(session, NOW)["skipped"] == 1
        assert smtp_server.envelopes == []


class TestDigest:
    def test_numbers_only_for_the_domains(self, session):
        org, first, second = _two_domains(session)
        whole = build_digest(session, org, NOW)
        scoped = build_digest(session, org, NOW, domain_ids=[second.id])
        assert (whole.total, whole.failed) == (150, 60)
        assert (scoped.total, scoped.failed) == (50, 50)
        assert scoped.scope == ["example.net"]
        assert [line.name for line in scoped.domains] == ["example.net"]
        assert [line.ip for line in scoped.failing_sources] == ["198.51.100.7"]

    def test_due_digest_goes_to_domain_recipients(self, session, smtp_server):
        org, first, second = _two_domains(session)
        _admin(session, org)
        _entered_earlier(session, add_recipient(session, first, "team@example.test", "Kim"),
                         add_recipient(session, second, "team@example.test"),
                         add_recipient(session, second, "nur-alarme@example.test", digest=False))
        session.commit()
        assert send_due_digests(session, NOW) == 1
        by_address = {e.rcpt_tos[0]: m for e, m in zip(smtp_server.envelopes, smtp_server.messages, strict=True)}
        assert set(by_address) == {"chefin@example.test", "team@example.test"}
        mail = by_address["team@example.test"]
        assert mail["Subject"].startswith("DMARC-Wochenbericht example.net, example.org:")
        text = " ".join(mail.get_body(("plain",)).get_content().split())
        assert "Hallo Kim," in text
        assert "bei example.net, example.org als Empfänger des Wochenberichts eingetragen" in text
        rows = session.query(DomainRecipient).filter_by(email="team@example.test").all()
        assert all(aware(row.digest_last_sent_at) == NOW for row in rows)
        # Once per week
        send_due_digests(session, NOW + timedelta(minutes=15))
        assert len(smtp_server.envelopes) == 2

    def test_own_switch_when_the_organisation_digest_is_off(self, session, smtp_server):
        org, first, _ = _two_domains(session)
        org.digest_enabled = False
        _entered_earlier(session, add_recipient(session, first, "team@example.test"))
        session.commit()
        assert send_due_digests(session, NOW) == 0
        assert [e.rcpt_tos for e in smtp_server.envelopes] == [["team@example.test"]]


    def test_new_entry_waits_for_the_next_slot(self, session, smtp_server):
        org, first, _ = _two_domains(session)
        org.digest_enabled = False
        recipient = add_recipient(session, first, "team@example.test")
        recipient.created_at = NOW - timedelta(hours=1)
        session.commit()
        send_due_digests(session, NOW)
        assert smtp_server.envelopes == []


class TestPage:
    def test_manager_enters_changes_and_removes(self, web, session_factory):
        ids = _seed(session_factory, role="manager", superadmin=False)
        _login(web, ids["org"])
        page = web.get(f"/domains/{ids['domain']}").text
        assert "Weitere Empfänger" in page and "Empfänger eintragen" in page
        response = web.post(f"/domains/{ids['domain']}/recipients",
                            data={"email": "team@example.test", "name": "Kim", "alerts": "1"})
        assert response.status_code == 303
        assert "bekommt ab jetzt die Alarme für" in web.get(f"/domains/{ids['domain']}").text
        db = session_factory()
        recipient = db.query(DomainRecipient).one()
        assert (recipient.alerts, recipient.digest) == (True, False)
        db.close()
        web.post(f"/domains/{ids['domain']}/recipients/{recipient.id}", data={"alerts": "1", "digest": "1"})
        web.post(f"/domains/{ids['domain']}/recipients/{recipient.id}/delete")
        db = session_factory()
        assert db.query(DomainRecipient).count() == 0
        actions = {a for (a,) in db.query(AuditLog.action).filter(AuditLog.action.like("domain_recipient.%"))}
        assert actions == {"domain_recipient.add", "domain_recipient.update", "domain_recipient.delete"}
        db.close()

    def test_wrong_address_is_explained(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        web.post(f"/domains/{ids['domain']}/recipients", data={"email": "kein-at", "alerts": "1"})
        page = web.get(f"/domains/{ids['domain']}").text
        assert "Empfänger nicht eingetragen" in page and "keine gültige E-Mail-Adresse" in page

    def test_analyst_may_look_but_not_change(self, web, session_factory):
        ids = _seed(session_factory, role="analyst", superadmin=False)
        _login(web, ids["org"])
        page = web.get(f"/domains/{ids['domain']}").text
        assert "Weitere Empfänger" in page and "Empfänger eintragen" not in page
        response = web.post(f"/domains/{ids['domain']}/recipients", data={"email": "team@example.test"})
        assert response.status_code == 403

    def test_other_organisation_is_not_reachable(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        other = Organization(name="Andere", slug="andere", is_active=True)
        db.add(other)
        db.flush()
        domain = Domain(organization_id=other.id, name="andere.example", is_active=True)
        db.add(domain)
        db.commit()
        domain_id = domain.id
        db.close()
        _login(web, ids["org"])
        response = web.post(f"/domains/{domain_id}/recipients", data={"email": "team@example.test", "alerts": "1"})
        assert response.status_code == 404
