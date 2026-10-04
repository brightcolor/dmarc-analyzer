"""Alerts by mail come bundled: collected for a while, then one mail per channel or address."""
from datetime import timedelta

import pytest

from app.config import settings
from app.models import NotificationDelivery
from app.services.alert_service import raise_event
from app.services.domain_recipients import add_recipient
from app.services.notification import dispatch_pending
from tests.helpers import NOW, make_channel, make_domain, make_org
from tests.test_alerting import http_calls  # noqa: F401 - fixture


@pytest.fixture
def window(monkeypatch):
    monkeypatch.setattr(settings, "NOTIFICATION_EMAIL_BUNDLE_SECONDS", 900)
    return timedelta(seconds=900)


def _alert(session, org, title, severity="warning", domain=None, at=NOW):
    return raise_event(session, org_id=org.id, alert_type="dmarc_fail_rate", severity=severity, title=title,
                       domain_id=domain.id if domain else None, now=at)


def _text(message) -> str:
    return " ".join(message.get_body(("plain",)).get_content().split())


def test_mails_wait_and_go_out_together(session, smtp_server, window):
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]}, name="Admin")
    _alert(session, org, "12 % scheitern an DMARC für example.org")
    _alert(session, org, "Neue unbekannte Quelle 192.0.2.7", severity="critical", at=NOW + timedelta(minutes=5))
    assert dispatch_pending(session, NOW + timedelta(minutes=10)) == {"sent": 0, "failed": 0, "skipped": 0}
    assert dispatch_pending(session, NOW + window + timedelta(seconds=1)) == {"sent": 2, "failed": 0, "skipped": 0}
    assert len(smtp_server.envelopes) == 1
    mail = smtp_server.messages[0]
    assert mail["Subject"] == "Kritisch: 2 Alarme für Muster Farben"
    text = _text(mail)
    assert text.index("Neue unbekannte Quelle 192.0.2.7") < text.index("12 % scheitern")  # most severe first
    assert "1 kritischer Alarm · 1 Warnung" in text
    assert "kommen gesammelt in einer Mail" in text
    assert {d.status for d in session.query(NotificationDelivery)} == {"sent"}


def test_single_alert_keeps_its_own_mail(session, smtp_server, window):
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    _alert(session, org, "12 % scheitern an DMARC")
    dispatch_pending(session, NOW + window)
    assert smtp_server.messages[0]["Subject"] == "Warnung: 12 % scheitern an DMARC"


def test_other_channels_go_out_at_once(session, http_calls, window):  # noqa: F811 - fixture
    org = make_org(session)
    make_channel(session, org, "webhook")
    _alert(session, org, "12 % scheitern an DMARC")
    assert dispatch_pending(session, NOW)["sent"] == 1
    assert len(http_calls["requests"]) == 1


def test_domain_recipient_gets_one_mail_for_its_domains(session, smtp_server, window):
    org = make_org(session)
    first, second = make_domain(session, org, "example.org"), make_domain(session, org, "example.net")
    add_recipient(session, first, "team@example.test")
    add_recipient(session, second, "team@example.test")
    _alert(session, org, "Fehlerquote example.org", domain=first)
    _alert(session, org, "Fehlerquote example.net", domain=second)
    dispatch_pending(session, NOW + window)
    assert [e.rcpt_tos for e in smtp_server.envelopes] == [["team@example.test"]]
    mail = smtp_server.messages[0]
    assert mail["Subject"] == "2 Alarme für example.net, example.org"
    assert "bei example.net, example.org als Empfänger für Alarme eingetragen" in _text(mail)


def test_list_length_comes_from_the_settings(session, smtp_server, window, monkeypatch):
    monkeypatch.setattr(settings, "NOTIFICATION_BUNDLE_MAX_ITEMS", 2)
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    for index in range(4):
        _alert(session, org, f"Alarm {index}")
    dispatch_pending(session, NOW + window)
    text = _text(smtp_server.messages[0])
    assert "Alarm 1" in text and "Alarm 2" not in text
    assert "Dazu 2 weitere Alarme" in text


def test_same_severity_sorts_by_time_with_and_without_zone(session, smtp_server, window):
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    later = _alert(session, org, "Fehlerquote example.org", at=NOW + timedelta(minutes=5))
    earlier = _alert(session, org, "Fehlerquote example.net")
    session.expire(earlier)  # SQLite hands it back without zone, the other one keeps its zone
    assert later.created_at.tzinfo is not None and earlier.created_at.tzinfo is None
    assert dispatch_pending(session, NOW + window) == {"sent": 2, "failed": 0, "skipped": 0}
    text = _text(smtp_server.messages[0])
    assert text.index("Fehlerquote example.net") < text.index("Fehlerquote example.org")


def test_alert_resolved_before_sending_gets_no_mail(session, smtp_server, window):
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    event = _alert(session, org, "DNS-Einträge fehlerhaft für example.org")
    assert dispatch_pending(session, NOW + timedelta(minutes=5)) == {"sent": 0, "failed": 0, "skipped": 0}
    event.status = "resolved"
    assert dispatch_pending(session, NOW + window) == {"sent": 0, "failed": 0, "skipped": 1}
    assert smtp_server.envelopes == []
    delivery = event.deliveries[0]
    assert delivery.status == "skipped"
    assert "erledigt" in delivery.error_message


def test_bundle_names_only_the_open_alert(session, smtp_server, window):
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    done = _alert(session, org, "DNS-Einträge fehlerhaft für example.org", severity="critical")
    _alert(session, org, "12 % scheitern an DMARC für example.org", at=NOW + timedelta(minutes=5))
    done.status = "resolved"
    # The window still counts from the first alert
    assert dispatch_pending(session, NOW + window) == {"sent": 1, "failed": 0, "skipped": 1}
    assert len(smtp_server.envelopes) == 1
    mail = smtp_server.messages[0]
    assert mail["Subject"] == "Warnung: 12 % scheitern an DMARC für example.org"
    assert "DNS-Einträge" not in _text(mail)


def test_bundle_lists_only_open_alerts(session, smtp_server, window):
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    _alert(session, org, "Neue unbekannte Quelle 192.0.2.7", severity="critical")
    _alert(session, org, "DNS-Einträge fehlerhaft für example.org").status = "resolved"
    _alert(session, org, "example.org ist bereit für p=reject", severity="info")
    assert dispatch_pending(session, NOW + window) == {"sent": 2, "failed": 0, "skipped": 1}
    mail = smtp_server.messages[0]
    assert mail["Subject"] == "Kritisch: 2 Alarme für Muster Farben"
    text = _text(mail)
    assert "Neue unbekannte Quelle 192.0.2.7" in text and "bereit für p=reject" in text
    assert "1 kritischer Alarm · 1 Hinweis" in text
    assert "DNS-Einträge" not in text


def test_no_mail_when_every_alert_is_closed(session, smtp_server, window):
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    _alert(session, org, "DNS-Einträge fehlerhaft für example.org").status = "resolved"
    _alert(session, org, "Neue unbekannte Quelle 192.0.2.7").status = "ignored"
    assert dispatch_pending(session, NOW + window) == {"sent": 0, "failed": 0, "skipped": 2}
    assert smtp_server.envelopes == []


def test_acknowledged_alert_is_still_mailed(session, smtp_server, window):
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    _alert(session, org, "12 % scheitern an DMARC").status = "acknowledged"
    assert dispatch_pending(session, NOW + window) == {"sent": 1, "failed": 0, "skipped": 0}
    assert smtp_server.messages[0]["Subject"] == "Warnung: 12 % scheitern an DMARC"


@pytest.mark.parametrize(("skip", "status", "mails"), [
    ("acknowledged,resolved,ignored", "acknowledged", 0),
    ("", "resolved", 1),
])
def test_skipped_alert_statuses_come_from_the_settings(session, smtp_server, window, monkeypatch, skip, status,
                                                       mails):
    monkeypatch.setattr(settings, "NOTIFICATION_SKIP_ALERT_STATUSES", skip)
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    _alert(session, org, "12 % scheitern an DMARC").status = status
    dispatch_pending(session, NOW + window)
    assert len(smtp_server.envelopes) == mails


def test_failed_bundle_is_retried_as_a_whole(session, window, monkeypatch):
    monkeypatch.setattr(settings, "MAIL_SMTP_HOST", "127.0.0.1")
    monkeypatch.setattr(settings, "MAIL_SMTP_PORT", 9)  # nobody listens there
    monkeypatch.setattr(settings, "MAIL_SMTP_SECURITY", "none")
    monkeypatch.setattr(settings, "MAIL_TIMEOUT_SECONDS", 2)
    org = make_org(session)
    make_channel(session, org, "email", {"to": ["admin@example.test"]})
    _alert(session, org, "Alarm 1")
    _alert(session, org, "Alarm 2")
    assert dispatch_pending(session, NOW + window)["failed"] == 2
    deliveries = session.query(NotificationDelivery).all()
    assert {d.status for d in deliveries} == {"failed"} and {d.retry_count for d in deliveries} == {1}
    assert all("127.0.0.1:9" in d.error_message for d in deliveries)
