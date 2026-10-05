"""Mail templates: the HTML part escapes every value, the plain text part keeps it as written."""
from app.services.alert_service import raise_event
from app.services.mail_render import render_alert_bundle, render_alert_mail
from tests.helpers import NOW, make_channel, make_org

TITLE = 'Quelle <b>"neu"</b> & mehr'
ESCAPED = "Quelle &lt;b&gt;&#34;neu&#34;&lt;/b&gt; &amp; mehr"


def _event(session, org, title=TITLE, description="Hinweis <i>kursiv</i>"):
    return raise_event(session, org_id=org.id, alert_type="dmarc_fail_rate", severity="warning", title=title,
                       description=description, now=NOW)


def test_alert_mail_escapes_html_and_keeps_text(session):
    org = make_org(session, name="Müller & Söhne")
    channel = make_channel(session, org, "email", {"to": ["admin@example.test"]})
    subject, text, html = render_alert_mail(_event(session, org), channel)
    assert ESCAPED in html and TITLE not in html
    assert "Hinweis &lt;i&gt;kursiv&lt;/i&gt;" in html
    assert "Müller &amp; Söhne" in html
    assert TITLE in text and "Hinweis <i>kursiv</i>" in text and "Müller & Söhne" in text
    assert subject == f"Warnung: {TITLE}"


def test_bundle_mail_escapes_html_and_keeps_text(session):
    org = make_org(session)
    channel = make_channel(session, org, "email", {"to": ["admin@example.test"]})
    events = [_event(session, org), _event(session, org, title="Zweiter <Alarm>")]
    _, text, html = render_alert_bundle(events, channel)
    assert ESCAPED in html and "Zweiter &lt;Alarm&gt;" in html
    assert TITLE not in html and "Zweiter <Alarm>" not in html
    assert TITLE in text and "Zweiter <Alarm>" in text
