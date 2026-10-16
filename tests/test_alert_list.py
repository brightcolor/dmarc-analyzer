"""Alert list: rows with domain, cause and source, groups for alerts of one kind about one domain, group actions."""
import pytest

from app.config import settings
from app.models import AlertEvent, AuditLog, Domain, Organization
from app.routers.alerts import _safe_events_url
from app.services.alert_list import group_rows, load_rows
from app.services.alert_service import ALERT_TYPES, raise_event
from tests.helpers import NOW, make_org
from tests.test_web import _login, _seed


def _source_alert(db, org, ip, domain="hsp-events.de", severity="warning", status="open", **kwargs):
    event = raise_event(
        db, org_id=org.id, alert_type="new_unknown_source", severity=severity,
        title=f"Neue unbekannte Quelle {ip} (host.example, Anbieter) für {domain}", source_ip=ip, now=NOW,
        metrics={"domains": [domain], "domains_more": 0, "source_label": "host.example, Anbieter", "total": 2,
                 **kwargs})
    event.status = status
    return event


@pytest.fixture
def seeded(web, session_factory):
    ids = _seed(session_factory)
    db = session_factory()
    org = db.get(Organization, ids["org"])
    db.query(AlertEvent).delete()
    for n in range(1, 4):
        _source_alert(db, org, f"198.51.100.{n}")
    _source_alert(db, org, "198.51.100.9", domain="crust-y.com")
    domain = db.query(Domain).filter_by(organization_id=org.id).first()
    fail = raise_event(db, org_id=org.id, alert_type="dmarc_fail_rate", severity="critical",
                       title="80 % scheitern an DMARC für " + domain.name, domain_id=domain.id, now=NOW,
                       metrics={"causes": [{"key": "spoof", "label": "Gefälschter Absender (vermutlich)",
                                            "messages": 8, "sources": 3}]})
    stranger = make_org(db, "Fremd", "fremd")
    foreign = _source_alert(db, stranger, "203.0.113.5")
    db.commit()
    out = {"org": org.id, "foreign": foreign.id, "fail": fail.id, "domain": domain.name}
    db.close()
    _login(web, ids["org"])
    return out


class TestRows:
    def test_row_names_domain_cause_and_source(self, session):
        org = make_org(session)
        event = _source_alert(session, org, "198.51.100.1")
        rows, truncated = load_rows(session, org.id, None, None, ALERT_TYPES)
        assert not truncated
        row = rows[0]
        assert row.title == "Neue unbekannte Versandquelle 198.51.100.1" and row.domains == ["hsp-events.de"]
        assert row.source == "host.example, Anbieter" and row.detail and row.event is event

    def test_domain_of_a_fail_rate_alert_comes_from_the_alert(self, session):
        from tests.helpers import make_domain

        org = make_org(session)
        domain = make_domain(session, org, "piste.de")
        raise_event(session, org_id=org.id, alert_type="dmarc_fail_rate", severity="info", title="x",
                    domain_id=domain.id, now=NOW)
        assert load_rows(session, org.id, None, None, ALERT_TYPES)[0][0].domains == ["piste.de"]

    def test_filter_by_status_and_severity(self, session):
        org = make_org(session)
        _source_alert(session, org, "198.51.100.1")
        _source_alert(session, org, "198.51.100.2", status="resolved", severity="info")
        assert len(load_rows(session, org.id, "open", None, ALERT_TYPES)[0]) == 1
        assert len(load_rows(session, org.id, None, "info", ALERT_TYPES)[0]) == 1
        assert len(load_rows(session, org.id, None, None, ALERT_TYPES)[0]) == 2

    def test_load_limit_comes_from_the_settings(self, session, monkeypatch):
        monkeypatch.setattr(settings, "UI_ALERT_GROUP_LIMIT", 100)
        org = make_org(session)
        for n in range(101):
            _source_alert(session, org, f"198.51.{n // 250}.{n % 250}")
        rows, truncated = load_rows(session, org.id, None, None, ALERT_TYPES)
        assert len(rows) == 100 and truncated


class TestGroups:
    def test_same_kind_and_domain_form_one_group_by_severity(self, session):
        org = make_org(session)
        for n in range(3):
            _source_alert(session, org, f"198.51.100.{n}")
        _source_alert(session, org, "198.51.100.9", domain="crust-y.com", severity="critical")
        groups = group_rows(load_rows(session, org.id, None, None, ALERT_TYPES)[0], ALERT_TYPES)
        assert [(g.domain, g.count, g.severity) for g in groups] == [("crust-y.com", 1, "critical"),
                                                                     ("hsp-events.de", 3, "warning")]
        assert groups[1].sources == 3 and groups[1].messages == 6 and groups[1].open_count == 3

    def test_causes_are_summed(self, session):
        org = make_org(session)
        for n in range(2):
            _source_alert(session, org, f"198.51.100.{n}", causes=[{"label": "Gefälschter Absender", "messages": 3}])
        group = group_rows(load_rows(session, org.id, None, None, ALERT_TYPES)[0], ALERT_TYPES)[0]
        assert group.causes == [("Gefälschter Absender", 6)]


class TestPages:
    def test_list_shows_groups_chips_and_no_wall_of_text(self, web, seeded):
        page = web.get("/alerts/events?status=open").text
        assert "app-alertgroup" in page and "Neue unbekannte Versandquelle · hsp-events.de" in page
        assert "Alle 3 erledigt" in page and "app-chip--domain\">crust-y.com" in page
        assert "Gefälschter Absender (vermutlich) · 8 Nachrichten" in page
        assert "Administrator, alle Domains" not in page
        assert page.count("Gründe und Abhilfe ansehen") == 5

    def test_single_view_lists_every_alert(self, web, seeded):
        page = web.get("/alerts/events?status=open&view=single").text
        assert "app-alertgroup" not in page and page.count('class="app-alert"') == 5

    def test_group_action_resolves_only_that_group(self, web, seeded, session_factory):
        response = web.post("/alerts/events/bulk", data={
            "alert_type": "new_unknown_source", "domain": "hsp-events.de", "action": "resolve", "status": "open",
            "next": "/alerts/events?status=open"})
        assert response.status_code == 303 and response.headers["location"] == "/alerts/events?status=open"
        db = session_factory()
        statuses = {e.source_ip: e.status for e in db.query(AlertEvent).filter_by(organization_id=seeded["org"])}
        assert statuses["198.51.100.1"] == statuses["198.51.100.3"] == "resolved"
        assert statuses["198.51.100.9"] == "open"
        assert db.get(AlertEvent, seeded["foreign"]).status == "open"
        entry = db.query(AuditLog).filter_by(action="alert.bulk_resolve").one()
        assert '"count": 3' in entry.new_value
        db.close()
        assert "3 Alarme erledigt" in web.get("/alerts/events").text

    def test_group_action_acknowledge_skips_handled_alerts(self, web, seeded, session_factory):
        db = session_factory()
        first = db.query(AlertEvent).filter_by(source_ip="198.51.100.1").one()
        first.status = "resolved"
        db.commit()
        db.close()
        web.post("/alerts/events/bulk", data={"alert_type": "new_unknown_source", "domain": "hsp-events.de",
                                              "action": "acknowledge", "status": ""})
        db = session_factory()
        statuses = {e.source_ip: e.status for e in db.query(AlertEvent).filter_by(organization_id=seeded["org"])}
        assert statuses["198.51.100.1"] == "resolved" and statuses["198.51.100.2"] == "acknowledged"
        db.close()

    def test_unknown_group_action_is_refused_with_a_reason(self, web, seeded):
        response = web.post("/alerts/events/bulk", data={"alert_type": "new_unknown_source", "domain": "x",
                                                         "action": "loeschen"})
        assert response.status_code == 400 and "Sammelaktion" in response.text
        assert web.post("/alerts/events/bulk", data={"alert_type": "gibt-es-nicht", "domain": "x",
                                                     "action": "resolve"}).status_code == 400

    def test_single_actions_return_to_where_they_came_from(self, web, seeded, session_factory):
        db = session_factory()
        event_id = db.query(AlertEvent).filter_by(source_ip="198.51.100.9").one().id
        db.close()
        response = web.post(f"/alerts/events/{event_id}/acknowledge", data={"next": f"/alerts/events/{event_id}"})
        assert response.headers["location"] == f"/alerts/events/{event_id}"
        assert web.post(f"/alerts/events/{event_id}/resolve", data={"next": "https://example.net/"}
                        ).headers["location"] == "/alerts/events"

    def test_read_only_members_cannot_use_group_actions(self, web, session_factory):
        ids = _seed(session_factory, role="read_only", superadmin=False)
        _login(web, ids["org"])
        response = web.post("/alerts/events/bulk", data={"alert_type": "new_unknown_source", "domain": "x",
                                                         "action": "resolve"})
        assert response.status_code == 403
        assert "Alle " not in web.get("/alerts/events").text

    @pytest.mark.parametrize(("target", "expected"), [
        ("/alerts/events?status=open", "/alerts/events?status=open"),
        ("/alerts/events/abc", "/alerts/events/abc"),
        ("//example.net/alerts/events", "/alerts/events"),
        ("https://example.net/", "/alerts/events"),
        ("", "/alerts/events"),
    ])
    def test_return_target_stays_inside_the_alerts(self, target, expected):
        assert _safe_events_url(target) == expected


class TestKindGroups:
    def _missing(self, db, org, domain):
        from tests.helpers import make_domain

        domain_row = make_domain(db, org, domain)
        return raise_event(db, org_id=org.id, alert_type="reports_missing", severity="info",
                           title=f"Seit 2 Tagen keine Berichte für {domain}", domain_id=domain_row.id, now=NOW)

    def test_alerts_that_arise_per_domain_form_one_group_over_all_domains(self, session):
        org = make_org(session)
        for name in ("a.example", "b.example", "c.example"):
            self._missing(session, org, name)
        groups = group_rows(load_rows(session, org.id, None, None, ALERT_TYPES)[0], ALERT_TYPES)
        assert len(groups) == 1 and groups[0].count == 3 and groups[0].domain == ""
        assert groups[0].domain_names == ["a.example", "b.example", "c.example"]

    def test_kinds_come_from_the_settings(self, session, monkeypatch):
        org = make_org(session)
        for name in ("a.example", "b.example"):
            self._missing(session, org, name)
        monkeypatch.setattr(settings, "UI_ALERT_GROUP_BY_TYPE", "")
        assert len(group_rows(load_rows(session, org.id, None, None, ALERT_TYPES)[0], ALERT_TYPES)) == 2
        monkeypatch.setattr(settings, "UI_ALERT_GROUP_BY_TYPE", "reports_missing")
        assert len(group_rows(load_rows(session, org.id, None, None, ALERT_TYPES)[0], ALERT_TYPES)) == 1

    def test_group_action_covers_every_domain_of_the_kind(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        org = db.get(Organization, ids["org"])
        db.query(AlertEvent).delete()
        for name in ("a.example", "b.example"):
            self._missing(db, org, name)
        db.commit()
        db.close()
        _login(web, ids["org"])
        page = web.get("/alerts/events?status=open").text
        assert "2 Domains" in page and "Alle 2 erledigt" in page
        web.post("/alerts/events/bulk", data={"alert_type": "reports_missing", "domain": "", "action": "resolve",
                                              "status": "open"})
        db = session_factory()
        assert {e.status for e in db.query(AlertEvent)} == {"resolved"}
        db.close()

    def test_nested_rows_do_not_repeat_the_text(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        org = db.get(Organization, ids["org"])
        db.query(AlertEvent).delete()
        for name in ("a.example", "b.example"):
            event = self._missing(db, org, name)
            event.description = "Es kam kein neuer DMARC-Bericht an."
        db.commit()
        db.close()
        _login(web, ids["org"])
        assert "Es kam kein neuer DMARC-Bericht an." not in web.get("/alerts/events?status=open").text
        assert web.get("/alerts/events?status=open&view=single").text.count("Es kam kein neuer DMARC-Bericht an.") == 2

    def test_invalid_kind_is_explained_at_start(self, monkeypatch):
        from app.config import load_settings

        monkeypatch.setenv("UI_ALERT_GROUP_BY_TYPE", "reports_missing,*")
        with pytest.raises(SystemExit) as exc:
            load_settings()
        assert "UI_ALERT_GROUP_BY_TYPE:" in str(exc.value) and "keine Alarmart" in str(exc.value)
