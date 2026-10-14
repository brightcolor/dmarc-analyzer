"""Alert rules in the web interface: create, edit, delete, and who may do which."""
import json

from app.models import AlertEvent, AlertRule, AuditLog, NotificationChannel, Organization
from tests.test_web import _login, _seed

FORM = {"name": "Fehlerquote", "domain_id": "", "threshold": "10", "time_window_minutes": "60",
        "cooldown_minutes": "60", "severity": "warning"}


def _rule(session_factory, org_id: str, alert_type: str = "dmarc_fail_rate", **values) -> str:
    db = session_factory()
    values = {"threshold": 10, "time_window_minutes": 60, "cooldown_minutes": 60, "severity": "warning",
              "notification_channel_ids": "[]", **values}
    rule = AlertRule(organization_id=org_id, name="Fehlerquote", alert_type=alert_type, is_active=True, **values)
    db.add(rule)
    db.commit()
    rule_id = rule.id
    db.close()
    return rule_id


def _load(session_factory, rule_id: str) -> AlertRule | None:
    db = session_factory()
    rule = db.get(AlertRule, rule_id)
    db.close()
    return rule


class TestEdit:
    def test_form_shows_the_current_values(self, web, session_factory):
        ids = _seed(session_factory)
        rule_id = _rule(session_factory, ids["org"], threshold=12.5, domain_id=ids["domain"])
        _login(web, ids["org"])
        page = web.get(f"/alerts/rules/{rule_id}/edit")
        assert page.status_code == 200
        assert 'value="12.5"' in page.text
        assert f'value="{ids["domain"]}" selected' in page.text
        assert "DMARC-Fehlerquote über der Schwelle" in page.text
        assert 'name="alert_type"' not in page.text

    def test_saving_changes_the_rule_and_is_logged(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        channel = NotificationChannel(organization_id=ids["org"], name="Technik", channel_type="webhook",
                                      config="{}", is_active=True)
        db.add(channel)
        db.commit()
        channel_id = channel.id
        db.close()
        rule_id = _rule(session_factory, ids["org"])
        _login(web, ids["org"])
        response = web.post(f"/alerts/rules/{rule_id}/edit", data={
            **FORM, "name": "Strenger", "threshold": "2,5", "time_window_minutes": "120",
            "cooldown_minutes": "0", "severity": "critical", "domain_id": ids["domain"], "channel_ids": [channel_id],
        })
        assert response.status_code == 303
        rule = _load(session_factory, rule_id)
        assert (rule.name, rule.threshold, rule.time_window_minutes, rule.cooldown_minutes, rule.severity) == \
               ("Strenger", 2.5, 120, 0, "critical")
        assert rule.domain_id == ids["domain"]
        assert json.loads(rule.notification_channel_ids) == [channel_id]
        assert rule.alert_type == "dmarc_fail_rate"
        db = session_factory()
        entry = db.query(AuditLog).filter_by(action="rule.update", resource_id=rule_id).one()
        db.close()
        assert '"threshold": 10' in entry.old_value and '"threshold": 2.5' in entry.new_value

    def test_empty_threshold_falls_back_to_the_default(self, web, session_factory):
        ids = _seed(session_factory)
        rule_id = _rule(session_factory, ids["org"])
        _login(web, ids["org"])
        assert web.post(f"/alerts/rules/{rule_id}/edit", data={**FORM, "threshold": ""}).status_code == 303
        assert _load(session_factory, rule_id).threshold is None

    def test_bad_values_are_explained_and_kept(self, web, session_factory):
        ids = _seed(session_factory)
        rule_id = _rule(session_factory, ids["org"])
        _login(web, ids["org"])
        response = web.post(f"/alerts/rules/{rule_id}/edit", data={**FORM, "name": "Neu", "time_window_minutes": "0"})
        assert response.status_code == 400
        assert "Die Regel wurde nicht gespeichert" in response.text
        assert 'value="Neu"' in response.text
        assert _load(session_factory, rule_id).name == "Fehlerquote"

    def test_type_cannot_be_changed(self, web, session_factory):
        ids = _seed(session_factory)
        rule_id = _rule(session_factory, ids["org"])
        _login(web, ids["org"])
        web.post(f"/alerts/rules/{rule_id}/edit", data={**FORM, "alert_type": "volume_spike"})
        assert _load(session_factory, rule_id).alert_type == "dmarc_fail_rate"

    def test_create_error_keeps_the_input(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/alerts/rules/new", data={**FORM, "alert_type": "volume_spike", "name": "Spitze",
                                                       "threshold": "viel"})
        assert response.status_code == 400
        assert 'value="Spitze"' in response.text
        assert '<option value="volume_spike" selected>' in response.text


class TestDelete:
    def test_rule_goes_and_its_alarms_stay(self, web, session_factory):
        ids = _seed(session_factory)
        rule_id = _rule(session_factory, ids["org"])
        db = session_factory()
        db.add(AlertEvent(organization_id=ids["org"], rule_id=rule_id, alert_type="dmarc_fail_rate",
                          severity="warning", title="12 % scheitern", status="open"))
        db.commit()
        db.close()
        _login(web, ids["org"])
        assert web.post(f"/alerts/rules/{rule_id}/delete").status_code == 303
        assert _load(session_factory, rule_id) is None
        db = session_factory()
        event = db.query(AlertEvent).filter_by(title="12 % scheitern").one()
        logged = db.query(AuditLog).filter_by(action="rule.delete", resource_id=rule_id).count()
        db.close()
        assert event.rule_id is None
        assert logged == 1
        assert "Regel gelöscht" in web.get("/alerts/rules").text


class TestPermissions:
    def test_analyst_may_neither_edit_nor_delete(self, web, session_factory):
        ids = _seed(session_factory, role="analyst", superadmin=False)
        rule_id = _rule(session_factory, ids["org"])
        _login(web, ids["org"])
        assert web.get(f"/alerts/rules/{rule_id}/edit").status_code == 403
        assert web.post(f"/alerts/rules/{rule_id}/edit", data=FORM).status_code == 403
        assert web.post(f"/alerts/rules/{rule_id}/delete").status_code == 403
        assert _load(session_factory, rule_id) is not None
        assert "/edit" not in web.get("/alerts/rules").text

    def test_manager_may_edit_and_delete(self, web, session_factory):
        ids = _seed(session_factory, role="manager", superadmin=False)
        rule_id = _rule(session_factory, ids["org"])
        _login(web, ids["org"])
        assert f"/alerts/rules/{rule_id}/edit" in web.get("/alerts/rules").text
        assert web.post(f"/alerts/rules/{rule_id}/edit", data={**FORM, "name": "Neu"}).status_code == 303
        assert web.post(f"/alerts/rules/{rule_id}/delete").status_code == 303

    def test_operator_types_stay_with_the_operator(self, web, session_factory):
        ids = _seed(session_factory, role="org_admin", superadmin=False)
        rule_id = _rule(session_factory, ids["org"], alert_type="smtp_rate_limit")
        _login(web, ids["org"])
        assert web.get(f"/alerts/rules/{rule_id}/edit").status_code == 403
        assert web.post(f"/alerts/rules/{rule_id}/delete").status_code == 403
        assert f"/alerts/rules/{rule_id}/edit" not in web.get("/alerts/rules").text

    def test_operator_may_edit_operator_types(self, web, session_factory):
        ids = _seed(session_factory)
        rule_id = _rule(session_factory, ids["org"], alert_type="smtp_rate_limit")
        _login(web, ids["org"])
        assert web.post(f"/alerts/rules/{rule_id}/edit", data={**FORM, "name": "Grenze"}).status_code == 303
        assert _load(session_factory, rule_id).name == "Grenze"

    def test_rules_of_another_organisation_are_not_found(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        other = Organization(name="Fremd", slug="fremd", is_active=True)
        db.add(other)
        db.commit()
        other_id = other.id
        db.close()
        rule_id = _rule(session_factory, other_id)
        _login(web, ids["org"])
        assert web.get(f"/alerts/rules/{rule_id}/edit").status_code == 404
        assert web.post(f"/alerts/rules/{rule_id}/edit", data={**FORM, "name": "Gekapert"}).status_code == 404
        assert web.post(f"/alerts/rules/{rule_id}/delete").status_code == 404
        assert _load(session_factory, rule_id).name == "Fehlerquote"
