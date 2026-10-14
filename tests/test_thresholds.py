"""Thresholds per organisation: the .env as default, own values on top, kept apart between organisations."""
import re

import pytest

from app.config import settings
from app.models import AppSettings, AuditLog, Organization
from app.services.org_settings import (
    KEY_PREFIX,
    THRESHOLDS,
    ThresholdError,
    plain_number,
    save_thresholds,
    thresholds_for,
)
from tests.test_recommendations import _add_traffic, _codes, address  # noqa: F401 - shared fixture
from tests.test_web import _login, _seed

EMPTY = {t.name: "" for t in THRESHOLDS}


def _other_org(db) -> Organization:
    other = Organization(name="Fremd", slug="fremd", is_active=True)
    db.add(other)
    db.flush()
    return other


class TestValues:
    def test_without_own_values_the_env_applies(self, db, org):
        limits = thresholds_for(db, org.id)
        assert all(getattr(limits, t.name) == getattr(settings, t.name) for t in THRESHOLDS)

    def test_own_values_win_and_stay_in_their_organisation(self, db, org):
        other = _other_org(db)
        save_thresholds(db, org.id, {**EMPTY, "RECOMMENDATION_MIN_MESSAGES": "40", "UI_PASS_RATE_GOOD": "97,5"})
        db.flush()
        assert thresholds_for(db, org.id).RECOMMENDATION_MIN_MESSAGES == 40
        assert thresholds_for(db, org.id).UI_PASS_RATE_GOOD == 97.5
        assert thresholds_for(db, other.id).RECOMMENDATION_MIN_MESSAGES == settings.RECOMMENDATION_MIN_MESSAGES

    def test_empty_field_returns_to_the_env(self, db, org):
        save_thresholds(db, org.id, {**EMPTY, "RECOMMENDATION_WINDOW_DAYS": "14"})
        db.flush()
        changes = save_thresholds(db, org.id, EMPTY)
        db.flush()
        assert changes == {"RECOMMENDATION_WINDOW_DAYS": (14, None)}
        assert db.query(AppSettings).filter_by(organization_id=org.id).count() == 0
        assert thresholds_for(db, org.id).RECOMMENDATION_WINDOW_DAYS == settings.RECOMMENDATION_WINDOW_DAYS

    def test_unchanged_values_report_no_change(self, db, org):
        save_thresholds(db, org.id, {**EMPTY, "RECOMMENDATION_WINDOW_DAYS": "14"})
        db.flush()
        assert save_thresholds(db, org.id, {**EMPTY, "RECOMMENDATION_WINDOW_DAYS": "14"}) == {}

    @pytest.mark.parametrize("name, raw, message", [
        ("UI_PASS_RATE_GOOD", "101", "erlaubt sind 0 bis 100 %"),
        ("RECOMMENDATION_MIN_MESSAGES", "12,5", "ganze Zahl"),
        ("RECOMMENDATION_WINDOW_DAYS", "viele", "keine gültige Angabe"),
        ("RECOMMENDATION_SPF_ONLY_SHARE", "nan", "erlaubt sind"),
    ])
    def test_bad_values_are_explained(self, db, org, name, raw, message):
        with pytest.raises(ThresholdError, match=message):
            save_thresholds(db, org.id, {**EMPTY, name: raw})
        assert db.query(AppSettings).filter_by(organization_id=org.id).count() == 0

    def test_yellow_may_not_lie_above_green(self, db, org):
        with pytest.raises(ThresholdError, match="Gelb ab darf nicht über Grün ab"):
            save_thresholds(db, org.id, {**EMPTY, "UI_PASS_RATE_WARN": "98"})

    def test_quarantine_may_not_lie_above_reject(self, db, org):
        with pytest.raises(ThresholdError, match="p=quarantine empfehlen ab darf nicht über"):
            save_thresholds(db, org.id, {**EMPTY, "RECOMMENDATION_QUARANTINE_PASS_RATE": "99,5"})

    def test_unreadable_stored_value_falls_back(self, db, org):
        db.add(AppSettings(key=KEY_PREFIX + "RECOMMENDATION_MIN_MESSAGES", value="kaputt", organization_id=org.id))
        db.flush()
        assert thresholds_for(db, org.id).RECOMMENDATION_MIN_MESSAGES == settings.RECOMMENDATION_MIN_MESSAGES

    @pytest.mark.parametrize("value, text", [(None, ""), (95.0, "95"), (12.5, "12.5"), (10_000_000, "10000000")])
    def test_numbers_for_forms(self, value, text):
        assert plain_number(value) == text


class TestRecommendationsUseThem:
    def test_quarantine_threshold_of_the_organisation(self, db, org, domain, address):  # noqa: F811
        domain.dmarc_policy = "none"
        _add_traffic(db, org, domain, passed=90, failed=10)
        assert "READY_FOR_QUARANTINE" not in _codes(db, org, domain)
        save_thresholds(db, org.id, {**EMPTY, "RECOMMENDATION_QUARANTINE_PASS_RATE": "85"})
        db.flush()
        assert "READY_FOR_QUARANTINE" in _codes(db, org, domain)

    def test_high_fail_rate_of_the_organisation(self, db, org, domain, address):  # noqa: F811
        _add_traffic(db, org, domain, passed=85, failed=15)
        assert "HIGH_FAIL_RATE" not in _codes(db, org, domain)
        save_thresholds(db, org.id, {**EMPTY, "RECOMMENDATION_HIGH_FAIL_RATE": "10"})
        db.flush()
        assert "HIGH_FAIL_RATE" in _codes(db, org, domain)


class TestPage:
    def test_admin_saves_and_it_is_logged(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        page = web.get("/settings/thresholds")
        assert page.status_code == 200
        assert f'placeholder="{plain_number(settings.UI_PASS_RATE_GOOD)}"' in page.text
        response = web.post("/settings/thresholds", data={**EMPTY, "RECOMMENDATION_MIN_MESSAGES": "40"})
        assert response.status_code == 303
        assert 'value="40"' in web.get("/settings/thresholds").text
        db = session_factory()
        assert thresholds_for(db, ids["org"]).RECOMMENDATION_MIN_MESSAGES == 40
        entry = db.query(AuditLog).filter_by(action="thresholds.update").one()
        db.close()
        assert '"RECOMMENDATION_MIN_MESSAGES": 40' in entry.new_value

    def test_errors_keep_the_input(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/settings/thresholds", data={**EMPTY, "UI_PASS_RATE_WARN": "98",
                                                          "RECOMMENDATION_WINDOW_DAYS": "14"})
        assert response.status_code == 400
        assert "Die Schwellen wurden nicht gespeichert" in response.text
        assert 'value="14"' in response.text

    def test_manager_may_look_but_not_change(self, web, session_factory):
        ids = _seed(session_factory, role="manager", superadmin=False)
        _login(web, ids["org"])
        page = web.get("/settings/thresholds")
        assert page.status_code == 200
        assert " disabled" in page.text
        assert "dürfen Administratoren" in page.text
        assert web.post("/settings/thresholds", data={**EMPTY, "RECOMMENDATION_MIN_MESSAGES": "40"}
                        ).status_code == 403
        db = session_factory()
        assert db.query(AppSettings).filter(AppSettings.key.startswith(KEY_PREFIX)).count() == 0
        db.close()

    @pytest.mark.parametrize("good, warn, state", [("", "", "warn"), ("0", "0", "on"), ("100", "100", "bad")])
    def test_traffic_light_follows_the_organisation(self, web, session_factory, good, warn, state):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        web.post("/settings/thresholds", data={**EMPTY, "UI_PASS_RATE_GOOD": good, "UI_PASS_RATE_WARN": warn})
        rows = web.get("/reports").text.split("<tbody>", 1)[1].split("</tbody>")[0]
        # The seeded reports pass at 77.8 % and 76.9 %
        assert set(re.findall(r"bc-state--(on|warn|bad)\">\d", rows)) == {state}
