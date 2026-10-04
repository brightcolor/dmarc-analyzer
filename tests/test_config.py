"""Invalid settings stop the start with a readable German message."""
import pytest

from app.config import load_settings


def test_out_of_range_value_is_explained(monkeypatch):
    monkeypatch.setenv("DMARC_MAX_RECORDS_PER_REPORT", "5")
    with pytest.raises(SystemExit) as exc:
        load_settings()
    message = str(exc.value)
    assert "DMARC_MAX_RECORDS_PER_REPORT: muss mindestens 100 sein" in message
    assert "korrigieren" in message


def test_non_numeric_value_is_explained(monkeypatch):
    monkeypatch.setenv("RECOMMENDATION_WINDOW_DAYS", "dreißig")
    with pytest.raises(SystemExit) as exc:
        load_settings()
    assert "RECOMMENDATION_WINDOW_DAYS: muss eine ganze Zahl sein" in str(exc.value)


def test_valid_values_load(monkeypatch):
    monkeypatch.setenv("RECOMMENDATION_WINDOW_DAYS", "14")
    assert load_settings().RECOMMENDATION_WINDOW_DAYS == 14


@pytest.mark.parametrize(("value", "reason"), [
    ("resolved,erledigt", "unbekannter Status 'erledigt'"),
    ("open,resolved", "open würde jede Benachrichtigung verhindern"),
])
def test_alert_statuses_to_skip_are_checked(monkeypatch, value, reason):
    monkeypatch.setenv("NOTIFICATION_SKIP_ALERT_STATUSES", value)
    with pytest.raises(SystemExit) as exc:
        load_settings()
    assert f"NOTIFICATION_SKIP_ALERT_STATUSES: {reason}" in str(exc.value)


def test_alert_statuses_to_skip_ignore_case_and_spaces(monkeypatch):
    monkeypatch.setenv("NOTIFICATION_SKIP_ALERT_STATUSES", " Resolved, acknowledged ,")
    assert load_settings().notification_skip_alert_statuses == {"resolved", "acknowledged"}
