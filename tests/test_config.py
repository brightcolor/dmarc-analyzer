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


@pytest.mark.parametrize(("value", "reason"), [
    ("", "braucht mindestens ein Ziel"),
    (" , ", "braucht mindestens ein Ziel"),
    ("ftp://127.0.0.1/", "'ftp://127.0.0.1/' ist kein Ziel der Prüfung"),
    ("http:///api/v1/health", "'http:///api/v1/health' ist kein Ziel der Prüfung"),
    ("smtp://127.0.0.1:70000", "'smtp://127.0.0.1:70000' hat keinen gültigen Port"),
    ("smtp://127.0.0.1:0", "'smtp://127.0.0.1:0' hat keinen gültigen Port"),
])
def test_healthcheck_targets_are_checked(monkeypatch, value, reason):
    monkeypatch.setenv("HEALTHCHECK_TARGETS", value)
    with pytest.raises(SystemExit) as exc:
        load_settings()
    assert f"HEALTHCHECK_TARGETS: {reason}" in str(exc.value)


def test_healthcheck_with_own_values(monkeypatch):
    monkeypatch.setenv("HEALTHCHECK_TARGETS", " https://dmarc.example.test/api/v1/health , smtp://[::1]:25 ,")
    monkeypatch.setenv("HEALTHCHECK_TIMEOUT_SECONDS", "1.5")
    loaded = load_settings()
    assert loaded.healthcheck_targets == ["https://dmarc.example.test/api/v1/health", "smtp://[::1]:25"]
    assert loaded.HEALTHCHECK_TIMEOUT_SECONDS == 1.5


def test_healthcheck_time_limit_has_bounds(monkeypatch):
    monkeypatch.setenv("HEALTHCHECK_TIMEOUT_SECONDS", "60")
    with pytest.raises(SystemExit) as exc:
        load_settings()
    assert "HEALTHCHECK_TIMEOUT_SECONDS: darf höchstens 30" in str(exc.value)
