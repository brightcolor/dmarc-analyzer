"""Account page: name, e-mail address and password of the signed-in user."""
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.dependencies import session_is_current
from app.main import app
from app.migrate import run_migrations
from app.models import AuditLog, User
from app.security import verify_password
from app.services.auth import create_user
from tests.test_web import PASSWORD, _login, _seed

NEW_PASSWORD = "Ganz-Neues-Passwort-77"


def _user(session_factory, email="admin@example.test"):
    db = session_factory()
    try:
        user = db.query(User).filter_by(email=email).one()
        db.expunge(user)
        return user
    finally:
        db.close()


def _actions(session_factory, action):
    db = session_factory()
    try:
        return db.query(AuditLog).filter_by(action=action).all()
    finally:
        db.close()


@pytest.fixture
def signed_in(web, session_factory):
    ids = _seed(session_factory)
    _login(web, ids["org"])
    return ids


class TestPage:
    def test_anonymous_visitors_are_sent_to_the_login(self, web, session_factory):
        _seed(session_factory)
        response = web.get("/account")
        assert response.status_code == 303 and response.headers["location"] == "/auth/login"
        assert web.post("/account/password", data={"password": "x"}).status_code == 303

    def test_page_shows_the_account_and_the_menu_links_to_it(self, web, signed_in):
        page = web.get("/account")
        assert page.status_code == 200
        assert 'value="admin@example.test"' in page.text and 'value="Max Mustermann"' in page.text
        assert 'action="/account/password"' in page.text
        assert 'href="/account"' in web.get("/dashboard").text


class TestProfile:
    def test_name_changes_without_password(self, web, signed_in, session_factory):
        response = web.post("/account/profile", data={"full_name": "  Maxi   Muster ", "email": "admin@example.test"})
        assert response.status_code == 303
        assert _user(session_factory).full_name == "Maxi Muster"
        assert "Name gespeichert" in web.get("/account").text
        assert len(_actions(session_factory, "user.name_change")) == 1

    def test_empty_name_falls_back_to_the_address(self, web, signed_in, session_factory):
        web.post("/account/profile", data={"full_name": "", "email": "admin@example.test"})
        assert _user(session_factory).full_name is None

    def test_nothing_changed_is_said(self, web, signed_in):
        web.post("/account/profile", data={"full_name": "Max Mustermann", "email": "ADMIN@example.test "})
        assert "Nichts geändert" in web.get("/account").text

    def test_new_address_needs_the_current_password(self, web, signed_in, session_factory):
        response = web.post("/account/profile", data={"full_name": "Max", "email": "neu@example.test",
                                                      "current_password": ""})
        assert response.status_code == 400
        assert "Das aktuelle Passwort stimmt nicht" in response.text
        assert 'value="neu@example.test"' in response.text
        assert _user(session_factory).email == "admin@example.test"
        assert _user(session_factory).full_name == "Max Mustermann"

    def test_wrong_password_is_refused(self, web, signed_in, session_factory):
        response = web.post("/account/profile", data={"full_name": "Max", "email": "neu@example.test",
                                                      "current_password": "falsch"})
        assert response.status_code == 400
        assert _user(session_factory).email == "admin@example.test"

    def test_new_address_with_the_right_password(self, web, signed_in, session_factory):
        response = web.post("/account/profile", data={"full_name": "Max Mustermann", "email": " Neu@Example.test ",
                                                      "current_password": PASSWORD})
        assert response.status_code == 303
        assert _user(session_factory, "neu@example.test").full_name == "Max Mustermann"
        assert "E-Mail-Adresse geändert" in web.get("/account").text
        entry = _actions(session_factory, "user.email_change")[0]
        assert "admin@example.test" in entry.old_value and "neu@example.test" in entry.new_value
        web.get("/auth/logout")
        assert web.post("/auth/login", data={"email": "neu@example.test", "password": PASSWORD}
                        ).headers["location"] == "/dashboard"
        web.get("/auth/logout")
        assert web.post("/auth/login", data={"email": "admin@example.test", "password": PASSWORD}
                        ).headers["location"] == "/auth/login"

    @pytest.mark.parametrize("address", ["kein-at-zeichen", "a@b", "a b@example.test", "x" * 250 + "@example.test"])
    def test_invalid_address_is_explained(self, web, signed_in, address):
        response = web.post("/account/profile", data={"full_name": "Max", "email": address,
                                                      "current_password": PASSWORD})
        assert response.status_code == 400
        assert "keine gültige E-Mail-Adresse" in response.text

    def test_taken_address_is_refused(self, web, signed_in, session_factory):
        db = session_factory()
        create_user(db, "zweite@example.test", PASSWORD)
        db.commit()
        db.close()
        response = web.post("/account/profile", data={"full_name": "Max", "email": "zweite@example.test",
                                                      "current_password": PASSWORD})
        assert response.status_code == 400
        assert "gehört schon zu einem anderen Konto" in response.text

    def test_name_too_long_is_explained(self, web, signed_in):
        response = web.post("/account/profile", data={"full_name": "N" * 300, "email": "admin@example.test"})
        assert response.status_code == 400
        assert "Der Name ist zu lang" in response.text


class TestPassword:
    def _change(self, web, current=PASSWORD, new=NEW_PASSWORD, repeat=None):
        return web.post("/account/password", data={"current_password": current, "password": new,
                                                   "password_confirm": new if repeat is None else repeat})

    def test_change_keeps_this_session_and_works_for_the_next_login(self, web, signed_in, session_factory):
        response = self._change(web)
        assert response.status_code == 303 and response.headers["location"] == "/account"
        assert web.get("/account").status_code == 200
        user = _user(session_factory)
        assert verify_password(NEW_PASSWORD, user.password_hash) and user.credentials_changed_at is not None
        web.get("/auth/logout")
        assert web.post("/auth/login", data={"email": "admin@example.test", "password": PASSWORD}
                        ).headers["location"] == "/auth/login"
        assert web.post("/auth/login", data={"email": "admin@example.test", "password": NEW_PASSWORD}
                        ).headers["location"] == "/dashboard"

    def test_confirmation_is_shown_once(self, web, signed_in):
        self._change(web)
        assert "Alle anderen angemeldeten Geräte sind abgemeldet" in web.get("/account").text

    def test_other_sessions_end(self, web, signed_in):
        with TestClient(app, follow_redirects=False) as other:
            other.post("/auth/login", data={"email": "admin@example.test", "password": PASSWORD})
            assert other.get("/account").status_code == 200
            assert self._change(web).status_code == 303
            gone = other.get("/account")
            assert gone.status_code == 303 and gone.headers["location"] == "/auth/login"
            assert web.get("/account").status_code == 200

    def test_audit_entry_holds_no_password(self, web, signed_in, session_factory):
        self._change(web)
        entry = _actions(session_factory, "user.password_change")[0]
        assert NEW_PASSWORD not in f"{entry.old_value}{entry.new_value}"
        assert PASSWORD not in f"{entry.old_value}{entry.new_value}"

    @pytest.mark.parametrize(("kwargs", "reason"), [
        ({"current": "falsch"}, "Das aktuelle Passwort stimmt nicht"),
        ({"repeat": "anders"}, "stimmen nicht überein"),
        ({"new": "kurz", "repeat": "kurz"}, "zu kurz"),
        ({"new": PASSWORD, "repeat": PASSWORD}, "dasselbe wie das aktuelle"),
    ])
    def test_refusals_are_explained(self, web, signed_in, session_factory, kwargs, reason):
        response = self._change(web, **kwargs)
        assert response.status_code == 400 and reason in response.text
        assert verify_password(PASSWORD, _user(session_factory).password_hash)
        assert _user(session_factory).credentials_changed_at is None

    def test_wrong_passwords_lock_the_change(self, web, signed_in, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_ACCOUNT", 2)
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 50)
        assert self._change(web, current="falsch1").status_code == 400
        assert self._change(web, current="falsch2").status_code == 400
        locked = self._change(web)
        assert locked.status_code == 400
        assert "Zu viele falsche Passwörter" in locked.text and "Uhr gesperrt" in locked.text
        refused = web.post("/account/profile", data={"full_name": "Max", "email": "neu@example.test",
                                                     "current_password": PASSWORD})
        assert "Zu viele falsche Passwörter" in refused.text

    def test_password_rules_come_from_the_settings(self, web, signed_in, monkeypatch):
        monkeypatch.setattr(settings, "PASSWORD_MIN_LENGTH", 20)
        response = self._change(web, new="Zwölf-Zeichen", repeat="Zwölf-Zeichen")
        assert response.status_code == 400 and "mindestens 20 Zeichen" in response.text


class TestSessionCheck:
    def _user(self, changed):
        user = User(email="a@example.test", password_hash="x")
        user.credentials_changed_at = changed
        return user

    def test_sessions_before_any_change_stay_valid(self):
        assert session_is_current(self._user(None), {"user_id": "u"})

    def test_session_without_a_stamp_ends_after_a_change(self):
        assert not session_is_current(self._user(datetime.now(UTC)), {"user_id": "u"})

    def test_older_session_ends_newer_stays(self):
        changed = datetime.now(UTC)
        assert not session_is_current(self._user(changed), {"iat": (changed - timedelta(seconds=5)).timestamp()})
        assert session_is_current(self._user(changed), {"iat": changed.timestamp()})
        assert session_is_current(self._user(changed), {"iat": (changed + timedelta(seconds=5)).timestamp()})

    def test_database_without_time_zone_counts_as_utc(self):
        changed = datetime.now(UTC).replace(tzinfo=None)
        assert session_is_current(self._user(changed), {"iat": changed.replace(tzinfo=UTC).timestamp()})

    def test_stamp_of_the_wrong_type_ends_the_session(self):
        assert not session_is_current(self._user(datetime.now(UTC)), {"iat": "gestern"})


def test_migration_adds_the_column():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    run_migrations(engine)
    assert "credentials_changed_at" in {c["name"] for c in inspect(engine).get_columns("users")}
    engine.dispose()
