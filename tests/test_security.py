"""Security: client address behind proxies, foreign forms, login lock, notification targets, roles, input limits."""
import logging
import socket
import time
from datetime import timedelta

import pytest
from starlette.requests import Request

from app.config import settings
from app.dependencies import get_client_ip
from app.models import AlertEvent, LoginAttempt, Organization, PlanDefinition, SourceIp, User
from app.routers import auth, users
from app.services import notification
from app.services.auth import create_api_token
from app.services.login_guard import locked_until, record_attempt
from app.services.notification import ChannelError, build_channel_config, dispatch_pending, target_problem
from app.services.retention import run_retention
from tests.helpers import NOW, make_channel, make_org
from tests.test_web import PASSWORD, _login, _seed


def _request(peer: str, forwarded: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers, "client": (peer, 1234)})


class TestClientAddress:
    def test_forwarded_header_counts_only_from_trusted_proxies(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXIES", "")
        assert get_client_ip(_request("198.51.100.7", "203.0.113.9")) == "198.51.100.7"
        monkeypatch.setattr(settings, "TRUSTED_PROXIES", "127.0.0.1, 10.0.0.0/8")
        assert get_client_ip(_request("198.51.100.7", "203.0.113.9")) == "198.51.100.7"

    def test_chain_is_read_from_the_right(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXIES", "127.0.0.1, 10.0.0.0/8")
        # The client wrote 1.2.3.4 itself; the proxies added the real address and their own
        assert get_client_ip(_request("127.0.0.1", "1.2.3.4, 203.0.113.9, 10.1.2.3")) == "203.0.113.9"

    def test_only_proxies_in_the_chain(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXIES", "127.0.0.0/8")
        assert get_client_ip(_request("127.0.0.1", "127.0.0.2")) == "127.0.0.2"


class TestForeignForms:
    def _rule(self, web, **headers):
        return web.post("/alerts/rules/new", headers=headers, data={
            "name": "", "alert_type": "new_unknown_source", "domain_id": "", "threshold": "",
            "time_window_minutes": "60", "cooldown_minutes": "60", "severity": "warning",
        })

    def test_foreign_origin_is_refused(self, web, session_factory):
        _login(web, _seed(session_factory)["org"])
        response = self._rule(web, Origin="https://evil.example")
        assert response.status_code == 403
        assert "von einer fremden Seite (evil.example)" in response.text

    def test_foreign_referer_and_null_origin_are_refused(self, web, session_factory):
        _login(web, _seed(session_factory)["org"])
        assert self._rule(web, Referer="https://evil.example/seite").status_code == 403
        assert self._rule(web, Origin="null").status_code == 403

    def test_own_origin_and_trusted_origins_pass(self, web, session_factory, monkeypatch):
        _login(web, _seed(session_factory)["org"])
        assert self._rule(web, Origin="http://testserver").status_code == 303
        monkeypatch.setattr(settings, "CSRF_TRUSTED_ORIGINS", "https://dmarc.example.com")
        assert self._rule(web, Origin="https://dmarc.example.com").status_code == 303

    def test_api_is_not_affected(self, web):
        assert web.post("/api/v1/alerts/events/x/acknowledge", headers={"Origin": "https://evil.example"}
                        ).status_code == 401


class TestLoginLock:
    def test_account_lock_and_reset(self, session, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_ACCOUNT", 3)
        monkeypatch.setattr(settings, "LOGIN_LOCKOUT_SECONDS", 600)
        for minute in range(3):
            assert locked_until(session, "login", "203.0.113.1", "chefin@example.test", NOW) is None
            record_attempt(session, "login", f"203.0.113.{minute}", "chefin@example.test", False,
                           NOW - timedelta(minutes=3 - minute))
        until = locked_until(session, "login", "203.0.113.9", "chefin@example.test", NOW)
        assert until is not None and until.replace(tzinfo=NOW.tzinfo) == NOW - timedelta(minutes=1, seconds=-600)
        assert locked_until(session, "login", "203.0.113.9", "chefin@example.test", NOW + timedelta(minutes=10)) \
            is None
        assert locked_until(session, "login", "203.0.113.9", "andere@example.test", NOW) is None

    def test_ip_lock(self, session, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 2)
        for account in ("a@example.test", "b@example.test"):
            record_attempt(session, "login", "203.0.113.5", account, False, NOW - timedelta(seconds=30))
        assert locked_until(session, "login", "203.0.113.5", "c@example.test", NOW) is not None
        assert locked_until(session, "setup", "203.0.113.5", None, NOW) is None

    def test_success_starts_the_count_anew(self, session, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_ACCOUNT", 2)
        record_attempt(session, "login", "203.0.113.1", "chefin@example.test", False, NOW - timedelta(minutes=5))
        record_attempt(session, "login", "203.0.113.1", "chefin@example.test", True, NOW - timedelta(minutes=4))
        record_attempt(session, "login", "203.0.113.1", "chefin@example.test", False, NOW - timedelta(minutes=3))
        assert locked_until(session, "login", "203.0.113.1", "chefin@example.test", NOW) is None

    def test_old_failures_do_not_count(self, session, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_ACCOUNT", 1)
        monkeypatch.setattr(settings, "LOGIN_FAILURE_WINDOW_SECONDS", 300)
        record_attempt(session, "login", "203.0.113.1", "chefin@example.test", False, NOW - timedelta(minutes=6))
        assert locked_until(session, "login", "203.0.113.1", "chefin@example.test", NOW) is None

    def test_login_page_locks(self, web, session_factory, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_ACCOUNT", 2)
        _seed(session_factory)
        for _ in range(2):
            web.post("/auth/login", data={"email": "admin@example.test", "password": "falsch"})
        response = web.post("/auth/login", data={"email": "admin@example.test", "password": PASSWORD})
        assert response.headers["location"] == "/auth/login"
        page = web.get("/auth/login")
        assert "Anmeldung bis" in page.text and "gesperrt" in page.text
        db = session_factory()
        assert db.query(LoginAttempt).filter_by(success=False).count() == 2
        db.close()

    def test_setup_code_locks(self, web, session_factory, monkeypatch):
        from app.services.setup import ensure_setup_code
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 2)
        db = session_factory()
        ensure_setup_code(db)
        db.close()
        form = {"setup_code": "AAAA-BBBB-CCCC", "email": "chefin@example.test", "full_name": "Erika Muster",
                "org_name": "Muster Farben", "password": PASSWORD, "password_confirm": PASSWORD}
        assert web.post("/auth/setup", data=form).status_code == 400
        assert web.post("/auth/setup", data=form).status_code == 400
        response = web.post("/auth/setup", data=form)
        assert response.status_code == 429
        assert "zu oft falsch eingegeben" in response.text

    def test_retention_removes_old_attempts(self, session, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_ATTEMPT_RETENTION_DAYS", 7)
        record_attempt(session, "login", "203.0.113.1", "a@example.test", False, NOW - timedelta(days=8))
        record_attempt(session, "login", "203.0.113.1", "a@example.test", False, NOW - timedelta(days=6))
        assert run_retention(session, NOW).login_attempts == 1
        assert session.query(LoginAttempt).count() == 1


@pytest.fixture
def resolve(monkeypatch):
    """Fake DNS for notification targets: host → address."""
    table: dict[str, str] = {}

    def getaddrinfo(host, port, *args, **kwargs):
        if host not in table:
            raise socket.gaierror("unknown")
        family = socket.AF_INET6 if ":" in table[host] else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (table[host], port))]

    monkeypatch.setattr(notification.socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(settings, "NOTIFICATION_BLOCK_PRIVATE_TARGETS", True)
    return table


class TestNotificationTargets:
    @pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "192.168.1.5", "169.254.169.254", "100.64.0.1",
                                         "::1", "fd00::5", "::ffff:10.0.0.1"])
    def test_internal_addresses_are_refused(self, resolve, address):
        resolve["hooks.example.test"] = address
        problem = target_problem("https://hooks.example.test/x")
        assert problem and "interne Adresse" in problem

    def test_public_address_and_allowed_hosts(self, resolve, monkeypatch):
        resolve["hooks.example.test"] = "93.184.215.14"
        assert target_problem("https://hooks.example.test/x") is None
        resolve["ntfy.lan"] = "192.168.1.9"
        assert target_problem("http://ntfy.lan/alarme") is not None
        monkeypatch.setattr(settings, "NOTIFICATION_ALLOWED_INTERNAL_HOSTS", "ntfy.lan")
        assert target_problem("http://ntfy.lan/alarme") is None

    def test_ip_literal_and_unknown_name(self, resolve):
        assert "127.0.0.1 ist eine interne Adresse" in target_problem("http://127.0.0.1:8000/")
        assert "lässt sich nicht auflösen" in target_problem("https://unbekannt.example.test/")

    def test_channel_form_refuses_internal_targets(self, resolve):
        resolve["intern.example.test"] = "10.0.0.8"
        with pytest.raises(ChannelError, match="interne Adresse"):
            build_channel_config("webhook", url="http://intern.example.test/hook")

    def test_target_is_checked_again_before_sending(self, session, resolve):
        org = make_org(session)
        make_channel(session, org, "webhook", {"url": "https://hooks.example.test/x"})
        from app.services.alert_service import create_system_alert
        create_system_alert(session, org_id=org.id, alert_type="import_failed", title="Test")
        resolve["hooks.example.test"] = "127.0.0.1"
        assert dispatch_pending(session, NOW)["failed"] == 1
        delivery = session.query(notification.NotificationDelivery).one()
        assert "interne Adresse 127.0.0.1" in delivery.error_message

    def test_switched_off(self, resolve, monkeypatch):
        monkeypatch.setattr(settings, "NOTIFICATION_BLOCK_PRIVATE_TARGETS", False)
        assert target_problem("http://127.0.0.1/") is None


class TestAddressChecks:
    """Mail address patterns of setup, invitation, channels, digest and domain recipients."""

    PATTERNS = [auth.EMAIL_RE, users.EMAIL_RE, notification.EMAIL_PATTERN]

    @pytest.mark.parametrize("pattern", PATTERNS)
    @pytest.mark.parametrize("address", ["name@example.org", "vor.nach+dmarc@mail.example.co.uk",
                                         "info@müller-druck.example"])
    def test_usual_addresses_pass(self, pattern, address):
        assert pattern.match(address)

    @pytest.mark.parametrize("pattern", PATTERNS)
    @pytest.mark.parametrize("address", ["kein-at-zeichen", "name@example", "name@example..org",
                                         "name@.example.org", "name@example.org.", "a@b@example.org",
                                         "na me@example.org"])
    def test_malformed_addresses_fail(self, pattern, address):
        assert not pattern.match(address)

    @pytest.mark.parametrize("pattern", PATTERNS)
    def test_crafted_long_input_stays_linear(self, pattern):
        # CodeQL py/polynomial-redos: overlapping classes backtracked quadratically on this input
        crafted = "!@!." + "!." * 50_000 + "@"
        started = time.perf_counter()
        assert not pattern.match(crafted)
        assert time.perf_counter() - started < 1


class TestOversizedForms:
    """Starlette limits every form, also without file upload; the refusal names the reason in German."""

    @pytest.mark.parametrize("data", [
        {f"feld{i}": "x" for i in range(1001)},
        {"email": "x" * (1024 * 1024 + 1)},
    ], ids=["too-many-fields", "entry-too-long"])
    def test_refusal_is_explained(self, web, data, caplog):
        caplog.set_level(logging.INFO, logger="app.main")
        response = web.post("/auth/setup", data=data)
        assert response.status_code == 400
        assert "Das Formular hat zu viele Felder oder Dateien" in response.text
        assert "Too many fields" not in response.text and "exceeded maximum size" not in response.text
        assert "Form refused: " in caplog.text

    def test_json_clients_get_the_same_reason(self, web):
        response = web.post("/auth/setup", data={f"feld{i}": "x" for i in range(1001)},
                            headers={"Accept": "application/json"})
        assert response.status_code == 400
        assert response.json()["detail"].startswith("Das Formular hat zu viele Felder oder Dateien")


class TestRoles:
    def _source(self, session_factory, org_id):
        db = session_factory()
        source_id = db.query(SourceIp).filter_by(organization_id=org_id).first().id
        event_id = db.query(AlertEvent).filter_by(organization_id=org_id).first().id
        db.close()
        return source_id, event_id

    def test_read_only_may_look_but_not_change(self, web, session_factory):
        ids = _seed(session_factory, role="read_only", superadmin=False)
        _login(web, ids["org"])
        source_id, event_id = self._source(session_factory, ids["org"])
        refused = [
            web.post("/upload", files={"file": ("r.xml", b"<feedback/>", "application/xml")}),
            web.post(f"/source-ips/{source_id}/classify", data={"classification": "trusted"}),
            web.post("/senders/google/decide", data={"decision": "trusted"}),
            web.post(f"/alerts/events/{event_id}/acknowledge"),
            web.post("/alerts/rules/new", data={"name": "x", "alert_type": "new_unknown_source"}),
            web.post("/domains/new", data={"name": "example.net"}),
        ]
        assert [r.status_code for r in refused] == [403] * len(refused)
        assert "mindestens die Rolle Analyst" in refused[0].text
        assert "ab der Rolle Analyst" in web.get("/upload").text
        assert "ab der Rolle Manager" in web.get("/alerts/rules").text
        assert web.get("/dashboard").status_code == 200

    def test_analyst_handles_sources_but_not_rules(self, web, session_factory):
        ids = _seed(session_factory, role="analyst", superadmin=False)
        _login(web, ids["org"])
        source_id, event_id = self._source(session_factory, ids["org"])
        assert web.post(f"/source-ips/{source_id}/classify", data={"classification": "trusted"}).status_code == 303
        assert web.post(f"/alerts/events/{event_id}/acknowledge").status_code == 303
        assert web.post("/alerts/rules/new", data={"name": "x", "alert_type": "new_unknown_source"}
                        ).status_code == 403
        assert "mindestens die Rolle Manager" in web.post("/domains/new", data={"name": "example.net"}).text

    def test_manager_handles_rules_but_not_channels(self, web, session_factory):
        ids = _seed(session_factory, role="manager", superadmin=False)
        _login(web, ids["org"])
        assert web.post("/alerts/rules/new", data={
            "name": "x", "alert_type": "new_unknown_source", "domain_id": "", "threshold": "",
            "time_window_minutes": "60", "cooldown_minutes": "60", "severity": "warning",
        }).status_code == 303
        assert web.post("/alerts/channels/new", data={"channel_type": "webhook", "url": "https://x.example"}
                        ).status_code == 403

    def test_api_token_of_read_only_user(self, web, session_factory):
        ids = _seed(session_factory, role="read_only", superadmin=False)
        db = session_factory()
        user = db.query(User).filter_by(email="admin@example.test").one()
        raw, _ = create_api_token(db, ids["org"], user.id, "Lesen")
        event_id = db.query(AlertEvent).filter_by(organization_id=ids["org"]).first().id
        db.commit()
        db.close()
        response = web.post(f"/api/v1/alerts/events/{event_id}/acknowledge",
                            headers={"Authorization": f"Bearer {raw}"})
        assert response.status_code == 403
        assert "Lesezugriff" in response.json()["detail"]


def test_default_plan_comes_from_the_settings(session, monkeypatch):
    import app.database
    from app.main import _create_default_plan

    monkeypatch.setattr(app.database, "SessionLocal", session.info["factory"])
    monkeypatch.setattr(settings, "DEFAULT_PLAN_MAX_DOMAINS", 7)
    monkeypatch.setattr(settings, "DEFAULT_PLAN_REPORT_RETENTION_DAYS", 90)
    _create_default_plan()
    plan = session.query(PlanDefinition).filter_by(slug="default").one()
    assert (plan.max_domains, plan.report_retention_days) == (7, 90)
    assert session.query(Organization).count() == 0
