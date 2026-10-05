"""Web interface: first-run setup, login, permissions, error pages and every page rendering."""
import pytest
from fastapi.testclient import TestClient

from app.models import (
    AlertEvent,
    AppSettings,
    Domain,
    DomainRecipient,
    ImportJob,
    NotificationChannel,
    Organization,
    OrganizationMembership,
    SourceIp,
    User,
)
from app.services.auth import create_user
from app.services.dmarc_parser import parse_xml_bytes
from app.services.import_service import store_parsed_report
from app.services.setup import SETUP_CODE_KEY, ensure_setup_code
from tests.conftest import DMARCBIS_XML, SAMPLE_DMARC_XML

PASSWORD = "Testpasswort-2026"


def _seed(session_factory, role: str = "org_admin", superadmin: bool = True) -> dict:
    db = session_factory()
    org = Organization(name="Muster Farben", slug="muster-farben", is_active=True)
    db.add(org)
    db.flush()
    admin = create_user(db, "admin@example.test", PASSWORD, full_name="Max Mustermann", is_superadmin=superadmin)
    db.add(OrganizationMembership(user_id=admin.id, organization_id=org.id, role=role))
    if not superadmin:
        # An operator exists, so the first-run setup is closed
        create_user(db, "betrieb@example.test", PASSWORD, full_name="Betrieb", is_superadmin=True)
    job = ImportJob(organization_id=org.id, source="web_upload", status="completed", file_name="report.xml")
    db.add(job)
    db.flush()
    classic = store_parsed_report(db, parse_xml_bytes(SAMPLE_DMARC_XML), org.id, job.id)
    bis = store_parsed_report(db, parse_xml_bytes(DMARCBIS_XML), org.id, job.id)
    db.add(AlertEvent(organization_id=org.id, alert_type="new_unknown_source", severity="warning",
                      title="Neue Quelle", status="open"))
    db.commit()
    ids = {
        "org": org.id, "job": job.id, "classic": classic.id, "bis": bis.id,
        "domain": db.query(Domain).filter_by(organization_id=org.id).first().id,
        "source": db.query(SourceIp).filter_by(organization_id=org.id).first().id,
    }
    db.close()
    return ids


def _login(client: TestClient, org_id: str, email: str = "admin@example.test") -> None:
    response = client.post("/auth/login", data={"email": email, "password": PASSWORD})
    assert response.status_code == 303
    client.post("/organizations/select", data={"org_id": org_id})


class TestFirstRunSetup:
    def test_every_page_leads_to_setup(self, web):
        response = web.get("/dashboard")
        assert response.status_code == 303
        assert response.headers["location"] == "/auth/setup"

    def test_health_and_static_stay_reachable(self, web):
        assert web.get("/api/v1/health").status_code == 200
        assert web.get("/static/css/app.css").status_code == 200

    def test_fonts_and_logos_have_their_media_type(self, web):
        assert web.get("/static/bc/fonts/anton-400.woff2").headers["content-type"] == "font/woff2"
        assert web.get("/static/bc/logo/bc-mark.svg").headers["content-type"].startswith("image/svg+xml")

    def test_setup_page_asks_for_code(self, web):
        page = web.get("/auth/setup")
        assert page.status_code == 200
        assert "Einrichtungscode" in page.text

    def test_wrong_code_is_refused(self, web, session_factory):
        db = session_factory()
        ensure_setup_code(db)
        db.close()
        response = web.post("/auth/setup", data={
            "setup_code": "AAAA-BBBB-CCCC", "email": "chefin@example.test", "full_name": "Erika Muster",
            "org_name": "Muster Farben", "password": PASSWORD, "password_confirm": PASSWORD,
        })
        assert response.status_code == 400
        assert "Einrichtungscode stimmt nicht" in response.text
        db = session_factory()
        assert db.query(User).count() == 0
        db.close()

    def test_correct_code_creates_admin_and_closes_setup(self, web, session_factory):
        db = session_factory()
        code = ensure_setup_code(db)
        db.close()
        response = web.post("/auth/setup", data={
            "setup_code": code.lower().replace("-", " "), "email": "Chefin@Example.test",
            "full_name": "Erika Muster", "org_name": "Müller Druck", "password": PASSWORD,
            "password_confirm": PASSWORD,
        })
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        assert web.get("/dashboard").status_code == 200

        db = session_factory()
        admin = db.query(User).one()
        assert admin.is_superadmin and admin.email == "chefin@example.test"
        assert db.query(Organization).one().slug == "mueller-druck"
        assert db.query(AppSettings).filter_by(key=SETUP_CODE_KEY).count() == 0
        db.close()
        assert web.get("/auth/setup").status_code == 404

    def test_short_password_keeps_code(self, web, session_factory):
        db = session_factory()
        code = ensure_setup_code(db)
        db.close()
        response = web.post("/auth/setup", data={
            "setup_code": code, "email": "chefin@example.test", "org_name": "Muster Farben",
            "password": "kurz", "password_confirm": "kurz",
        })
        assert response.status_code == 400
        assert "zu kurz" in response.text
        db = session_factory()
        assert db.query(AppSettings).filter_by(key=SETUP_CODE_KEY).count() == 1
        db.close()


class TestLogin:
    def test_wrong_password_is_explained(self, web, session_factory):
        _seed(session_factory)
        response = web.post("/auth/login", data={"email": "admin@example.test", "password": "falsch"})
        assert response.headers["location"] == "/auth/login"
        assert "stimmen nicht" in web.get("/auth/login").text

    def test_next_parameter_stays_inside_the_app(self, web, session_factory):
        _seed(session_factory)
        response = web.post("/auth/login", data={"email": "admin@example.test", "password": PASSWORD,
                                                 "next": "https://example.net/phish"})
        assert response.headers["location"] == "/dashboard"

    def test_next_parameter_with_local_path(self, web, session_factory):
        _seed(session_factory)
        response = web.post("/auth/login", data={"email": "admin@example.test", "password": PASSWORD,
                                                 "next": "/reports"})
        assert response.headers["location"] == "/reports"

    @pytest.mark.parametrize("target", ["https://example.net/x", "//example.net/x", "/\\example.net/x",
                                        "reports", ""],
                             ids=["absolute", "protocol-relative", "backslash", "without-slash", "empty"])
    def test_next_target_outside_the_app_leads_to_the_dashboard(self, web, session_factory, target):
        _seed(session_factory)
        response = web.post("/auth/login", data={"email": "admin@example.test", "password": PASSWORD,
                                                 "next": target})
        assert response.headers["location"] == "/dashboard"

    def test_login_form_carries_only_paths_inside_the_app(self, web, session_factory):
        _seed(session_factory)
        assert 'name="next" value="/reports?format=rfc9990"' in web.get(
            "/auth/login", params={"next": "/reports?format=rfc9990"}).text
        assert 'name="next" value="/dashboard"' in web.get("/auth/login", params={"next": "//example.net/x"}).text


class TestBackToTheEntry:
    """After a change the browser returns to the page of the entry it changed."""

    def test_domain_actions_return_to_the_domain(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        page = f"/domains/{ids['domain']}"
        assert web.post(f"{page}/add-address").headers["location"] == page
        added = web.post(f"{page}/recipients", data={"email": "team@example.test", "alerts": "1"})
        assert added.headers["location"] == f"{page}#empfaenger"
        refused = web.post(f"{page}/recipients", data={"email": "kein-at", "alerts": "1"})
        assert refused.headers["location"] == f"{page}#empfaenger"
        db = session_factory()
        recipient_id = db.query(DomainRecipient).one().id
        db.close()
        changed = web.post(f"{page}/recipients/{recipient_id}", data={"alerts": "1", "digest": "1"})
        assert changed.headers["location"] == f"{page}#empfaenger"
        assert web.post(f"{page}/recipients/{recipient_id}/delete").headers["location"] == f"{page}#empfaenger"
        assert web.post(f"{page}/toggle").headers["location"] == page

    def test_source_classification_returns_to_the_source(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post(f"/source-ips/{ids['source']}/classify", data={"classification": "trusted"})
        assert response.status_code == 303
        assert response.headers["location"] == f"/source-ips/{ids['source']}"

    @pytest.mark.parametrize("path", ["/domains/unbekannt/toggle", "/domains/unbekannt/add-address",
                                      "/domains/unbekannt/recipients", "/source-ips/unbekannt/classify"])
    def test_unknown_entry_ends_with_404(self, web, session_factory, path):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post(path, data={"email": "team@example.test", "classification": "trusted"})
        assert response.status_code == 404
        assert "location" not in response.headers


class TestPages:
    def test_every_page_renders(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        pages = [
            "/dashboard", "/domains", f"/domains/{ids['domain']}", "/domains/new", "/reports",
            "/reports?format=rfc9990", f"/reports/{ids['classic']}", f"/reports/{ids['bis']}", "/upload",
            "/imports", f"/imports/{ids['job']}", "/smtp/status", "/smtp/messages", "/smtp/rejections",
            "/source-ips", f"/source-ips/{ids['source']}", "/alerts/events", "/alerts/rules", "/alerts/channels",
            "/alerts/digest", "/alerts/digest/preview", "/senders", "/source-ips?sender=none",
            "/users", "/users/invite", "/api-tokens", "/organizations", f"/organizations/{ids['org']}",
            "/organizations/new", "/organizations/select", "/hilfe/dmarc-formate", "/failure-reports",
            "/tls-reports",
        ]
        for path in pages:
            response = web.get(path)
            assert response.status_code == 200, f"{path}: {response.status_code}"
            assert 'lang="de"' in response.text

    def test_report_pages_name_their_format(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        assert "RFC 9990" in web.get(f"/reports/{ids['bis']}").text
        classic = web.get(f"/reports/{ids['classic']}").text
        assert "RFC 7489" in classic
        assert "Der Bericht enthält pct" in classic

    def test_format_filter(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        listing = web.get("/reports?format=rfc9990").text
        assert "bis-report-001" not in listing  # the list shows domains, not ids
        assert listing.count("app-format--rfc9990") >= 1
        assert "app-format--rfc7489" not in listing.split("<tbody>")[1]

    def test_unknown_page_is_german(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.get("/reports/does-not-exist")
        assert response.status_code == 404
        assert "Seite nicht gefunden" in response.text

    def test_api_errors_stay_json(self, web, session_factory):
        _seed(session_factory)
        response = web.get("/api/v1/reports")
        assert response.status_code == 401
        assert response.headers["content-type"].startswith("application/json")


class TestPermissions:
    def test_analyst_cannot_invite(self, web, session_factory):
        ids = _seed(session_factory, role="analyst", superadmin=False)
        _login(web, ids["org"])
        response = web.get("/users/invite")
        assert response.status_code == 403
        assert "nur Administratoren" in response.text

    def test_analyst_cannot_create_tokens(self, web, session_factory):
        ids = _seed(session_factory, role="analyst", superadmin=False)
        _login(web, ids["org"])
        assert web.post("/api-tokens/new", data={"name": "x"}).status_code == 403

    def test_only_operator_sees_rejections(self, web, session_factory):
        ids = _seed(session_factory, role="org_admin", superadmin=False)
        _login(web, ids["org"])
        assert web.get("/smtp/rejections").status_code == 403
        assert "Abgelehnte Empfänger" not in web.get("/dashboard").text

    def test_org_admin_can_invite(self, web, session_factory):
        ids = _seed(session_factory, role="org_admin", superadmin=False)
        _login(web, ids["org"])
        response = web.post("/users/invite", data={"email": "neu@example.test", "password": PASSWORD,
                                                   "role": "analyst"})
        assert response.status_code == 303

    def test_invite_checks_password_rules(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/users/invite", data={"email": "neu@example.test", "password": "kurz",
                                                   "role": "analyst"})
        assert response.status_code == 400
        assert "zu kurz" in response.text


class TestUpload:
    def test_file_name_cannot_leave_the_upload_folder(self, web, session_factory, tmp_path, monkeypatch):
        from app.config import settings
        monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path / "uploads"))
        ids = _seed(session_factory)
        _login(web, ids["org"])
        xml = SAMPLE_DMARC_XML.replace(b"test-report-001", b"upload-001")
        response = web.post("/upload", files={"file": ("../../../escape.xml", xml, "application/xml")})
        assert response.status_code == 303
        stored = list((tmp_path / "uploads").rglob("*.xml"))
        assert len(stored) == 1
        assert stored[0].parent == tmp_path / "uploads" / ids["org"]
        assert not (tmp_path / "escape.xml").exists()

    def test_wrong_file_type_is_explained(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/upload", files={"file": ("bericht.pdf", b"%PDF", "application/pdf")})
        assert response.status_code == 400
        assert "Dateiart" in response.text

    def test_foreign_domain_is_refused(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/upload", data={"domain_id": "fremd"},
                            files={"file": ("r.xml", SAMPLE_DMARC_XML, "application/xml")})
        assert response.status_code == 400
        assert "gehört nicht" in response.text


class TestForms:
    def test_rule_without_threshold(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/alerts/rules/new", data={
            "name": "", "alert_type": "new_unknown_source", "domain_id": "", "threshold": "",
            "time_window_minutes": "60", "cooldown_minutes": "60", "severity": "warning",
        })
        assert response.status_code == 303

    def test_channel_with_bad_topic_is_explained(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/alerts/channels/new", data={"name": "ntfy", "channel_type": "ntfy",
                                                          "topic": "mit leerzeichen"})
        assert response.status_code == 400
        assert "darf nur Buchstaben, Ziffern" in response.text

    def test_mail_channel_needs_valid_addresses(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/alerts/channels/new", data={"name": "Team", "channel_type": "email",
                                                          "recipients": "technik@example.test\nkeine-adresse"})
        assert response.status_code == 400
        assert "keine-adresse" in response.text
        response = web.post("/alerts/channels/new", data={"name": "Team", "channel_type": "email",
                                                          "recipients": "technik@example.test"})
        assert response.status_code == 303
        page = web.get("/alerts/channels")
        assert "technik@example.test" in page.text
        assert "Kanal angelegt" in page.text

    def test_channel_test_button(self, web, session_factory, monkeypatch):
        import httpx

        from app.services import notification

        sent = []
        real_client = httpx.Client
        monkeypatch.setattr(notification.httpx, "Client", lambda **kw: real_client(
            transport=httpx.MockTransport(lambda request: sent.append(request) or httpx.Response(200)), **kw))
        ids = _seed(session_factory)
        _login(web, ids["org"])
        web.post("/alerts/channels/new", data={"name": "Hook", "channel_type": "webhook",
                                               "url": "https://hooks.example.test/dmarc"})
        db = session_factory()
        channel_id = db.query(NotificationChannel).one().id
        db.close()
        web.post(f"/alerts/channels/{channel_id}/test")
        assert "Testnachricht verschickt" in web.get("/alerts/channels").text
        assert "Testnachricht" in sent[0].content.decode("utf-8")


class TestAlertsAfterImport:
    def test_upload_checks_the_rules(self, web, session_factory, tmp_path, monkeypatch):
        from app.config import settings
        monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path / "uploads"))
        ids = _seed(session_factory)
        _login(web, ids["org"])
        web.post("/alerts/rules/new", data={
            "name": "Neue Quellen", "alert_type": "new_unknown_source", "domain_id": "", "threshold": "",
            "time_window_minutes": "60", "cooldown_minutes": "0", "severity": "warning",
        })
        xml = SAMPLE_DMARC_XML.replace(b"test-report-001", b"upload-002").replace(b"198.51.100.5", b"198.51.100.77")
        assert web.post("/upload", files={"file": ("neu.xml", xml, "application/xml")}).status_code == 303
        db = session_factory()
        events = db.query(AlertEvent).filter(AlertEvent.rule_id.isnot(None)).all()
        db.close()
        # The seeded sources are new as well, all within the last hour
        assert "198.51.100.77" in {e.source_ip for e in events}
        assert len(events) == len({e.source_ip for e in events})


class TestEmptyFields:
    def test_empty_domain_name_gets_the_routes_message(self, web, session_factory):
        _login(web, _seed(session_factory)["org"])
        response = web.post("/domains/new", data={"name": ""})
        assert response.status_code == 400
        assert "kein gültiger Domainname" in response.text

    def test_note_can_be_cleared(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        web.post(f"/source-ips/{ids['source']}/classify", data={"classification": "trusted", "notes": "Newsletter"})
        web.post(f"/source-ips/{ids['source']}/classify", data={"classification": "trusted", "notes": ""})
        db = session_factory()
        assert db.get(SourceIp, ids["source"]).notes is None
        db.close()
