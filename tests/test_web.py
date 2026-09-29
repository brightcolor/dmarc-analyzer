"""Web interface: first-run setup, login, permissions, error pages and every page rendering."""
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import get_db
from app.main import app
from app.models import (
    AlertEvent,
    AppSettings,
    Base,
    Domain,
    ImportJob,
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


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine)
    engine.dispose()


@pytest.fixture
def web(session_factory):
    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.setup_done = False
    with TestClient(app, follow_redirects=False) as client:
        client.app.state.setup_done = False
        yield client
    app.dependency_overrides.clear()
    app.state.setup_done = False


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


class TestPages:
    def test_every_page_renders(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        pages = [
            "/dashboard", "/domains", f"/domains/{ids['domain']}", "/domains/new", "/reports",
            "/reports?format=rfc9990", f"/reports/{ids['classic']}", f"/reports/{ids['bis']}", "/upload",
            "/imports", f"/imports/{ids['job']}", "/smtp/status", "/smtp/messages", "/smtp/rejections",
            "/source-ips", f"/source-ips/{ids['source']}", "/alerts/events", "/alerts/rules", "/alerts/channels",
            "/users", "/users/invite", "/api-tokens", "/organizations", f"/organizations/{ids['org']}",
            "/organizations/new", "/organizations/select", "/hilfe/dmarc-formate",
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

    def test_channel_with_broken_json_is_explained(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        response = web.post("/alerts/channels/new", data={"name": "ntfy", "channel_type": "ntfy",
                                                          "config_json": "{url: kaputt"})
        assert response.status_code == 400
        assert re.search(r"kein gültiges JSON \(Zeile \d+", response.text)
