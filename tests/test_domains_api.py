"""Creating domains over the API and the web form, limits per organisation and the operator tool."""
import pytest

from app.config import settings
from app.models import Domain, InboundMailAddress, Organization, User
from app.org_limits import main as org_limits
from app.services.auth import create_api_token
from app.services.domains import normalize_domain
from tests.test_web import _login, _seed


def _token(session_factory, org_id: str) -> str:
    db = session_factory()
    user = db.query(User).filter_by(email="admin@example.test").one()
    raw, _ = create_api_token(db, org_id, user.id, "Automatik")
    db.commit()
    db.close()
    return raw


@pytest.mark.parametrize(("typed", "stored"), [
    ("Example.ORG.", "example.org"),
    ("lübeck-united.de", "xn--lbeck-united-dlb.de"),
    ("xn--lbeck-united-dlb.de", "xn--lbeck-united-dlb.de"),
    ("mail.example.co.uk", "mail.example.co.uk"),
])
def test_names_are_normalized(typed, stored):
    assert normalize_domain(typed) == stored


@pytest.mark.parametrize("typed", ["", "localhost", "-bad.example", "bad_.example", "a..b", "exa mple.org"])
def test_no_domain(typed):
    assert normalize_domain(typed) is None


class TestApi:
    def test_create_and_repeat(self, web, session_factory):
        ids = _seed(session_factory)
        auth = {"Authorization": f"Bearer {_token(session_factory, ids['org'])}"}
        first = web.post("/api/v1/domains", json={"name": "Neu.Example.org"}, headers=auth)
        assert first.status_code == 201
        body = first.json()
        assert body["name"] == "neu.example.org" and body["created"] is True
        assert body["rua"] == f"mailto:{body['inbound_address']}"
        assert body["inbound_address"].endswith("@" + settings.SMTP_INBOUND_DOMAIN)
        again = web.post("/api/v1/domains", json={"name": "neu.example.org"}, headers=auth)
        assert again.status_code == 200
        assert again.json()["inbound_address"] == body["inbound_address"]

    def test_umlauts_and_domains_from_reports(self, web, session_factory):
        ids = _seed(session_factory)
        auth = {"Authorization": f"Bearer {_token(session_factory, ids['org'])}"}
        assert web.post("/api/v1/domains", json={"name": "lübeck-united.de"}, headers=auth).json()["name"] == \
            "xn--lbeck-united-dlb.de"
        # example.com came in with a report and had no address of its own yet
        known = web.post("/api/v1/domains", json={"name": "example.com"}, headers=auth)
        assert known.status_code == 200 and known.json()["inbound_address"].startswith("dom-example-com-")
        db = session_factory()
        domain = db.query(Domain).filter_by(organization_id=ids["org"], name="example.com").one()
        assert db.query(InboundMailAddress).filter_by(domain_id=domain.id).count() == 1
        db.close()

    def test_invalid_name(self, web, session_factory):
        ids = _seed(session_factory)
        auth = {"Authorization": f"Bearer {_token(session_factory, ids['org'])}"}
        response = web.post("/api/v1/domains", json={"name": "kein domain"}, headers=auth)
        assert response.status_code == 400
        assert "kein gültiger Domainname" in response.json()["detail"]

    def test_limit(self, web, session_factory):
        ids = _seed(session_factory)
        db = session_factory()
        org = db.get(Organization, ids["org"])
        org.max_domains = db.query(Domain).filter_by(organization_id=org.id).count()
        db.commit()
        db.close()
        auth = {"Authorization": f"Bearer {_token(session_factory, ids['org'])}"}
        response = web.post("/api/v1/domains", json={"name": "zu-viel.example.org"}, headers=auth)
        assert response.status_code == 409
        assert "python -m app.org_limits muster-farben --max-domains" in response.json()["detail"]

    def test_read_only_token(self, web, session_factory):
        ids = _seed(session_factory, role="read_only", superadmin=False)
        auth = {"Authorization": f"Bearer {_token(session_factory, ids['org'])}"}
        response = web.post("/api/v1/domains", json={"name": "neu.example.org"}, headers=auth)
        assert response.status_code == 403
        assert "ab der Rolle Manager" in response.json()["detail"]

    def test_without_token(self, web):
        assert web.post("/api/v1/domains", json={"name": "neu.example.org"}).status_code == 401


class TestWeb:
    def test_form_converts_umlauts(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        assert web.post("/domains/new", data={"name": "radiolübeck.de"}).status_code == 303
        db = session_factory()
        assert db.query(Domain).filter_by(organization_id=ids["org"], name="xn--radiolbeck-feb.de").count() == 1
        db.close()

    def test_add_address(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        assert web.post(f"/domains/{ids['domain']}/add-address").status_code == 303
        db = session_factory()
        assert db.query(InboundMailAddress).filter_by(domain_id=ids["domain"]).count() == 1
        db.close()


class TestLimits:
    def test_new_organisations_get_the_default_plan(self, web, session_factory, monkeypatch):
        from app.services.setup import ensure_setup_code
        monkeypatch.setattr(settings, "DEFAULT_PLAN_MAX_DOMAINS", 321)
        db = session_factory()
        code = ensure_setup_code(db)
        db.close()
        web.post("/auth/setup", data={
            "setup_code": code, "email": "chefin@example.test", "full_name": "Erika Muster",
            "org_name": "Muster Farben", "password": "Testpasswort-2026", "password_confirm": "Testpasswort-2026",
        })
        db = session_factory()
        assert db.query(Organization).one().max_domains == 321
        db.close()

    def test_operator_tool(self, session, monkeypatch, capsys):
        import app.org_limits as tool
        monkeypatch.setattr(tool, "SessionLocal", session.info["factory"])
        monkeypatch.setattr(tool, "run_migrations", lambda: None)
        session.add(Organization(name="Muster Farben", slug="muster-farben", is_active=True))
        session.commit()
        assert org_limits(["muster-farben", "--max-domains", "500", "--report-retention-days", "730"]) == 0
        assert (session.query(Organization).one().max_domains, session.query(Organization).one().report_retention_days) \
            == (500, 730)
        assert "Domains: 500, genutzt 0" in capsys.readouterr().out
        assert org_limits(["muster-farben", "--max-domains", "0"]) == 2
        assert "Domains muss zwischen 1 und 1000000 liegen" in capsys.readouterr().out
        assert org_limits(["gibt-es-nicht"]) == 2
        assert org_limits([]) == 0
