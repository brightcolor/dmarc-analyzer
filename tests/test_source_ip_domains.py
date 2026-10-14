"""IP address list: the domains each address sent for, and the filter by domain."""
import pytest

from app.config import settings
from app.models import Domain, Organization
from tests.helpers import NOW, add_report, add_source, make_domain, make_org
from tests.test_web import _login, _seed


@pytest.fixture
def shared_ip(web, session_factory):
    """One address that sent for four domains, one for a single domain, one without a domain."""
    ids = _seed(session_factory)
    db = session_factory()
    org = db.get(Organization, ids["org"])
    names = ("alpha.example", "beta.example", "gamma.example", "delta.example")
    domains = [make_domain(db, org, name) for name in names]
    add_source(db, org, "198.51.100.1", total=8)
    add_source(db, org, "198.51.100.2", total=2)
    add_source(db, org, "198.51.100.3", total=1)
    for domain in domains:
        add_report(db, org, domain, [("198.51.100.1", 2, True, True, True)], created_at=NOW)
    add_report(db, org, domains[0], [("198.51.100.2", 2, True, True, True)], created_at=NOW)
    add_report(db, org, None, [("198.51.100.3", 1, False, False, False)], created_at=NOW)
    db.commit()
    db.close()
    _login(web, ids["org"])
    return ids


def _row(page_text: str, ip: str) -> str:
    start = page_text.index(f">{ip}<")
    return page_text[start:page_text.index("</tr>", start)]


class TestDomainColumn:
    def test_domains_of_an_address_are_named(self, web, shared_ip):
        page = web.get("/source-ips")
        assert page.status_code == 200
        row = _row(page.text, "198.51.100.2")
        assert 'href="/source-ips?domain=alpha.example"' in row

    def test_more_domains_than_shown_are_counted(self, web, shared_ip, monkeypatch):
        monkeypatch.setattr(settings, "UI_SOURCE_DOMAINS_SHOWN", 3)
        row = _row(web.get("/source-ips").text, "198.51.100.1")
        # sorted by name: alpha, beta, delta are shown, gamma is counted
        assert "alpha.example" in row and "beta.example" in row and "delta.example" in row
        assert "gamma.example</a>" not in row
        assert ">+1<" in row
        assert 'title="gamma.example"' in row

    def test_other_limit_from_the_settings(self, web, shared_ip, monkeypatch):
        monkeypatch.setattr(settings, "UI_SOURCE_DOMAINS_SHOWN", 1)
        row = _row(web.get("/source-ips").text, "198.51.100.1")
        assert ">+3<" in row
        monkeypatch.setattr(settings, "UI_SOURCE_DOMAINS_SHOWN", 4)
        assert ">+" not in _row(web.get("/source-ips").text, "198.51.100.1")

    def test_address_without_a_domain_shows_a_dash(self, web, shared_ip):
        assert "—" in _row(web.get("/source-ips").text, "198.51.100.3")


class TestDomainFilter:
    def test_filter_keeps_the_addresses_of_the_domain(self, web, shared_ip):
        page = web.get("/source-ips?domain=beta.example").text
        assert ">198.51.100.1<" in page
        assert ">198.51.100.2<" not in page
        assert ">198.51.100.3<" not in page

    def test_filter_lists_the_domains_of_the_organisation(self, web, shared_ip):
        page = web.get("/source-ips").text
        for name in ("alpha.example", "beta.example", "gamma.example", "delta.example"):
            assert f'<option value="{name}"' in page

    def test_selected_domain_and_reset(self, web, shared_ip):
        page = web.get("/source-ips?domain=alpha.example").text
        assert '<option value="alpha.example" selected>' in page
        assert "Filter zurücksetzen" in page

    def test_unknown_domain_is_ignored(self, web, shared_ip):
        page = web.get("/source-ips?domain=gibt-es-nicht.example")
        assert page.status_code == 200
        assert ">198.51.100.1<" in page.text and ">198.51.100.3<" in page.text

    def test_other_organisation_is_not_visible(self, web, shared_ip, session_factory):
        db = session_factory()
        other = make_org(db, "Fremd", "fremd")
        foreign = make_domain(db, other, "fremd.example")
        add_source(db, other, "203.0.113.9", total=4)
        add_report(db, other, foreign, [("203.0.113.9", 4, True, True, True)], created_at=NOW)
        db.commit()
        assert db.query(Domain).filter_by(name="fremd.example").count() == 1
        db.close()
        page = web.get("/source-ips").text
        assert "fremd.example" not in page and "203.0.113.9" not in page
        assert "203.0.113.9" not in web.get("/source-ips?domain=fremd.example").text
