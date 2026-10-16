"""IP address list, domain list and overview: where mail fails, how each domain fares, what needs a look."""
from datetime import timedelta

import pytest

from app.config import settings
from app.models import AlertEvent, DmarcRecord, DmarcReport, Domain, Organization, SourceIp
from app.services.alert_service import raise_event
from tests.helpers import NOW, add_report, add_source, make_domain
from tests.test_web import _login, _seed


@pytest.fixture
def org_data(web, session_factory):
    """The organisation of the web tests, emptied of reports, sources and domains, with a signed-in admin."""
    ids = _seed(session_factory)
    db = session_factory()
    for model in (AlertEvent, DmarcRecord, DmarcReport, SourceIp, Domain):
        db.query(model).filter_by(organization_id=ids["org"]).delete()
    db.commit()
    org = db.get(Organization, ids["org"])
    yield db, org
    db.close()


def _login_admin(web, org):
    _login(web, org.id)


def _now():
    from datetime import UTC, datetime

    return datetime.now(UTC)


class TestSourceList:
    def _sources(self, db, org):
        domain = make_domain(db, org, "piste.de")
        db.add(Domain(organization_id=org.id, name="mailware.cc", is_active=True))
        own = add_source(db, org, "198.51.100.1", total=10, failed=5, classification="trusted",
                         reverse_dns="mx.piste.de")
        weak = add_source(db, org, "198.51.100.2", total=10, failed=8, classification="trusted",
                          reverse_dns="mail.hoster.example")
        spoof = add_source(db, org, "198.51.100.3", total=4, failed=4, classification="suspicious")
        for source in (own, weak, spoof):
            source.enriched_at = NOW
        add_report(db, org, domain, [("198.51.100.1", 10, True, True, True), ("198.51.100.2", 10, True, True, True),
                                     ("198.51.100.3", 4, False, False, False)], created_at=_now())
        db.commit()
        return own, weak, spoof

    def test_own_server_is_named_and_unassigned_stays_unassigned(self, web, org_data):
        db, org = org_data
        self._sources(db, org)
        _login_admin(web, org)
        page = web.get("/source-ips").text
        own_row = page[page.index(">198.51.100.1<"):page.index(">198.51.100.2<")]
        weak_row = page[page.index(">198.51.100.2<"):page.index(">198.51.100.3<")]
        assert "Eigener Server" in own_row and "Eigener Server" not in weak_row
        assert "nicht zugeordnet" in weak_row

    def test_warning_chip_only_for_trusted_sources_below_the_threshold(self, web, org_data, monkeypatch):
        db, org = org_data
        own, weak, spoof = self._sources(db, org)
        _login_admin(web, org)
        monkeypatch.setattr(settings, "UI_PASS_RATE_WARN", 75.0)
        page = web.get("/source-ips").text
        assert page.count("Fehler prüfen") == 2  # 50 % and 20 % trusted; the forged source is no problem
        monkeypatch.setattr(settings, "UI_PASS_RATE_WARN", 30.0)
        assert web.get("/source-ips").text.count("Fehler prüfen") == 1

    def test_quality_filter_lists_sources_that_may_be_yours(self, web, org_data):
        db, org = org_data
        self._sources(db, org)
        _login_admin(web, org)
        page = web.get("/source-ips?problem=1").text
        assert ">198.51.100.1<" in page and ">198.51.100.2<" in page and ">198.51.100.3<" not in page
        assert '<option value="1" selected>' in page and "Filter zurücksetzen" in page

    def test_domain_names_stay_whole_and_first_seen_is_gone(self, web, org_data):
        db, org = org_data
        self._sources(db, org)
        _login_admin(web, org)
        page = web.get("/source-ips").text
        assert 'class="app-nowrap" href="/source-ips?domain=piste.de"' in page
        assert "Zuerst gesehen" not in page and "Zuletzt gesehen" in page


class TestDomainList:
    def _domains(self, db, org):
        quiet = make_domain(db, org, "aaa-ruhig.example")
        weak = make_domain(db, org, "mmm-schwach.example")
        broken = make_domain(db, org, "zzz-kaputt.example")
        add_report(db, org, quiet, [("198.51.100.1", 20, True, True, True)], created_at=_now())
        add_report(db, org, weak, [("198.51.100.2", 6, True, True, True), ("198.51.100.3", 14, False, False, False)],
                   created_at=_now())
        add_report(db, org, broken, [("198.51.100.4", 5, False, False, False)], created_at=_now())
        old = make_domain(db, org, "nnn-alt.example")
        add_report(db, org, old, [("198.51.100.5", 99, False, False, False)], created_at=_now() - timedelta(days=90))
        raise_event(db, org_id=org.id, alert_type="dmarc_fail_rate", severity="warning", title="x", domain_id=broken.id)
        raise_event(db, org_id=org.id, alert_type="dmarc_fail_rate", severity="warning", title="y", domain_id=broken.id)
        broken.dns_status = "warning"
        old.is_active = False
        db.commit()

    @staticmethod
    def _row(page: str, name: str) -> str:
        start = page.index(f"{name}.example</a>")
        return page[start:page.index("</tr>", start)]

    def _order(self, page: str) -> list[str]:
        names = ["aaa-ruhig", "mmm-schwach", "nnn-alt", "zzz-kaputt"]
        return sorted(names, key=lambda n: page.index(f"{n}.example</a>"))

    def test_problems_come_first(self, web, org_data):
        db, org = org_data
        self._domains(db, org)
        _login_admin(web, org)
        assert self._order(web.get("/domains").text) == ["mmm-schwach", "zzz-kaputt", "aaa-ruhig", "nnn-alt"]

    def test_name_order_on_request(self, web, org_data):
        db, org = org_data
        self._domains(db, org)
        _login_admin(web, org)
        page = web.get("/domains?sort=name").text
        assert self._order(page) == ["aaa-ruhig", "mmm-schwach", "nnn-alt", "zzz-kaputt"]
        assert '<option value="name" selected>' in page and "Suche zurücksetzen" in page

    def test_columns_show_rate_messages_and_open_alerts(self, web, org_data):
        db, org = org_data
        self._domains(db, org)
        _login_admin(web, org)
        page = web.get("/domains").text
        weak = self._row(page, "mmm-schwach")
        assert "30,0 %" in weak and ">20<" in weak
        broken = self._row(page, "zzz-kaputt")
        assert ">2</a>" in broken and "0,0 %" in broken
        assert "Bestehen (30 Tage)" in page and "Offene Alarme" in page

    def test_old_reports_do_not_count_and_inactive_domains_are_marked(self, web, org_data):
        db, org = org_data
        self._domains(db, org)
        _login_admin(web, org)
        page = web.get("/domains").text
        old = self._row(page, "nnn-alt")
        assert "inaktiv" in old and "99" not in old

    def test_window_comes_from_the_settings(self, web, org_data, monkeypatch):
        db, org = org_data
        self._domains(db, org)
        _login_admin(web, org)
        monkeypatch.setattr(settings, "UI_CHART_DAYS", 120)
        page = web.get("/domains").text
        assert "Bestehen (120 Tage)" in page
        assert "99" in self._row(page, "nnn-alt")


class TestOverview:
    def test_failures_are_split_into_forged_and_to_check(self, web, org_data):
        db, org = org_data
        domain = make_domain(db, org, "piste.de")
        add_source(db, org, "198.51.100.1", total=9, failed=9, classification="suspicious")
        own = add_source(db, org, "198.51.100.2", total=4, failed=4, classification="trusted",
                         reverse_dns="mx.piste.de")
        add_report(db, org, domain, [("198.51.100.1", 9, False, False, False), ("198.51.100.2", 4, False, False, False),
                                     ("198.51.100.7", 2, False, False, False)], created_at=_now())
        db.commit()
        _login_admin(web, org)
        page = web.get("/dashboard").text
        assert "Woran die Fehler liegen" in page
        assert "<strong>9</strong> Nachrichten von Quellen, die als verdächtig" in page
        assert "<strong>6</strong> Nachrichten von eigenen, freigegebenen" in page
        assert f'href="/source-ips/{own.id}"' in page and "198.51.100.7" in page
        assert 'href="/source-ips?problem=1"' in page

    def test_no_split_without_failures(self, web, org_data):
        db, org = org_data
        domain = make_domain(db, org, "piste.de")
        add_report(db, org, domain, [("198.51.100.1", 5, True, True, True)], created_at=_now())
        db.commit()
        _login_admin(web, org)
        assert "Woran die Fehler liegen" not in web.get("/dashboard").text

    def test_domains_that_never_reported_are_a_count(self, web, org_data):
        db, org = org_data
        active = make_domain(db, org, "aktiv.example")
        add_report(db, org, active, [("198.51.100.1", 5, True, True, True)], created_at=_now())
        for n in range(3):
            make_domain(db, org, f"nie{n}.example")
        db.commit()
        _login_admin(web, org)
        page = web.get("/dashboard").text
        assert "3 Domains haben noch nie einen Bericht geschickt" in page
        assert "nie0.example" not in page

    def test_domains_that_stopped_reporting_are_listed_up_to_the_limit(self, web, org_data, monkeypatch):
        db, org = org_data
        monkeypatch.setattr(settings, "UI_RECENT_LIMIT", 3)
        for n in range(5):
            domain = make_domain(db, org, f"still{n}.example")
            add_report(db, org, domain, [("198.51.100.1", 1, True, True, True)], created_at=_now() - timedelta(days=40))
            domain.last_report_at = _now() - timedelta(days=40)
        db.commit()
        _login_admin(web, org)
        page = web.get("/dashboard").text
        assert "Domains, die sich nicht mehr melden" in page
        assert page.count(".example</a>") == 3 and "und 2 weitere" in page
