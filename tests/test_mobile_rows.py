"""Report file names as two lines: receiver on top, domain and reported day below."""
import pytest

from app.models import ImportJob
from app.templates_config import report_file_parts
from tests.test_web import _login, _seed


@pytest.mark.parametrize(("name", "host", "domain", "period"), [
    ("google.com!example.org!1790553600!1790639999.zip", "google.com", "example.org", "28.09.2026"),
    ("enterprise.protection.outlook.com!example.org!1790467200!1790553600.xml.gz",
     "enterprise.protection.outlook.com", "example.org", "27.09.2026"),
    ("Mail.ru!example.org!1790553600!1790639999!abc123.xml", "Mail.ru", "example.org", "28.09.2026"),
    ("mx.example.net!example.org!1790380800!1790553599.xml", "mx.example.net", "example.org", "26.09. – 27.09.2026"),
])
def test_report_file_names(name, host, domain, period):
    assert report_file_parts(name) == {"host": host, "domain": domain, "period": period}


@pytest.mark.parametrize("name", [None, "", "report.xml", "a!b!c!d.zip", "../google.com!x!1790553600!1790639999.zip"])
def test_other_names_stay_as_they_are(name):
    assert report_file_parts(name) is None


def test_dashboard_and_imports_show_two_lines(web, session_factory):
    ids = _seed(session_factory)
    db = session_factory()
    db.add(ImportJob(organization_id=ids["org"], source="web_upload", status="completed",
                     file_name="google.com!example.org!1790553600!1790639999.zip"))
    db.commit()
    db.close()
    _login(web, ids["org"])
    for path in ("/dashboard", "/imports"):
        page = web.get(path).text
        assert '<a class="bc-row-title" href="/imports/' in page
        assert ">google.com</a>" in page
        assert "example.org · 28.09.2026" in page
        assert 'class="bc-only-narrow"' in page


def test_every_list_has_two_lines_on_phones():
    """Each list table puts its title in the first cell and hides the other columns on phones."""
    from pathlib import Path

    templates = Path(__file__).resolve().parent.parent / "app" / "templates"
    missing = []
    for path in sorted(templates.rglob("*.html")):
        name = path.relative_to(templates).as_posix()
        for table in path.read_text(encoding="utf-8").split('<table class="bc-table"')[1:]:
            table = table.split("</table>")[0]
            # Shares compare three short values side by side and fit a phone as they are
            if "Anteil als Balken" in table:
                continue
            titled = "bc-row-title" in table or "ui.report_file(" in table
            if "bc-hide-narrow" not in table or not titled:
                missing.append(name)
    assert missing == []
