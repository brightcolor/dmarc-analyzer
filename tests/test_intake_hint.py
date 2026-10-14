"""The intake page says where its values come from, because they cannot be changed there."""
from tests.test_web import _login, _seed


def test_operator_is_pointed_to_the_env(web, session_factory):
    _login(web, _seed(session_factory)["org"])
    page = web.get("/smtp/status").text
    assert "<code>.env</code>" in page and "--force-recreate" in page


def test_members_learn_who_sets_the_values(web, session_factory):
    _login(web, _seed(session_factory, role="org_admin", superadmin=False)["org"])
    page = web.get("/smtp/status").text
    assert "legt der Betreiber in der Serverkonfiguration fest" in page
    assert ".env" not in page
