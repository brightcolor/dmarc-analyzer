"""Recommendations for pct (RFC 7489), t (RFC 9989) and configurable thresholds."""
import pytest

from app.config import settings
from app.models import DmarcRecord, DmarcReport, InboundMailAddress
from app.services.recommendation import get_recommendations_for_domain


def _codes(db, org, domain) -> set[str]:
    return {r.code for r in get_recommendations_for_domain(db, org.id, domain.id)}


def _add_traffic(db, org, domain, passed: int, failed: int) -> None:
    report = DmarcReport(organization_id=org.id, domain_id=domain.id, report_id=f"r-{passed}-{failed}",
                         total_messages=passed + failed)
    db.add(report)
    db.flush()
    for count, ok in ((passed, True), (failed, False)):
        if count:
            db.add(DmarcRecord(report_id=report.id, organization_id=org.id, domain_id=domain.id,
                               source_ip="192.0.2.1" if ok else "198.51.100.1", count=count,
                               disposition="none", dmarc_pass=ok, spf_aligned=ok, dkim_aligned=ok))
    db.flush()


@pytest.fixture
def address(db, org):
    db.add(InboundMailAddress(organization_id=org.id, address="org-abc@reports.example.org", token="abc",
                              status="active", purpose="org_report"))
    db.flush()


class TestPolicyTags:
    def test_pct_zero_without_testing_warns(self, db, org, domain, address):
        domain.dmarc_policy, domain.dmarc_policy_pct = "reject", 0
        assert "PCT_ZERO_WITHOUT_TESTING" in _codes(db, org, domain)

    def test_pct_zero_with_testing_is_fine(self, db, org, domain, address):
        domain.dmarc_policy, domain.dmarc_policy_pct, domain.dmarc_policy_testing = "reject", 0, "y"
        codes = _codes(db, org, domain)
        assert "PCT_ZERO_WITHOUT_TESTING" not in codes
        assert "TESTING_MODE" in codes

    def test_partial_pct(self, db, org, domain, address):
        domain.dmarc_policy, domain.dmarc_policy_pct = "quarantine", 50
        recs = get_recommendations_for_domain(db, org.id, domain.id)
        partial = next(r for r in recs if r.code == "PCT_PARTIAL")
        assert "RFC 9989" in partial.description

    def test_pct_irrelevant_with_policy_none(self, db, org, domain, address):
        domain.dmarc_policy, domain.dmarc_policy_pct = "none", 0
        assert not {"PCT_ZERO_WITHOUT_TESTING", "PCT_PARTIAL"} & _codes(db, org, domain)

    def test_full_pct_gives_no_hint(self, db, org, domain, address):
        domain.dmarc_policy, domain.dmarc_policy_pct = "reject", 100
        assert not {"PCT_ZERO_WITHOUT_TESTING", "PCT_PARTIAL"} & _codes(db, org, domain)


class TestThresholdsFromSettings:
    def test_ready_for_quarantine_uses_setting(self, db, org, domain, address, monkeypatch):
        domain.dmarc_policy = "none"
        _add_traffic(db, org, domain, passed=90, failed=10)
        assert "READY_FOR_QUARANTINE" not in _codes(db, org, domain)
        monkeypatch.setattr(settings, "RECOMMENDATION_QUARANTINE_PASS_RATE", 85.0)
        assert "READY_FOR_QUARANTINE" in _codes(db, org, domain)

    def test_minimum_messages_uses_setting(self, db, org, domain, address, monkeypatch):
        domain.dmarc_policy = "none"
        _add_traffic(db, org, domain, passed=50, failed=0)
        assert "READY_FOR_QUARANTINE" not in _codes(db, org, domain)
        monkeypatch.setattr(settings, "RECOMMENDATION_MIN_MESSAGES", 40)
        assert "READY_FOR_QUARANTINE" in _codes(db, org, domain)

    def test_high_fail_rate_uses_setting(self, db, org, domain, address, monkeypatch):
        _add_traffic(db, org, domain, passed=85, failed=15)
        assert "HIGH_FAIL_RATE" not in _codes(db, org, domain)
        monkeypatch.setattr(settings, "RECOMMENDATION_HIGH_FAIL_RATE", 10.0)
        assert "HIGH_FAIL_RATE" in _codes(db, org, domain)

    def test_texts_are_german(self, db, org, domain):
        recs = get_recommendations_for_domain(db, org.id, domain.id)
        titles = {r.code: r.title for r in recs}
        assert titles["NO_INBOUND_ADDRESS"] == "Keine aktive Berichtsadresse"
        assert titles["NO_REPORTS_EVER"] == "Noch keine DMARC-Berichte empfangen"
