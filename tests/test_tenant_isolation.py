"""Tests for multi-tenant data isolation — org A must never see org B's data."""
import pytest

from app.models import (
    DmarcRecord,
    DmarcReport,
    Domain,
    ImportJob,
    InboundMailAddress,
    Organization,
    SourceIp,
)
from app.security import generate_inbound_token
from app.services.dmarc_parser import parse_xml_bytes
from app.services.import_service import store_parsed_report
from tests.conftest import SAMPLE_DMARC_XML


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def org_a(db):
    o = Organization(name="Org A", slug="org-a", is_active=True)
    db.add(o)
    db.flush()
    return o


@pytest.fixture
def org_b(db):
    o = Organization(name="Org B", slug="org-b", is_active=True)
    db.add(o)
    db.flush()
    return o


@pytest.fixture
def job_a(db, org_a):
    j = ImportJob(organization_id=org_a.id, source="web_upload", status="pending")
    db.add(j)
    db.flush()
    return j


@pytest.fixture
def job_b(db, org_b):
    j = ImportJob(organization_id=org_b.id, source="web_upload", status="pending")
    db.add(j)
    db.flush()
    return j


@pytest.fixture
def report_a(db, org_a, job_a):
    parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
    report = store_parsed_report(db, parsed, org_a.id, job_a.id)
    db.flush()
    return report


@pytest.fixture
def domain_a(db, org_a):
    d = Domain(organization_id=org_a.id, name="a.example.com", is_active=True)
    db.add(d)
    db.flush()
    return d


@pytest.fixture
def domain_b(db, org_b):
    d = Domain(organization_id=org_b.id, name="b.example.com", is_active=True)
    db.add(d)
    db.flush()
    return d


# ── Reports ────────────────────────────────────────────────────────────────────

class TestReportIsolation:
    def test_org_b_cannot_see_org_a_reports(self, db, org_b, report_a):
        reports = db.query(DmarcReport).filter_by(organization_id=org_b.id).all()
        assert all(r.id != report_a.id for r in reports)

    def test_org_a_can_see_own_reports(self, db, org_a, report_a):
        reports = db.query(DmarcReport).filter_by(organization_id=org_a.id).all()
        assert any(r.id == report_a.id for r in reports)

    def test_two_orgs_have_separate_reports(self, db, org_a, org_b, job_a, job_b):
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        r_a = store_parsed_report(db, parsed, org_a.id, job_a.id)

        # Create a distinct report for org_b (different report_id)
        import copy
        parsed_b = parse_xml_bytes(
            SAMPLE_DMARC_XML.replace(b"test-report-001", b"test-report-org-b")
        )
        r_b = store_parsed_report(db, parsed_b, org_b.id, job_b.id)
        db.flush()

        assert r_a.organization_id == org_a.id
        assert r_b.organization_id == org_b.id
        assert r_a.id != r_b.id

        a_reports = db.query(DmarcReport).filter_by(organization_id=org_a.id).all()
        b_reports = db.query(DmarcReport).filter_by(organization_id=org_b.id).all()
        a_ids = {r.id for r in a_reports}
        b_ids = {r.id for r in b_reports}
        assert a_ids.isdisjoint(b_ids)


# ── Records ────────────────────────────────────────────────────────────────────

class TestRecordIsolation:
    def test_org_b_cannot_see_org_a_records(self, db, org_b, report_a):
        records = db.query(DmarcRecord).filter_by(organization_id=org_b.id).all()
        assert all(r.report_id != report_a.id for r in records)

    def test_records_carry_org_id(self, db, org_a, report_a):
        records = db.query(DmarcRecord).filter_by(organization_id=org_a.id).all()
        assert len(records) > 0
        assert all(r.organization_id == org_a.id for r in records)


# ── Domains ────────────────────────────────────────────────────────────────────

class TestDomainIsolation:
    def test_org_b_cannot_see_org_a_domains(self, db, org_b, domain_a):
        domains = db.query(Domain).filter_by(organization_id=org_b.id).all()
        assert all(d.id != domain_a.id for d in domains)

    def test_same_domain_name_in_two_orgs_is_allowed(self, db, org_a, org_b):
        d_a = Domain(organization_id=org_a.id, name="shared.example.com", is_active=True)
        d_b = Domain(organization_id=org_b.id, name="shared.example.com", is_active=True)
        db.add(d_a)
        db.add(d_b)
        db.flush()
        assert d_a.id != d_b.id

        a_result = db.query(Domain).filter_by(organization_id=org_a.id, name="shared.example.com").first()
        b_result = db.query(Domain).filter_by(organization_id=org_b.id, name="shared.example.com").first()
        assert a_result.id != b_result.id


# ── Source IPs ─────────────────────────────────────────────────────────────────

class TestSourceIpIsolation:
    def test_source_ip_scoped_to_org(self, db, org_a, org_b, report_a):
        sips_b = db.query(SourceIp).filter_by(organization_id=org_b.id).all()
        sip_ips_b = {s.ip_address for s in sips_b}
        assert "203.0.113.1" not in sip_ips_b
        assert "198.51.100.5" not in sip_ips_b

    def test_source_ip_created_under_org_a(self, db, org_a, report_a):
        sips_a = db.query(SourceIp).filter_by(organization_id=org_a.id).all()
        sip_ips_a = {s.ip_address for s in sips_a}
        assert "203.0.113.1" in sip_ips_a


# ── Inbound addresses ──────────────────────────────────────────────────────────

class TestInboundAddressIsolation:
    def test_inbound_address_scoped_to_org(self, db, org_a, org_b):
        token = generate_inbound_token(12)
        addr = InboundMailAddress(
            organization_id=org_a.id,
            address=f"test-{token}@reports.example.org",
            token=token,
            status="active",
            purpose="org_report",
        )
        db.add(addr)
        db.flush()

        b_addrs = db.query(InboundMailAddress).filter_by(organization_id=org_b.id).all()
        assert all(a.id != addr.id for a in b_addrs)


# ── Import jobs ────────────────────────────────────────────────────────────────

class TestImportJobIsolation:
    def test_import_jobs_scoped_to_org(self, db, org_a, org_b, job_a):
        b_jobs = db.query(ImportJob).filter_by(organization_id=org_b.id).all()
        assert all(j.id != job_a.id for j in b_jobs)
