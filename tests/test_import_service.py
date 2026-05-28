"""Tests for the DMARC import pipeline (parsing, storing, deduplication)."""
import os
import tempfile

import pytest

from app.models import DmarcRecord, DmarcReport, ImportJob, SourceIp
from app.services.import_service import (
    check_duplicate,
    get_or_create_domain,
    process_import_job,
    store_parsed_report,
)
from app.services.dmarc_parser import parse_xml_bytes
from tests.conftest import BROKEN_XML, DUPLICATE_REPORT_XML, SAMPLE_DMARC_XML


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def import_job(db, org):
    job = ImportJob(
        organization_id=org.id,
        source="web_upload",
        status="pending",
        file_name="report.xml",
        file_type="xml",
    )
    db.add(job)
    db.flush()
    return job


@pytest.fixture
def xml_file(tmp_path):
    f = tmp_path / "report.xml"
    f.write_bytes(SAMPLE_DMARC_XML)
    return str(f)


@pytest.fixture
def broken_xml_file(tmp_path):
    f = tmp_path / "broken.xml"
    f.write_bytes(BROKEN_XML)
    return str(f)


# ── get_or_create_domain ───────────────────────────────────────────────────────

class TestGetOrCreateDomain:
    def test_creates_new_domain(self, db, org):
        d = get_or_create_domain(db, org.id, "newdomain.example.com")
        assert d is not None
        assert d.name == "newdomain.example.com"
        assert d.organization_id == org.id

    def test_returns_existing_domain(self, db, org, domain):
        d = get_or_create_domain(db, org.id, domain.name)
        assert d.id == domain.id

    def test_normalizes_trailing_dot(self, db, org):
        d = get_or_create_domain(db, org.id, "trailing.example.com.")
        assert d.name == "trailing.example.com"

    def test_normalizes_uppercase(self, db, org):
        d = get_or_create_domain(db, org.id, "UPPER.EXAMPLE.COM")
        assert d.name == "upper.example.com"


# ── check_duplicate ────────────────────────────────────────────────────────────

class TestCheckDuplicate:
    def test_no_duplicate_initially(self, db, org):
        assert check_duplicate(db, org.id, "test-report-001") is False

    def test_detects_duplicate_same_org(self, db, org, import_job):
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        store_parsed_report(db, parsed, org.id, import_job.id)
        assert check_duplicate(db, org.id, "test-report-001") is True

    def test_no_cross_tenant_duplicate(self, db, org, import_job):
        """Same report_id in a different org is NOT a duplicate."""
        from app.models import Organization
        other_org = Organization(name="Other Org", slug="other-org", is_active=True)
        db.add(other_org)
        db.flush()

        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        store_parsed_report(db, parsed, org.id, import_job.id)

        # Different org — must not see the duplicate
        assert check_duplicate(db, other_org.id, "test-report-001") is False


# ── store_parsed_report ────────────────────────────────────────────────────────

class TestStoreParsedReport:
    def test_creates_dmarc_report(self, db, org, import_job):
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        report = store_parsed_report(db, parsed, org.id, import_job.id)
        assert report.id is not None
        assert report.report_id == "test-report-001"
        assert report.organization_id == org.id

    def test_creates_two_records(self, db, org, import_job):
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        report = store_parsed_report(db, parsed, org.id, import_job.id)
        db.flush()
        records = db.query(DmarcRecord).filter_by(report_id=report.id).all()
        assert len(records) == 2

    def test_first_record_dmarc_pass(self, db, org, import_job):
        """First record (DKIM pass + SPF pass from example.com) must be DMARC pass."""
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        report = store_parsed_report(db, parsed, org.id, import_job.id)
        db.flush()
        records = db.query(DmarcRecord).filter_by(report_id=report.id).order_by(DmarcRecord.source_ip).all()
        # 198.51.100.5 = fail, 203.0.113.1 = pass
        by_ip = {r.source_ip: r for r in records}
        assert by_ip["203.0.113.1"].dmarc_pass is True

    def test_second_record_dmarc_fail(self, db, org, import_job):
        """Second record (DKIM fail + SPF fail from evil.com) must be DMARC fail."""
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        report = store_parsed_report(db, parsed, org.id, import_job.id)
        db.flush()
        records = db.query(DmarcRecord).filter_by(report_id=report.id).all()
        by_ip = {r.source_ip: r for r in records}
        assert by_ip["198.51.100.5"].dmarc_pass is False

    def test_report_totals(self, db, org, import_job):
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        report = store_parsed_report(db, parsed, org.id, import_job.id)
        # 10 pass + 3 fail = 13 total
        assert report.total_messages == 13
        assert report.pass_count == 10
        assert report.fail_count == 3

    def test_pass_rate_calculated(self, db, org, import_job):
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        report = store_parsed_report(db, parsed, org.id, import_job.id)
        assert report.pass_rate is not None
        assert abs(report.pass_rate - 76.92) < 0.1

    def test_source_ip_created(self, db, org, import_job):
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        store_parsed_report(db, parsed, org.id, import_job.id)
        db.flush()
        sip = db.query(SourceIp).filter_by(organization_id=org.id, ip_address="203.0.113.1").first()
        assert sip is not None
        assert sip.total_messages == 10
        assert sip.pass_count == 10

    def test_failing_source_ip_tracked(self, db, org, import_job):
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        store_parsed_report(db, parsed, org.id, import_job.id)
        db.flush()
        sip = db.query(SourceIp).filter_by(organization_id=org.id, ip_address="198.51.100.5").first()
        assert sip is not None
        assert sip.fail_count == 3

    def test_domain_last_report_updated(self, db, org, import_job, domain):
        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        store_parsed_report(db, parsed, org.id, import_job.id)
        db.refresh(domain)
        assert domain.last_report_at is not None

    def test_report_scoped_to_org(self, db, org, import_job):
        from app.models import Organization
        other_org = Organization(name="Other", slug="other", is_active=True)
        db.add(other_org)
        db.flush()

        parsed = parse_xml_bytes(SAMPLE_DMARC_XML)
        store_parsed_report(db, parsed, org.id, import_job.id)
        db.flush()

        other_reports = db.query(DmarcReport).filter_by(organization_id=other_org.id).all()
        assert other_reports == []


# ── process_import_job ─────────────────────────────────────────────────────────

class TestProcessImportJob:
    def test_completes_successfully(self, db, org, import_job, xml_file):
        import_job.file_path = xml_file
        process_import_job(db, import_job)
        assert import_job.status == "completed"
        assert import_job.records_imported == 1

    def test_sets_file_hash(self, db, org, import_job, xml_file):
        import_job.file_path = xml_file
        process_import_job(db, import_job)
        assert import_job.file_hash is not None
        assert len(import_job.file_hash) == 64  # SHA-256 hex

    def test_broken_xml_marks_failed(self, db, org, import_job, broken_xml_file):
        import_job.file_path = broken_xml_file
        process_import_job(db, import_job)
        assert import_job.status == "failed"
        assert import_job.records_failed >= 1

    def test_duplicate_skipped(self, db, org, import_job, xml_file):
        import_job.file_path = xml_file
        process_import_job(db, import_job)

        # Second import job with same file
        job2 = ImportJob(
            organization_id=org.id,
            source="web_upload",
            status="pending",
            file_name="report.xml",
            file_type="xml",
            file_path=xml_file,
        )
        db.add(job2)
        db.flush()
        process_import_job(db, job2)
        assert job2.records_skipped == 1
        assert job2.records_imported == 0

    def test_missing_file_marks_failed(self, db, org, import_job):
        import_job.file_path = "/nonexistent/path/report.xml"
        process_import_job(db, import_job)
        assert import_job.status == "failed"

    def test_gz_file_processed(self, db, org, import_job, tmp_path):
        import gzip as _gz, io as _io
        buf = _io.BytesIO()
        with _gz.GzipFile(fileobj=buf, mode='wb') as f:
            f.write(SAMPLE_DMARC_XML)
        gz_path = tmp_path / "report.xml.gz"
        gz_path.write_bytes(buf.getvalue())

        import_job.file_path = str(gz_path)
        import_job.file_name = "report.xml.gz"
        import_job.file_type = "xml_gz"
        process_import_job(db, import_job)
        assert import_job.status == "completed"

    def test_zip_file_processed(self, db, org, import_job, tmp_path):
        import io as _io, zipfile as _zf
        buf = _io.BytesIO()
        with _zf.ZipFile(buf, "w") as zf:
            zf.writestr("report.xml", SAMPLE_DMARC_XML)
        zip_path = tmp_path / "report.zip"
        zip_path.write_bytes(buf.getvalue())

        import_job.file_path = str(zip_path)
        import_job.file_name = "report.zip"
        import_job.file_type = "zip"
        process_import_job(db, import_job)
        assert import_job.status == "completed"
        assert import_job.records_imported == 1
