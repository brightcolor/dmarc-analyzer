"""Storing RFC 9990 reports, domain policy cache and evaluation rules from RFC 9989."""
import pytest

from app.models import DmarcRecord, DmarcReport, Domain, ImportJob
from app.services.dmarc_evaluator import AuthResultEntry, PolicyConfig, RecordEvalInput, evaluate_record
from app.services.dmarc_parser import FORMAT_RFC7489, FORMAT_RFC9990, parse_xml_bytes
from app.services.import_service import process_import_job, store_parsed_report
from tests.conftest import DMARCBIS_XML, SAMPLE_DMARC_XML


@pytest.fixture
def import_job(db, org):
    job = ImportJob(organization_id=org.id, source="web_upload", status="pending",
                    file_name="report.xml", file_type="xml")
    db.add(job)
    db.flush()
    return job


def _store(db, org, job, xml: bytes) -> DmarcReport:
    return store_parsed_report(db, parse_xml_bytes(xml), org.id, job.id)


class TestStoreDmarcbisReport:
    def test_format_and_evidence_stored(self, db, org, import_job):
        report = _store(db, org, import_job, DMARCBIS_XML)
        assert report.report_format == FORMAT_RFC9990
        assert report.format_evidence == "namespace"

    def test_new_policy_fields_stored(self, db, org, import_job):
        report = _store(db, org, import_job, DMARCBIS_XML)
        assert report.policy_np == "reject"
        assert report.policy_testing == "y"
        assert report.policy_discovery_method == "treewalk"
        assert report.policy_pct is None
        assert report.generator == "Example Reporter 3.1"

    def test_override_reasons_stored(self, db, org, import_job):
        report = _store(db, org, import_job, DMARCBIS_XML)
        records = db.query(DmarcRecord).filter_by(report_id=report.id).order_by(DmarcRecord.count).all()
        assert records[0].override_reasons == [{"type": "policy_test_mode", "comment": "t=y"}]
        assert records[1].override_reasons is None

    def test_pass_disposition_stored(self, db, org, import_job):
        report = _store(db, org, import_job, DMARCBIS_XML)
        dispositions = {r.disposition for r in db.query(DmarcRecord).filter_by(report_id=report.id)}
        assert dispositions == {"pass", "none"}

    def test_testing_mode_means_policy_not_applied(self, db, org, import_job):
        report = _store(db, org, import_job, DMARCBIS_XML)
        failing = db.query(DmarcRecord).filter_by(report_id=report.id, dmarc_pass=False).one()
        assert failing.policy_applied is False

    def test_classic_report_stored_as_rfc7489(self, db, org, import_job):
        report = _store(db, org, import_job, SAMPLE_DMARC_XML)
        assert report.report_format == FORMAT_RFC7489
        assert report.format_evidence == "pct"
        assert report.policy_pct == 100


class TestDomainPolicyCache:
    def test_each_format_keeps_its_own_tags(self, db, org, import_job):
        classic = SAMPLE_DMARC_XML.replace(b"<pct>100</pct>", b"<pct>40</pct>")
        _store(db, org, import_job, classic)
        _store(db, org, import_job, DMARCBIS_XML)
        domain = db.query(Domain).filter_by(organization_id=org.id, name="example.com").one()
        assert domain.dmarc_policy_pct == 40
        assert domain.dmarc_policy_np == "reject"
        assert domain.dmarc_policy_testing == "y"
        assert domain.last_report_format == FORMAT_RFC9990

    def test_testing_defaults_to_n_in_new_format(self, db, org, import_job):
        xml = DMARCBIS_XML.replace(b"<testing>y</testing>", b"")
        _store(db, org, import_job, xml)
        domain = db.query(Domain).filter_by(organization_id=org.id, name="example.com").one()
        assert domain.dmarc_policy_testing == "n"


class TestImportMessages:
    def test_missing_file_message_hides_path(self, db, org, import_job):
        import_job.file_path = "/srv/secret/location/report.xml"
        process_import_job(db, import_job)
        assert import_job.status == "failed"
        assert "/srv/secret" not in import_job.error_message
        assert "erneut hoch" in import_job.error_message

    def test_missing_report_id_is_explained(self, db, org, import_job, tmp_path):
        xml = SAMPLE_DMARC_XML.replace(b"<report_id>test-report-001</report_id>", b"")
        f = tmp_path / "no-id.xml"
        f.write_bytes(xml)
        import_job.file_path = str(f)
        process_import_job(db, import_job)
        from app.models import ImportError
        error = db.query(ImportError).filter_by(job_id=import_job.id).one()
        assert "Berichtsnummer" in error.error_message


def _failing_record(header_from: str) -> RecordEvalInput:
    return RecordEvalInput(
        source_ip="192.0.2.99", count=1, header_from=header_from, envelope_from=None,
        dkim_result="fail", spf_result="fail",
        auth_results=[AuthResultEntry("dkim", "example.org", "fail"), AuthResultEntry("spf", "example.org", "fail")],
    )


class TestEvaluationRules:
    def test_subdomain_falls_back_to_p_without_sp(self):
        policy = PolicyConfig(domain="example.com", p="reject", sp=None)
        assert evaluate_record(_failing_record("news.example.com"), policy).policy_applied is True

    def test_subdomain_uses_sp_when_present(self):
        policy = PolicyConfig(domain="example.com", p="reject", sp="none")
        assert evaluate_record(_failing_record("news.example.com"), policy).policy_applied is False

    def test_testing_mode_suspends_policy(self):
        policy = PolicyConfig(domain="example.com", p="reject", testing="y")
        result = evaluate_record(_failing_record("example.com"), policy)
        assert result.dmarc_pass is False
        assert result.policy_applied is False

    def test_testing_n_keeps_policy(self):
        policy = PolicyConfig(domain="example.com", p="quarantine", testing="n")
        assert evaluate_record(_failing_record("example.com"), policy).policy_applied is True
