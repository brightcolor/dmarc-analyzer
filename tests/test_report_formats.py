"""Reading RFC 7489 and RFC 9990 (DMARCbis) reports and telling them apart."""
from app.services.dmarc_parser import (
    FORMAT_RFC7489,
    FORMAT_RFC9990,
    parse_xml_bytes,
)
from app.services.report_formats import evidence_texts, format_info
from tests.conftest import (
    DMARCBIS_NO_NAMESPACE_XML,
    DMARCBIS_XML,
    LEGACY_NAMESPACE_XML,
    SAMPLE_DMARC_XML,
)


def _classic(policy_extra: bytes = b"", record_extra: bytes = b"") -> bytes:
    return (
        b"<feedback><report_metadata><org_name>example.net</org_name><report_id>r-1</report_id>"
        b"<date_range><begin>1790000000</begin><end>1790086399</end></date_range></report_metadata>"
        b"<policy_published><domain>example.com</domain><p>quarantine</p>" + policy_extra +
        b"</policy_published><record><row><source_ip>192.0.2.1</source_ip><count>1</count>"
        b"<policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>" + record_extra +
        b"</policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers>"
        b"</record></feedback>"
    )


class TestDmarcbisReport:
    def test_namespaced_report_is_read_completely(self):
        report = parse_xml_bytes(DMARCBIS_XML)
        assert report.report_id == "bis-report-001"
        assert report.reporting_org == "example.net"
        assert report.policy_domain == "example.com"
        assert len(report.records) == 2

    def test_detected_by_namespace(self):
        report = parse_xml_bytes(DMARCBIS_XML)
        assert report.report_format == FORMAT_RFC9990
        assert report.format_evidence == ["namespace"]

    def test_new_policy_fields(self):
        report = parse_xml_bytes(DMARCBIS_XML)
        assert report.policy_p == "reject"
        assert report.policy_sp == "quarantine"
        assert report.policy_np == "reject"
        assert report.policy_testing == "y"
        assert report.policy_discovery_method == "treewalk"

    def test_pct_absent_in_new_format(self):
        assert parse_xml_bytes(DMARCBIS_XML).policy_pct is None

    def test_metadata_fields(self):
        report = parse_xml_bytes(DMARCBIS_XML)
        assert report.generator == "Example Reporter 3.1"
        assert report.schema_version == "1.0"

    def test_pass_disposition_and_reasons(self):
        report = parse_xml_bytes(DMARCBIS_XML)
        assert report.records[0].disposition == "pass"
        assert report.records[1].reasons[0].type == "policy_test_mode"
        assert report.records[1].reasons[0].comment == "t=y"

    def test_auth_results_with_selector_and_scope(self):
        auth = parse_xml_bytes(DMARCBIS_XML).records[0].auth_results
        dkim = next(a for a in auth if a.auth_type == "dkim")
        spf = next(a for a in auth if a.auth_type == "spf")
        assert dkim.selector == "s2026"
        assert spf.scope == "mfrom"

    def test_detected_by_fields_without_namespace(self):
        report = parse_xml_bytes(DMARCBIS_NO_NAMESPACE_XML)
        assert report.report_format == FORMAT_RFC9990
        assert "namespace" not in report.format_evidence
        assert {"np", "testing", "discovery_method", "generator"} <= set(report.format_evidence)

    def test_single_new_field_is_enough(self):
        report = parse_xml_bytes(_classic(policy_extra=b"<np>reject</np>"))
        assert report.report_format == FORMAT_RFC9990
        assert report.format_evidence == ["np"]

    def test_pass_disposition_alone_marks_new_format(self):
        xml = _classic().replace(b"<disposition>none</disposition>", b"<disposition>pass</disposition>")
        report = parse_xml_bytes(xml)
        assert report.report_format == FORMAT_RFC9990
        assert report.format_evidence == ["disposition_pass"]

    def test_test_mode_reason_marks_new_format(self):
        report = parse_xml_bytes(_classic(record_extra=b"<reason><type>policy_test_mode</type></reason>"))
        assert report.format_evidence == ["policy_test_mode"]


class TestClassicReport:
    def test_detected_by_pct(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.report_format == FORMAT_RFC7489
        assert report.format_evidence == ["pct"]

    def test_without_markers_defaults_to_classic(self):
        report = parse_xml_bytes(_classic())
        assert report.report_format == FORMAT_RFC7489
        assert report.format_evidence == ["default"]

    def test_pct_defaults_to_100_in_classic_format(self):
        assert parse_xml_bytes(_classic()).policy_pct == 100

    def test_explicit_pct_is_kept(self):
        assert parse_xml_bytes(_classic(policy_extra=b"<pct>25</pct>")).policy_pct == 25

    def test_legacy_reason_is_evidence(self):
        report = parse_xml_bytes(_classic(record_extra=b"<reason><type>sampled_out</type></reason>"))
        assert report.report_format == FORMAT_RFC7489
        assert report.format_evidence == ["legacy_reason"]
        assert report.records[0].reasons[0].type == "sampled_out"

    def test_no_new_fields_in_classic_report(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.policy_np is None
        assert report.policy_testing is None
        assert report.policy_discovery_method is None

    def test_other_namespace_is_read(self):
        report = parse_xml_bytes(LEGACY_NAMESPACE_XML)
        assert report.report_id == "legacy-ns-001"
        assert report.report_format == FORMAT_RFC7489
        assert len(report.records) == 2

    def test_values_are_normalised_to_lower_case(self):
        report = parse_xml_bytes(_classic().replace(b"<p>quarantine</p>", b"<p>Quarantine</p>"))
        assert report.policy_p == "quarantine"


class TestFormatTexts:
    def test_labels(self):
        assert format_info(FORMAT_RFC7489).label == "RFC 7489"
        assert format_info(FORMAT_RFC9990).label == "RFC 9990"

    def test_unknown_format_for_old_imports(self):
        assert format_info(None).label == "nicht erfasst"

    def test_evidence_is_explained(self):
        texts = evidence_texts("namespace,np")
        assert len(texts) == 2
        assert "dmarc-2.0" in texts[0]

    def test_every_evidence_code_has_a_text(self):
        from app.services.report_formats import EVIDENCE_TEXT
        codes = {"namespace", "np", "testing", "discovery_method", "generator", "disposition_pass",
                 "policy_test_mode", "pct", "legacy_reason", "default"}
        assert codes <= set(EVIDENCE_TEXT)
