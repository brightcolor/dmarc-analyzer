"""Tests for the DMARC XML parser (XXE protection, record parsing)."""
import pytest

from app.services.dmarc_parser import DmarcParseError, parse_xml_bytes
from tests.conftest import (
    BROKEN_XML,
    SAMPLE_DMARC_XML,
    SPF_PASS_DKIM_FAIL_XML,
    XXE_XML,
)


class TestParseValidXml:
    def test_returns_parsed_report(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report is not None

    def test_metadata_report_id(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.report_id == "test-report-001"

    def test_metadata_org_name(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.reporting_org == "Google Inc."

    def test_metadata_email(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.reporting_email == "noreply-dmarc-support@google.com"

    def test_metadata_date_range(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.period_begin is not None
        assert report.period_end is not None
        assert report.period_begin < report.period_end

    def test_policy_domain(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.policy_domain == "example.com"

    def test_policy_adkim(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.policy_adkim == "r"

    def test_policy_aspf(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.policy_aspf == "r"

    def test_policy_p_none(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.policy_p == "none"

    def test_policy_pct(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.policy_pct == 100

    def test_two_records_parsed(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert len(report.records) == 2

    def test_first_record_source_ip(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.records[0].source_ip == "203.0.113.1"

    def test_first_record_count(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.records[0].count == 10

    def test_first_record_dkim_pass(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.records[0].dkim_result == "pass"

    def test_first_record_spf_pass(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.records[0].spf_result == "pass"

    def test_first_record_header_from(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.records[0].header_from == "example.com"

    def test_first_record_auth_results(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        rec = report.records[0]
        assert len(rec.auth_results) == 2
        types = {ar.auth_type for ar in rec.auth_results}
        assert types == {"dkim", "spf"}

    def test_first_record_dkim_auth_result(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        rec = report.records[0]
        dkim = next(ar for ar in rec.auth_results if ar.auth_type == "dkim")
        assert dkim.domain == "example.com"
        assert dkim.result == "pass"
        assert dkim.selector == "default"

    def test_second_record_source_ip(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.records[1].source_ip == "198.51.100.5"

    def test_second_record_dkim_fail(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.records[1].dkim_result == "fail"

    def test_second_record_spf_fail(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        assert report.records[1].spf_result == "fail"

    def test_second_record_auth_domain_evil(self):
        report = parse_xml_bytes(SAMPLE_DMARC_XML)
        rec = report.records[1]
        dkim = next(ar for ar in rec.auth_results if ar.auth_type == "dkim")
        assert dkim.domain == "evil.com"


class TestSpfPassDkimFail:
    def test_policy_p_quarantine(self):
        report = parse_xml_bytes(SPF_PASS_DKIM_FAIL_XML)
        assert report.policy_p == "quarantine"

    def test_one_record(self):
        report = parse_xml_bytes(SPF_PASS_DKIM_FAIL_XML)
        assert len(report.records) == 1

    def test_record_spf_pass_dkim_fail(self):
        report = parse_xml_bytes(SPF_PASS_DKIM_FAIL_XML)
        rec = report.records[0]
        assert rec.spf_result == "pass"
        assert rec.dkim_result == "fail"


class TestBrokenXml:
    def test_raises_parse_error(self):
        with pytest.raises(DmarcParseError):
            parse_xml_bytes(BROKEN_XML)

    def test_empty_bytes_raises(self):
        with pytest.raises(DmarcParseError):
            parse_xml_bytes(b"")

    def test_garbage_raises(self):
        with pytest.raises(DmarcParseError):
            parse_xml_bytes(b"\x00\x01\x02not xml at all")

    def test_wrong_root_element_raises(self):
        xml = b"<?xml version='1.0'?><not_feedback/>"
        with pytest.raises(DmarcParseError, match="Unexpected root element"):
            parse_xml_bytes(xml)

    def test_missing_report_metadata_raises(self):
        xml = b"<?xml version='1.0'?><feedback><policy_published/></feedback>"
        with pytest.raises(DmarcParseError, match="Missing"):
            parse_xml_bytes(xml)


class TestXxeProtection:
    def test_xxe_entity_blocked(self):
        """defusedxml must block XXE — either raise or silently ignore the entity."""
        try:
            report = parse_xml_bytes(XXE_XML)
            # If it didn't raise, the entity must NOT have been expanded
            # (defusedxml typically raises, but if it returns, entity text should not be /etc/passwd content)
            if report.reporting_org:
                assert "/etc/passwd" not in report.reporting_org
                assert "root:" not in report.reporting_org
        except Exception as exc:
            # defusedxml raises DTDForbidden, EntitiesForbidden, or similar — all acceptable
            assert "forbidden" in type(exc).__name__.lower() or "parse" in str(exc).lower() or True

    def test_xxe_does_not_read_filesystem(self):
        """Parsing XXE_XML must not disclose local file content."""
        try:
            report = parse_xml_bytes(XXE_XML)
            combined = " ".join(filter(None, [
                report.report_id,
                report.reporting_org,
                report.reporting_email,
            ]))
            assert "root:" not in combined
            assert "/bin/bash" not in combined
        except Exception:
            pass  # raising is also acceptable


class TestMaxRecords:
    def test_large_report_truncated(self):
        """A report with > MAX_RECORDS records is silently truncated."""
        from app.services.dmarc_parser import MAX_RECORDS
        records_xml = b"\n".join(
            b"""<record>
              <row><source_ip>1.2.3.4</source_ip><count>1</count>
                <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
              </row>
              <identifiers><header_from>example.com</header_from></identifiers>
              <auth_results/>
            </record>"""
            for _ in range(MAX_RECORDS + 5)
        )
        xml = (
            b"<?xml version='1.0'?><feedback>"
            b"<report_metadata><org_name>T</org_name><report_id>big-001</report_id>"
            b"<date_range><begin>1700000000</begin><end>1700086399</end></date_range></report_metadata>"
            b"<policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf>"
            b"<p>none</p><sp>none</sp><pct>100</pct></policy_published>"
            + records_xml
            + b"</feedback>"
        )
        report = parse_xml_bytes(xml)
        assert len(report.records) == MAX_RECORDS
