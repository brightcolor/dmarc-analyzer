"""Tests for DMARC evaluation logic (RFC 7489)."""
import pytest

from app.services.dmarc_evaluator import (
    AuthResultEntry,
    EvalResult,
    PolicyConfig,
    RecordEvalInput,
    _domains_aligned,
    _organizational_domain,
    compute_report_stats,
    evaluate_record,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_policy(domain="example.com", adkim="r", aspf="r", p="none", sp="none", pct=100):
    return PolicyConfig(domain=domain, adkim=adkim, aspf=aspf, p=p, sp=sp, pct=pct)


def make_record(
    header_from="example.com",
    envelope_from="example.com",
    dkim_result=None,
    spf_result=None,
    auth_results=None,
    source_ip="203.0.113.1",
    count=1,
):
    return RecordEvalInput(
        source_ip=source_ip,
        count=count,
        header_from=header_from,
        envelope_from=envelope_from,
        dkim_result=dkim_result,
        spf_result=spf_result,
        auth_results=auth_results or [],
    )


def dkim_pass(domain="example.com", selector="default"):
    return AuthResultEntry("dkim", domain, "pass", selector=selector)


def spf_pass(domain="example.com"):
    return AuthResultEntry("spf", domain, "pass")


def dkim_fail(domain="example.com"):
    return AuthResultEntry("dkim", domain, "fail")


def spf_fail(domain="example.com"):
    return AuthResultEntry("spf", domain, "fail")


# ── Organizational domain extraction ──────────────────────────────────────────

class TestOrganizationalDomain:
    def test_simple_domain(self):
        assert _organizational_domain("example.com") == "example.com"

    def test_subdomain(self):
        assert _organizational_domain("mail.example.com") == "example.com"

    def test_deep_subdomain(self):
        assert _organizational_domain("a.b.c.example.com") == "example.com"

    def test_trailing_dot(self):
        assert _organizational_domain("example.com.") == "example.com"

    def test_empty(self):
        assert _organizational_domain("") == ""

    def test_single_label(self):
        assert _organizational_domain("localhost") == "localhost"


# ── Domain alignment ──────────────────────────────────────────────────────────

class TestDomainsAligned:
    def test_relaxed_exact(self):
        assert _domains_aligned("example.com", "example.com", "r")

    def test_relaxed_subdomain(self):
        assert _domains_aligned("mail.example.com", "example.com", "r")

    def test_relaxed_header_from_subdomain(self):
        assert _domains_aligned("example.com", "mail.example.com", "r")

    def test_relaxed_different(self):
        assert not _domains_aligned("evil.com", "example.com", "r")

    def test_strict_exact(self):
        assert _domains_aligned("example.com", "example.com", "s")

    def test_strict_subdomain_rejected(self):
        assert not _domains_aligned("mail.example.com", "example.com", "s")

    def test_strict_different(self):
        assert not _domains_aligned("evil.com", "example.com", "s")

    def test_empty_domain(self):
        assert not _domains_aligned("", "example.com", "r")

    def test_case_insensitive(self):
        assert _domains_aligned("EXAMPLE.COM", "example.com", "r")


# ── evaluate_record ────────────────────────────────────────────────────────────

class TestEvaluateRecord:
    def test_dkim_and_spf_both_pass_aligned(self):
        policy = make_policy()
        record = make_record(auth_results=[dkim_pass(), spf_pass()])
        result = evaluate_record(record, policy)
        assert result.dmarc_pass is True
        assert result.dkim_aligned is True
        assert result.spf_aligned is True

    def test_dkim_only_pass_aligned(self):
        policy = make_policy()
        record = make_record(auth_results=[dkim_pass(), spf_fail()])
        result = evaluate_record(record, policy)
        assert result.dmarc_pass is True
        assert result.dkim_aligned is True
        assert result.spf_aligned is False

    def test_spf_only_pass_aligned(self):
        policy = make_policy()
        record = make_record(auth_results=[dkim_fail(), spf_pass()])
        result = evaluate_record(record, policy)
        assert result.dmarc_pass is True
        assert result.dkim_aligned is False
        assert result.spf_aligned is True

    def test_both_fail_dmarc_fail(self):
        policy = make_policy(p="reject")
        record = make_record(
            header_from="example.com",
            auth_results=[dkim_fail("evil.com"), spf_fail("evil.com")],
        )
        result = evaluate_record(record, policy)
        assert result.dmarc_pass is False
        assert result.dkim_aligned is False
        assert result.spf_aligned is False

    def test_dkim_misaligned_domain_fails(self):
        policy = make_policy(adkim="r")
        record = make_record(
            header_from="example.com",
            auth_results=[AuthResultEntry("dkim", "evil.com", "pass")],
        )
        result = evaluate_record(record, policy)
        assert result.dmarc_pass is False
        assert result.dkim_aligned is False

    def test_strict_dkim_subdomain_fails(self):
        policy = make_policy(adkim="s")
        record = make_record(
            header_from="example.com",
            auth_results=[AuthResultEntry("dkim", "mail.example.com", "pass")],
        )
        result = evaluate_record(record, policy)
        assert result.dkim_aligned is False

    def test_relaxed_dkim_subdomain_passes(self):
        policy = make_policy(adkim="r")
        record = make_record(
            header_from="example.com",
            auth_results=[AuthResultEntry("dkim", "mail.example.com", "pass")],
        )
        result = evaluate_record(record, policy)
        assert result.dkim_aligned is True

    def test_strict_spf_subdomain_fails(self):
        policy = make_policy(aspf="s")
        record = make_record(
            header_from="example.com",
            auth_results=[AuthResultEntry("spf", "mail.example.com", "pass")],
        )
        result = evaluate_record(record, policy)
        assert result.spf_aligned is False

    def test_relaxed_spf_subdomain_passes(self):
        policy = make_policy(aspf="r")
        record = make_record(
            header_from="example.com",
            auth_results=[AuthResultEntry("spf", "mail.example.com", "pass")],
        )
        result = evaluate_record(record, policy)
        assert result.spf_aligned is True

    def test_row_level_dkim_pass_fallback(self):
        """When auth_results is empty, row-level dkim_result=pass is trusted."""
        policy = make_policy()
        record = make_record(dkim_result="pass", auth_results=[])
        result = evaluate_record(record, policy)
        assert result.dkim_aligned is True
        assert result.dmarc_pass is True

    def test_row_level_spf_pass_fallback_aligned_envelope(self):
        """When auth_results is empty, row-level spf_result=pass with aligned envelope_from."""
        policy = make_policy(aspf="r")
        record = make_record(
            header_from="example.com",
            envelope_from="bounce@example.com",
            spf_result="pass",
            auth_results=[],
        )
        result = evaluate_record(record, policy)
        assert result.spf_aligned is True
        assert result.dmarc_pass is True

    def test_policy_applied_on_fail_with_reject(self):
        policy = make_policy(p="reject")
        record = make_record(
            header_from="example.com",
            auth_results=[dkim_fail("evil.com"), spf_fail("evil.com")],
        )
        result = evaluate_record(record, policy)
        assert result.dmarc_pass is False
        assert result.policy_applied is True

    def test_policy_applied_on_fail_with_quarantine(self):
        policy = make_policy(p="quarantine")
        record = make_record(
            header_from="example.com",
            auth_results=[dkim_fail("evil.com"), spf_fail("evil.com")],
        )
        result = evaluate_record(record, policy)
        assert result.policy_applied is True

    def test_policy_not_applied_when_pass(self):
        policy = make_policy(p="reject")
        record = make_record(auth_results=[dkim_pass(), spf_pass()])
        result = evaluate_record(record, policy)
        assert result.policy_applied is False

    def test_policy_not_applied_with_none_policy(self):
        policy = make_policy(p="none")
        record = make_record(
            header_from="example.com",
            auth_results=[dkim_fail("evil.com"), spf_fail("evil.com")],
        )
        result = evaluate_record(record, policy)
        assert result.policy_applied is False

    def test_subdomain_uses_sp_policy(self):
        """Mail from subdomain uses sp= field for policy enforcement."""
        policy = make_policy(domain="example.com", p="none", sp="reject")
        record = make_record(
            header_from="sub.example.com",
            auth_results=[dkim_fail("evil.com"), spf_fail("evil.com")],
        )
        result = evaluate_record(record, policy)
        assert result.dmarc_pass is False
        assert result.policy_applied is True

    def test_detail_on_pass(self):
        policy = make_policy()
        record = make_record(auth_results=[dkim_pass(), spf_pass()])
        result = evaluate_record(record, policy)
        assert "pass" in result.detail.lower()

    def test_detail_on_fail(self):
        policy = make_policy(p="reject")
        record = make_record(
            header_from="example.com",
            auth_results=[dkim_fail("evil.com"), spf_fail("evil.com")],
        )
        result = evaluate_record(record, policy)
        assert "fail" in result.detail.lower()

    def test_spf_pass_result_required_for_alignment(self):
        """SPF softfail does not count as aligned."""
        policy = make_policy()
        record = make_record(
            header_from="example.com",
            auth_results=[AuthResultEntry("spf", "example.com", "softfail")],
        )
        result = evaluate_record(record, policy)
        assert result.spf_aligned is False


# ── compute_report_stats ───────────────────────────────────────────────────────

class TestComputeReportStats:
    def _pass_result(self):
        return EvalResult(dmarc_pass=True, spf_aligned=True, dkim_aligned=True,
                          policy_applied=False, detail="pass")

    def _fail_result(self):
        return EvalResult(dmarc_pass=False, spf_aligned=False, dkim_aligned=False,
                          policy_applied=True, detail="fail")

    def test_all_pass(self):
        results = [self._pass_result(), self._pass_result()]
        counts = [10, 5]
        stats = compute_report_stats(results, counts)
        assert stats["total"] == 15
        assert stats["pass"] == 15
        assert stats["fail"] == 0
        assert stats["pass_rate"] == 100.0

    def test_all_fail(self):
        results = [self._fail_result()]
        counts = [7]
        stats = compute_report_stats(results, counts)
        assert stats["total"] == 7
        assert stats["fail"] == 7
        assert stats["pass_rate"] == 0.0

    def test_mixed(self):
        results = [self._pass_result(), self._fail_result()]
        counts = [3, 7]
        stats = compute_report_stats(results, counts)
        assert stats["total"] == 10
        assert stats["pass"] == 3
        assert stats["fail"] == 7
        assert stats["pass_rate"] == 30.0

    def test_empty(self):
        stats = compute_report_stats([], [])
        assert stats["total"] == 0
        assert stats["pass_rate"] is None
