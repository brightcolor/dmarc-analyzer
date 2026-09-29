"""Suggested DMARC DNS record for receivers of both standards."""
from app.models import Domain
from app.services.dmarc_record import suggest_dmarc_record

RUA = "org-abc@reports.example.org"


def _domain(**policy) -> Domain:
    return Domain(name="example.com", organization_id="org-1", **policy)


def test_minimal_record():
    assert suggest_dmarc_record(_domain(), RUA) == f"v=DMARC1; p=none; rua=mailto:{RUA}"


def test_pct_zero_is_kept():
    record = suggest_dmarc_record(_domain(dmarc_policy="reject", dmarc_policy_pct=0), RUA)
    assert "pct=0" in record


def test_full_pct_is_left_out():
    assert "pct" not in suggest_dmarc_record(_domain(dmarc_policy="reject", dmarc_policy_pct=100), RUA)


def test_testing_mode_is_kept():
    assert "t=y" in suggest_dmarc_record(_domain(dmarc_policy="reject", dmarc_policy_testing="y"), RUA)


def test_testing_n_is_left_out():
    assert "t=" not in suggest_dmarc_record(_domain(dmarc_policy="reject", dmarc_policy_testing="n"), RUA)


def test_subdomain_policies_are_kept():
    record = suggest_dmarc_record(
        _domain(dmarc_policy="reject", dmarc_policy_sp="quarantine", dmarc_policy_np="reject"), RUA
    )
    assert record == f"v=DMARC1; p=reject; sp=quarantine; np=reject; rua=mailto:{RUA}"


def test_sp_equal_to_p_is_left_out():
    assert "sp=" not in suggest_dmarc_record(_domain(dmarc_policy="reject", dmarc_policy_sp="reject"), RUA)
