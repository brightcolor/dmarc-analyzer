"""
Builds the suggested DMARC DNS record for a domain.

The record stays readable for receivers of both standards: RFC 7489 receivers ignore t and np,
RFC 9989 receivers ignore pct. With failure reports switched on, the same address goes into ruf, and fo=1 asks
receivers to report as soon as SPF or DKIM fails.
"""
from app.config import settings
from app.models import Domain


def suggest_dmarc_record(domain: Domain, rua_address: str) -> str:
    policy = domain.dmarc_policy or "none"
    tags = ["v=DMARC1", f"p={policy}"]
    if domain.dmarc_policy_sp and domain.dmarc_policy_sp != policy:
        tags.append(f"sp={domain.dmarc_policy_sp}")
    if domain.dmarc_policy_np:
        tags.append(f"np={domain.dmarc_policy_np}")
    if (domain.dmarc_policy_testing or "").lower() == "y":
        tags.append("t=y")
    if domain.dmarc_policy_pct is not None and domain.dmarc_policy_pct < 100:
        tags.append(f"pct={domain.dmarc_policy_pct}")
    tags.append(f"rua=mailto:{rua_address}")
    if settings.FAILURE_REPORTS_ENABLED and settings.DMARC_SUGGEST_FAILURE_REPORTS:
        tags += [f"ruf=mailto:{rua_address}", "fo=1"]
    return "; ".join(tags)
