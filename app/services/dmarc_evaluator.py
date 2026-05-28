"""
DMARC evaluation logic per RFC 7489.

All rules are pure functions operating on plain data structures
so they can be tested in isolation without a database.
"""
from dataclasses import dataclass, field


@dataclass
class AuthResultEntry:
    auth_type: str    # "dkim" or "spf"
    domain: str
    result: str       # pass/fail/neutral/softfail/none/permerror/temperror
    selector: str | None = None  # DKIM only
    scope: str | None = None     # SPF only ("mfrom" or "helo")


@dataclass
class RecordEvalInput:
    source_ip: str
    count: int
    header_from: str          # organizational domain used for alignment
    envelope_from: str | None
    dkim_result: str | None  # row-level result (may be None)
    spf_result: str | None   # row-level result (may be None)
    auth_results: list[AuthResultEntry] = field(default_factory=list)


@dataclass
class PolicyConfig:
    domain: str
    adkim: str = "r"   # r = relaxed, s = strict
    aspf: str = "r"    # r = relaxed, s = strict
    p: str = "none"    # none / quarantine / reject
    sp: str = "none"   # subdomain policy
    pct: int = 100


@dataclass
class EvalResult:
    dmarc_pass: bool
    spf_aligned: bool
    dkim_aligned: bool
    policy_applied: bool
    detail: str


def _organizational_domain(fqdn: str) -> str:
    """
    Minimal organizational domain extraction (no Public Suffix List).
    Takes the last two labels (e.g. mail.example.com → example.com).
    A proper implementation should use the Public Suffix List.
    """
    if not fqdn:
        return ""
    parts = fqdn.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def _domains_aligned(d1: str, d2: str, mode: str) -> bool:
    """
    Check alignment between two domain names.
    Strict: exact match.
    Relaxed: organizational domain match.
    """
    if not d1 or not d2:
        return False
    d1 = d1.lower().strip()
    d2 = d2.lower().strip()
    if mode == "s":
        return d1 == d2
    # relaxed
    return _organizational_domain(d1) == _organizational_domain(d2)


def evaluate_record(record: RecordEvalInput, policy: PolicyConfig) -> EvalResult:
    """
    Evaluate a single DMARC record row.

    DMARC passes if at least one authenticated mechanism (SPF or DKIM)
    passes AND is aligned with the RFC5322.From domain.
    """
    is_subdomain = record.header_from.lower().rstrip(".") != policy.domain.lower().rstrip(".")

    # Effective subdomain policy
    effective_p = policy.p
    if is_subdomain and policy.sp:
        effective_p = policy.sp

    # --- DKIM alignment check ---
    dkim_aligned = False
    for ar in record.auth_results:
        if ar.auth_type != "dkim":
            continue
        if ar.result != "pass":
            continue
        if _domains_aligned(ar.domain, record.header_from, policy.adkim):
            dkim_aligned = True
            break

    # Fall back to row-level result if no detailed auth_results present
    if not dkim_aligned and record.dkim_result == "pass":
        # We have to trust the row-level result; assume aligned (common in older reports)
        dkim_aligned = True

    # --- SPF alignment check ---
    spf_aligned = False
    for ar in record.auth_results:
        if ar.auth_type != "spf":
            continue
        if ar.result not in ("pass",):
            continue
        if _domains_aligned(ar.domain, record.header_from, policy.aspf):
            spf_aligned = True
            break

    if not spf_aligned and record.spf_result == "pass":
        # Fallback: if envelope_from aligned, mark as SPF-aligned
        if record.envelope_from:
            ef_domain = record.envelope_from.split("@")[-1] if "@" in record.envelope_from else record.envelope_from
            if _domains_aligned(ef_domain, record.header_from, policy.aspf):
                spf_aligned = True

    dmarc_pass = dkim_aligned or spf_aligned

    # Policy enforcement: policy_applied = True when mail was acted on per policy
    policy_applied = dmarc_pass is False and effective_p in ("quarantine", "reject")

    if dmarc_pass:
        detail = "DMARC pass"
        if dkim_aligned and spf_aligned:
            detail = "DMARC pass (DKIM aligned + SPF aligned)"
        elif dkim_aligned:
            detail = "DMARC pass (DKIM aligned)"
        else:
            detail = "DMARC pass (SPF aligned)"
    else:
        parts = []
        if not dkim_aligned:
            parts.append("DKIM not aligned")
        if not spf_aligned:
            parts.append("SPF not aligned")
        detail = "DMARC fail: " + "; ".join(parts)

    return EvalResult(
        dmarc_pass=dmarc_pass,
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        policy_applied=policy_applied,
        detail=detail,
    )


def compute_report_stats(records: list[EvalResult], counts: list[int]) -> dict:
    """Compute aggregate pass/fail statistics for a report."""
    total = sum(counts)
    if total == 0:
        return {"total": 0, "pass": 0, "fail": 0, "pass_rate": None}
    pass_total = sum(c for r, c in zip(records, counts, strict=False) if r.dmarc_pass)
    fail_total = total - pass_total
    return {
        "total": total,
        "pass": pass_total,
        "fail": fail_total,
        "pass_rate": round(pass_total / total * 100, 2),
    }
