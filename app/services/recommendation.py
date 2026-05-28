"""
Rule-based recommendation engine for DMARC domains.
No AI/ML. All logic is deterministic and explainable.
"""
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Domain, DmarcRecord, DmarcReport, InboundMailAddress, SourceIp


@dataclass
class Recommendation:
    code: str
    severity: str  # info, warning, critical
    title: str
    description: str
    data_basis: str


def get_recommendations_for_domain(db: Session, org_id: str, domain_id: str) -> list[Recommendation]:
    recs: list[Recommendation] = []
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org_id).first()
    if not domain:
        return recs

    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)
    seven_days_ago = now - timedelta(days=7)

    # --- Check if any inbound address is configured ---
    has_address = (
        db.query(InboundMailAddress)
        .filter_by(organization_id=org_id, domain_id=domain_id, status="active")
        .first()
        is not None
    )
    if not has_address:
        has_org_address = (
            db.query(InboundMailAddress)
            .filter_by(organization_id=org_id, status="active")
            .filter(InboundMailAddress.domain_id.is_(None))
            .first()
            is not None
        )
        if not has_org_address:
            recs.append(Recommendation(
                code="NO_INBOUND_ADDRESS",
                severity="warning",
                title="No active report address configured",
                description=(
                    "This domain has no active inbound mail address for DMARC reports. "
                    "Without a configured rua address, this application cannot receive DMARC reports."
                ),
                data_basis="No active InboundMailAddress found for this domain or organization.",
            ))

    # --- Check for missing recent reports ---
    recent_report = (
        db.query(DmarcReport)
        .filter_by(organization_id=org_id, domain_id=domain_id)
        .filter(DmarcReport.created_at >= seven_days_ago)
        .first()
    )
    if not recent_report:
        last_report = (
            db.query(DmarcReport)
            .filter_by(organization_id=org_id, domain_id=domain_id)
            .order_by(DmarcReport.created_at.desc())
            .first()
        )
        if last_report is None:
            recs.append(Recommendation(
                code="NO_REPORTS_EVER",
                severity="warning",
                title="No DMARC reports received yet",
                description=(
                    "No DMARC aggregate reports have been received for this domain. "
                    "Check that the DMARC record contains the correct rua address, "
                    "and that the DNS record is published correctly."
                ),
                data_basis="Zero DmarcReport records found for this domain.",
            ))
        else:
            days_since = (now - last_report.created_at).days
            recs.append(Recommendation(
                code="REPORTS_STALE",
                severity="info",
                title=f"No reports received in the last 7 days",
                description=(
                    f"The last report was received {days_since} day(s) ago. "
                    "This may indicate the sending domain has stopped sending, "
                    "or the rua address in the DMARC record needs updating."
                ),
                data_basis=f"Last report: {last_report.created_at.date()}",
            ))

    # --- Analyse recent records ---
    records = (
        db.query(DmarcRecord)
        .join(DmarcReport)
        .filter(
            DmarcReport.organization_id == org_id,
            DmarcReport.domain_id == domain_id,
            DmarcReport.created_at >= thirty_days_ago,
        )
        .all()
    )

    if not records:
        return recs

    total_msgs = sum(r.count for r in records)
    pass_msgs = sum(r.count for r in records if r.dmarc_pass)
    fail_msgs = total_msgs - pass_msgs
    pass_rate = pass_msgs / total_msgs * 100 if total_msgs > 0 else 0

    unknown_ips = (
        db.query(SourceIp)
        .filter_by(organization_id=org_id, classification="unknown")
        .filter(SourceIp.ip_address.in_([r.source_ip for r in records]))
        .count()
    )

    # --- pct < 100 ---
    if domain.dmarc_policy_pct is not None and domain.dmarc_policy_pct < 100:
        recs.append(Recommendation(
            code="PCT_LESS_THAN_100",
            severity="info",
            title=f"Policy pct={domain.dmarc_policy_pct}% — only partial enforcement",
            description=(
                f"The DMARC policy is only applied to {domain.dmarc_policy_pct}% of messages. "
                "This is common during a rollout but should be raised to 100% once the policy is validated."
            ),
            data_basis=f"policy_pct={domain.dmarc_policy_pct} from last parsed report.",
        ))

    # --- Policy none with high pass rate ---
    if domain.dmarc_policy == "none" and pass_rate >= 95 and total_msgs >= 100:
        recs.append(Recommendation(
            code="READY_FOR_QUARANTINE",
            severity="info",
            title="Domain may be ready for policy: quarantine",
            description=(
                f"Pass rate is {pass_rate:.1f}% over the last 30 days ({total_msgs} messages). "
                "This is a strong signal that moving to p=quarantine is safe, "
                "provided all sending sources have been verified."
            ),
            data_basis=f"pass_rate={pass_rate:.1f}%, total_msgs={total_msgs}, policy=none",
        ))

    # --- Policy quarantine with high pass rate ---
    if domain.dmarc_policy == "quarantine" and pass_rate >= 99 and total_msgs >= 100 and unknown_ips == 0:
        recs.append(Recommendation(
            code="READY_FOR_REJECT",
            severity="info",
            title="Domain may be ready for policy: reject",
            description=(
                f"Pass rate is {pass_rate:.1f}% with no unknown sources. "
                "You could consider moving to p=reject for maximum protection."
            ),
            data_basis=f"pass_rate={pass_rate:.1f}%, unknown_ips=0",
        ))

    # --- High fail rate ---
    fail_rate = fail_msgs / total_msgs * 100 if total_msgs > 0 else 0
    if fail_rate > 20 and total_msgs >= 20:
        recs.append(Recommendation(
            code="HIGH_FAIL_RATE",
            severity="warning",
            title=f"High DMARC fail rate: {fail_rate:.1f}%",
            description=(
                f"{fail_msgs} of {total_msgs} messages failed DMARC in the last 30 days. "
                "Review failing source IPs and check SPF/DKIM configuration."
            ),
            data_basis=f"fail_rate={fail_rate:.1f}%, fail_msgs={fail_msgs}, total={total_msgs}",
        ))

    # --- quarantine/reject with high fail rate ---
    if domain.dmarc_policy in ("quarantine", "reject") and fail_rate > 10 and total_msgs >= 20:
        recs.append(Recommendation(
            code="POLICY_ACTIVE_FAILURES",
            severity="critical",
            title=f"Policy {domain.dmarc_policy} is active but {fail_rate:.1f}% of messages fail",
            description=(
                f"Your policy is set to {domain.dmarc_policy} but {fail_rate:.1f}% of messages "
                "are failing DMARC. Legitimate email may be quarantined or rejected. "
                "Investigate failing sources immediately."
            ),
            data_basis=f"policy={domain.dmarc_policy}, fail_rate={fail_rate:.1f}%",
        ))

    # --- Unknown sources sending mail ---
    if unknown_ips > 0:
        recs.append(Recommendation(
            code="UNKNOWN_SOURCES",
            severity="warning",
            title=f"{unknown_ips} unknown sending source(s) detected",
            description=(
                f"{unknown_ips} source IP(s) have been observed sending mail for this domain "
                "but have not been classified. Review them in the Source IPs view."
            ),
            data_basis=f"unknown_ips={unknown_ips}",
        ))

    # --- SPF pass but DKIM fail ---
    spf_only_records = [r for r in records if r.spf_aligned and not r.dkim_aligned]
    spf_only_count = sum(r.count for r in spf_only_records)
    if spf_only_count > 0 and total_msgs > 0:
        pct = spf_only_count / total_msgs * 100
        if pct >= 5:
            recs.append(Recommendation(
                code="DKIM_MISSING_FOR_SPF_SENDERS",
                severity="info",
                title=f"{pct:.1f}% of messages pass only via SPF (no DKIM alignment)",
                description=(
                    "SPF alignment is sufficient for DMARC to pass, but DKIM signing adds "
                    "resilience especially for forwarded mail. Consider adding DKIM signing "
                    "to sources that currently lack it."
                ),
                data_basis=f"spf_only_msgs={spf_only_count}, total={total_msgs}",
            ))

    return recs
