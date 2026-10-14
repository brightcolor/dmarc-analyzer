"""
Source rules: networks, countries and host names from the settings that classify a source IP by themselves.

A rule applies to a source that has no decision yet and has never passed DMARC (SOURCE_RULE_MAX_PASSED_MESSAGES).
It sets the classification SOURCE_RULE_CLASSIFICATION and marks it with the origin "rule". A decision about the
address, about its sender or by a person always comes first; a rule never replaces one.
"""
import re

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import settings
from app.models import SourceIp
from app.security import utcnow

RULE_ORIGIN = "rule"
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")

# The rule settings the last full pass applied; a change makes the next pass look at every source again
_applied: tuple | None = None


def _signature() -> tuple:
    return (
        settings.SOURCE_RULES_ENABLED, settings.SOURCE_RULE_CLASSIFICATION, settings.SOURCE_RULE_MAX_PASSED_MESSAGES,
        tuple(sorted(settings.source_rule_asns)), tuple(sorted(settings.source_rule_countries)),
        tuple(settings.source_rule_rdns_patterns),
    )


def _host_matches(host: str, pattern: str) -> bool:
    if "." in pattern:
        return host == pattern or host.endswith("." + pattern)
    return pattern in _TOKEN_SPLIT.split(host)


def match(source: SourceIp) -> str | None:
    """The reason a rule applies to the source, else None."""
    if not settings.SOURCE_RULES_ENABLED or source.pass_count > settings.SOURCE_RULE_MAX_PASSED_MESSAGES:
        return None
    asn = (source.asn or "").strip().upper().removeprefix("AS")
    if asn and asn in settings.source_rule_asns:
        operator = f" ({source.asn_org})" if source.asn_org else ""
        return f"Das Netz AS{asn}{operator} steht in den Quellenregeln"
    country = (source.country_code or "").strip().upper()
    if country and country in settings.source_rule_countries:
        return f"Das Land {country} steht in den Quellenregeln"
    host = (source.reverse_dns or "").strip().strip(".").lower()
    if host:
        for pattern in settings.source_rule_rdns_patterns:
            if _host_matches(host, pattern):
                return f"Der Hostname {host} passt zum Muster „{pattern}“ der Quellenregeln"
    return None


def apply_rules(source: SourceIp) -> bool:
    """Classify the source by the rules, or hand it back when no rule applies any more; True when it changed."""
    if source.classification_source in ("manual", "sender"):
        return False
    if source.classification != "unknown" and source.classification_source != RULE_ORIGIN:
        return False
    reason = match(source)
    if reason is None:
        if source.classification_source != RULE_ORIGIN:
            return False
        source.classification = "unknown"
        source.classification_source = None
        source.classification_reason = None
        source.classified_at = None
        return True
    wanted = settings.SOURCE_RULE_CLASSIFICATION
    if (source.classification, source.classification_source, source.classification_reason) == (
            wanted, RULE_ORIGIN, reason):
        return False
    source.classification = wanted
    source.classification_source = RULE_ORIGIN
    source.classification_reason = reason
    source.classified_by = None
    source.classified_at = utcnow()
    return True


def apply_rules_all(db: Session, organization_id: str | None = None, force: bool = False) -> int:
    """Apply the rules to every source without a decision; returns the number of changed sources.

    Runs only when the rule settings differ from the last full pass, or when force is set. Addresses that
    show up later get their classification when they are identified."""
    global _applied
    signature = _signature()
    if not force and organization_id is None and signature == _applied:
        return 0
    query = db.query(SourceIp).filter(
        or_(SourceIp.classification == "unknown", SourceIp.classification_source == RULE_ORIGIN),
    )
    if organization_id:
        query = query.filter(SourceIp.organization_id == organization_id)
    changed = sum(apply_rules(source) for source in query)
    db.flush()
    if organization_id is None:
        _applied = signature
    return changed
