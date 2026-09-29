"""
Senders with names: which service sends the mail that arrives from a source IP.

Evidence, strongest first:
1. the host name of the address, confirmed by a forward lookup (anyone can set a PTR record, only the
   owner of the name can make it resolve back),
2. a passing DKIM signature from a domain of the service,
3. SPF pass for a bounce domain of the service.

The catalog in app/data/sender_catalog.json names the services; SENDER_CATALOG_PATH adds or replaces
entries. A decision about a sender (trusted, suspicious, ignored) applies to all of its addresses in the
organisation, including addresses that show up later. A decision a person made for one address stays.
"""
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import settings
from app.models import DmarcAuthResult, DmarcRecord, SenderApproval, SourceIp
from app.security import utcnow
from app.services.sender_lookup import LookupResult, lookup

logger = logging.getLogger(__name__)

BUILTIN_CATALOG = Path(__file__).resolve().parent.parent / "data" / "sender_catalog.json"
KINDS = {"mailbox": "Postfachanbieter", "esp": "Versanddienst", "app": "Anwendung", "hosting": "Webhoster"}
DECISIONS = ("trusted", "suspicious", "ignored")
DECISION_REASON = {
    "trusted": "Freigabe für {name}",
    "suspicious": "{name} als verdächtig eingestuft",
    "ignored": "{name} wird ignoriert",
}
KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
SUFFIX_PATTERN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


@dataclass(frozen=True)
class Sender:
    key: str
    name: str
    kind: str
    rdns: tuple[str, ...] = ()
    dkim: tuple[str, ...] = ()
    spf: tuple[str, ...] = ()

    @property
    def kind_label(self) -> str:
        return KINDS.get(self.kind, self.kind)


@dataclass
class Catalog:
    senders: dict[str, Sender]
    problems: list[str] = field(default_factory=list)

    def get(self, key: str | None) -> Sender | None:
        return self.senders.get(key) if key else None

    def name(self, key: str | None) -> str | None:
        sender = self.get(key)
        return sender.name if sender else key


# Catalog -------------------------------------------------------------------------------

def _suffixes(entry: dict, name: str, where: str, problems: list[str]) -> tuple[str, ...]:
    values = entry.get(name, [])
    if not isinstance(values, list):
        problems.append(f"{where}: „{name}“ muss eine Liste von Domains sein.")
        return ()
    good = []
    for value in values:
        suffix = str(value).strip().strip(".").lower()
        if SUFFIX_PATTERN.match(suffix):
            good.append(suffix)
        else:
            problems.append(f"{where}: „{value}“ in „{name}“ ist keine Domain.")
    return tuple(good)


def parse_catalog(data: object, origin: str) -> tuple[dict[str, Sender], list[str]]:
    """Senders from catalog data; entries with errors are skipped and described in the problems."""
    problems: list[str] = []
    entries = data.get("senders") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return {}, [f"{origin}: Die Datei braucht eine Liste „senders“."]
    senders: dict[str, Sender] = {}
    for index, entry in enumerate(entries, start=1):
        where = f"{origin}, Eintrag {index}"
        if not isinstance(entry, dict):
            problems.append(f"{where}: Jeder Eintrag muss ein Objekt mit key, name und kind sein.")
            continue
        key = str(entry.get("key", "")).strip().lower()
        name = str(entry.get("name", "")).strip()
        kind = str(entry.get("kind", "")).strip()
        if not KEY_PATTERN.match(key):
            problems.append(f"{where}: Der Schlüssel „{key}“ darf nur Kleinbuchstaben, Ziffern und - enthalten "
                            "und muss 2 bis 64 Zeichen lang sein.")
            continue
        if not name:
            problems.append(f"{where}: Für „{key}“ fehlt der Name.")
            continue
        if kind not in KINDS:
            problems.append(f"{where}: Die Art „{kind}“ gibt es nicht; erlaubt sind {', '.join(KINDS)}.")
            continue
        senders[key] = Sender(
            key=key, name=name[:100], kind=kind,
            rdns=_suffixes(entry, "rdns", where, problems),
            dkim=_suffixes(entry, "dkim", where, problems),
            spf=_suffixes(entry, "spf", where, problems),
        )
    return senders, problems


def _read(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


_cache: dict[tuple, Catalog] = {}


def load_catalog() -> Catalog:
    """Built-in catalog plus the entries of SENDER_CATALOG_PATH; problems of the extra file are listed."""
    extra = settings.SENDER_CATALOG_PATH.strip()
    extra_path = Path(extra) if extra else None
    try:
        stamp = extra_path.stat().st_mtime if extra_path else None
    except OSError:
        stamp = "missing"
    cache_key = (extra, stamp)
    if cache_key in _cache:
        return _cache[cache_key]

    try:
        senders, problems = parse_catalog(_read(BUILTIN_CATALOG), "Eingebauter Katalog")
    except (OSError, ValueError) as exc:
        senders, problems = {}, [f"Der eingebaute Absenderkatalog ließ sich nicht lesen ({exc.__class__.__name__}). "
                                 "Das Abbild ist unvollständig; ziehe es erneut."]
    if extra_path:
        try:
            added, extra_problems = parse_catalog(_read(extra_path), extra)
        except FileNotFoundError:
            added, extra_problems = {}, [f"Der zusätzliche Absenderkatalog {extra} fehlt. Prüfe SENDER_CATALOG_PATH."]
        except (OSError, ValueError) as exc:
            added, extra_problems = {}, [f"Der zusätzliche Absenderkatalog {extra} ließ sich nicht lesen ({exc}). "
                                         "Prüfe, ob die Datei gültiges JSON enthält."]
        senders.update(added)
        problems.extend(extra_problems)
    for problem in problems:
        logger.warning("Sender catalog: %s", problem)
    catalog = Catalog(senders=senders, problems=problems)
    _cache.clear()
    _cache[cache_key] = catalog
    return catalog


# Identification -------------------------------------------------------------------------

@dataclass
class Identification:
    sender: Sender | None = None
    evidence: str | None = None


def _match(name: str, suffixes: tuple[str, ...]) -> bool:
    return any(name == suffix or name.endswith("." + suffix) for suffix in suffixes)


def identify(catalog: Catalog, reverse_dns: str | None, confirmed: bool,
             dkim_domains: list[str], spf_domains: list[str]) -> Identification:
    host = (reverse_dns or "").lower().rstrip(".")
    if host and confirmed:
        for sender in catalog.senders.values():
            if _match(host, sender.rdns):
                return Identification(sender, f"Hostname {host}")
    for domain in dkim_domains:
        for sender in catalog.senders.values():
            if _match(domain, sender.dkim):
                return Identification(sender, f"DKIM-Signatur von {domain}")
    for domain in spf_domains:
        for sender in catalog.senders.values():
            if _match(domain, sender.spf):
                return Identification(sender, f"SPF für {domain}")
    return Identification()


def auth_evidence(db: Session, org_id: str, ip: str) -> tuple[list[str], list[str]]:
    """Domains with passing DKIM and SPF results in the records of one address."""
    rows = (
        db.query(DmarcAuthResult.auth_type, DmarcAuthResult.domain)
        .join(DmarcRecord, DmarcAuthResult.record_id == DmarcRecord.id)
        .filter(
            DmarcRecord.organization_id == org_id,
            DmarcRecord.source_ip == ip,
            DmarcAuthResult.result == "pass",
            DmarcAuthResult.domain.isnot(None),
        )
        .distinct()
        .limit(settings.SENDER_EVIDENCE_LIMIT)
        .all()
    )
    dkim = sorted({domain.lower().rstrip(".") for kind, domain in rows if kind == "dkim"})
    spf = sorted({domain.lower().rstrip(".") for kind, domain in rows if kind == "spf"})
    return dkim, spf


# Decisions ------------------------------------------------------------------------------

def decisions(db: Session, org_id: str) -> dict[str, SenderApproval]:
    return {a.sender_key: a for a in db.query(SenderApproval).filter_by(organization_id=org_id)}


def apply_decision(source: SourceIp, approval: SenderApproval | None, catalog: Catalog) -> bool:
    """Take over the decision about the sender of an address, unless a person decided about the address."""
    if source.classification_source == "manual":
        return False
    if approval is None:
        if source.classification_source != "sender":
            return False
        source.classification = "unknown"
        source.classification_source = None
        source.classification_reason = None
        source.classified_at = None
        return True
    reason = DECISION_REASON[approval.classification].format(name=catalog.name(approval.sender_key))
    if (source.classification, source.classification_source, source.classification_reason) == (
            approval.classification, "sender", reason):
        return False
    source.classification = approval.classification
    source.classification_source = "sender"
    source.classification_reason = reason
    source.classified_at = approval.decided_at
    return True


def decide(db: Session, org_id: str, sender_key: str, decision: str, user_id: str | None) -> int:
    """Record or remove (decision "reset") a decision and apply it; returns the number of changed addresses."""
    approval = db.query(SenderApproval).filter_by(organization_id=org_id, sender_key=sender_key).first()
    if decision == "reset":
        if approval is not None:
            db.delete(approval)
        approval = None
    else:
        if decision not in DECISIONS:
            raise ValueError(decision)
        if approval is None:
            approval = SenderApproval(organization_id=org_id, sender_key=sender_key)
            db.add(approval)
        approval.classification = decision
        approval.decided_by = user_id
        approval.decided_at = utcnow()
    db.flush()
    catalog = load_catalog()
    changed = 0
    for source in db.query(SourceIp).filter_by(organization_id=org_id, sender_key=sender_key):
        changed += apply_decision(source, approval, catalog)
    db.flush()
    return changed


def classify_manually(source: SourceIp, classification: str, user_id: str, db: Session) -> None:
    """A person decides about one address; "unknown" hands the address back to the decision about its sender."""
    now = utcnow()
    if classification == "unknown":
        source.classification = "unknown"
        source.classification_source = None
        source.classification_reason = None
        source.classified_by = user_id
        source.classified_at = now
        if source.sender_key:
            approval = decisions(db, source.organization_id).get(source.sender_key)
            apply_decision(source, approval, load_catalog())
        return
    source.classification = classification
    source.classification_source = "manual"
    source.classification_reason = None
    source.classified_by = user_id
    source.classified_at = now


# Identifying sources ------------------------------------------------------------------------

@dataclass
class RefreshResult:
    checked: int = 0
    identified: int = 0
    organizations: set[str] = field(default_factory=set)


def _lookups(ips: list[str]) -> dict[str, LookupResult]:
    if not settings.SENDER_LOOKUP_ENABLED or not ips:
        return {ip: LookupResult() for ip in ips}
    with ThreadPoolExecutor(max_workers=min(settings.SENDER_LOOKUP_WORKERS, len(ips))) as pool:
        return dict(zip(ips, pool.map(lookup, ips), strict=True))


def _update_lookup(source: SourceIp, found: LookupResult) -> None:
    # A failed lookup keeps what an earlier one found
    if found.reverse_dns:
        source.reverse_dns = found.reverse_dns[:255]
        source.reverse_dns_confirmed = found.reverse_dns_confirmed
    if found.asn:
        source.asn = found.asn[:20]
        source.asn_org = (found.asn_org or "")[:255] or None
    if found.country_code:
        source.country_code = found.country_code


def identify_source(db: Session, source: SourceIp, catalog: Catalog, approvals: dict[str, SenderApproval],
                    now: datetime, found: LookupResult | None = None) -> bool:
    """Look at the evidence of one address, name its sender and apply the decision about it."""
    if found is not None:
        _update_lookup(source, found)
    dkim, spf = auth_evidence(db, source.organization_id, source.ip_address)
    result = identify(catalog, source.reverse_dns, bool(source.reverse_dns_confirmed), dkim, spf)
    source.sender_key = result.sender.key if result.sender else None
    source.sender_evidence = result.evidence[:300] if result.evidence else None
    source.enriched_at = now
    apply_decision(source, approvals.get(source.sender_key) if source.sender_key else None, catalog)
    return result.sender is not None


def refresh_sources(db: Session, now: datetime | None = None, organization_id: str | None = None,
                    limit: int | None = None, everything: bool = False) -> RefreshResult:
    """Identify new sources and those not looked at for SENDER_LOOKUP_REFRESH_DAYS."""
    now = now or utcnow()
    query = db.query(SourceIp)
    if organization_id:
        query = query.filter(SourceIp.organization_id == organization_id)
    if not everything:
        stale = now - timedelta(days=settings.SENDER_LOOKUP_REFRESH_DAYS)
        query = query.filter(or_(SourceIp.enriched_at.is_(None), SourceIp.enriched_at < stale))
    sources = (
        query.order_by(SourceIp.enriched_at.isnot(None), SourceIp.total_messages.desc())
        .limit(limit or settings.SENDER_LOOKUP_BATCH_SIZE)
        .all()
    )
    result = RefreshResult()
    if not sources:
        return result
    found = _lookups(sorted({s.ip_address for s in sources}))
    catalog = load_catalog()
    approvals_by_org: dict[str, dict[str, SenderApproval]] = {}
    for source in sources:
        approvals = approvals_by_org.setdefault(source.organization_id, decisions(db, source.organization_id))
        result.identified += identify_source(db, source, catalog, approvals, now, found[source.ip_address])
        result.checked += 1
        result.organizations.add(source.organization_id)
    db.flush()
    logger.info("Senders: %d sources checked, %d identified", result.checked, result.identified)
    return result


def sender_label(source: SourceIp) -> str | None:
    """Name of the sender of an address, else its host name or operator."""
    return load_catalog().name(source.sender_key) if source.sender_key else (source.reverse_dns or source.asn_org)
