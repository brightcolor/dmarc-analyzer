"""
DNS check per domain: are the records in place that DMARC and this application need?

- DMARC at _dmarc.<domain>, or inherited from the organizational domain: one record with valid tags
- rua and ruf name a report address of the organisation
- consent of the report domain at <domain>._report._dmarc.<report domain> (RFC 7489, 7.1)
- SPF: one record, a closing all, at most 10 DNS lookups (RFC 7208, 4.6.4)
- DKIM: the keys of the selectors that passed DKIM in recent reports, with their length (RFC 8301)
- MX with resolvable hosts, and TLS reporting at _smtp._tls.<domain> (RFC 8460)

Every check ends in ok, info, warning or error. A lookup that times out or fails leaves its check "unknown";
the next run tries again. The scheduler checks each active domain again after DNS_CHECK_MAX_AGE_SECONDS.
"""
import base64
import binascii
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

import dns.exception
import dns.name
import dns.resolver
from sqlalchemy import func, or_, update
from sqlalchemy.orm import Session

from app.config import settings
from app.models import DmarcAuthResult, DmarcRecord, DmarcReport, Domain, Organization
from app.services.dmarc_evaluator import _organizational_domain
from app.services.dmarc_record import suggest_dmarc_record
from app.services.inbound_address import active_addresses, report_address
from app.services.text import clean_text
from app.services.tls_reports import suggest_tls_record

logger = logging.getLogger(__name__)

OK, INFO, WARNING, ERROR, UNKNOWN = "ok", "info", "warning", "error", "unknown"
STATES = (ERROR, WARNING, UNKNOWN, INFO, OK)

# Limits from the standards
SPF_LOOKUP_LIMIT = 10          # RFC 7208, 4.6.4
SPF_MAX_DEPTH = 10             # longest include chain the check follows
DKIM_MIN_RSA_BITS = 1024       # RFC 8301, 3.2
ED25519_KEY_BYTES = 32         # RFC 8463
DER_MAX_DEPTH = 2              # SubjectPublicKeyInfo around an RSAPublicKey, nothing deeper
DMARC_RI_MAX = 4_294_967_295   # RFC 7489, 6.3: ri is a 32-bit unsigned integer

DMARC_POLICIES = ("none", "quarantine", "reject")
DMARC_KNOWN_TAGS = ("v", "p", "sp", "np", "t", "pct", "rua", "ruf", "fo", "adkim", "aspf", "rf", "ri", "psd")
SPF_MECHANISMS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")
SPF_COUNTED = ("include", "a", "mx", "ptr", "exists")


class LookupFailed(Exception):
    """The DNS server gave no usable answer (timeout, server failure); the name may still exist."""


# Lookups ------------------------------------------------------------------------------------

class Resolver:
    """TXT, MX and address lookups with the time limit of the check; answers are kept for one check."""

    def __init__(self, deadline: float | None = None) -> None:
        self._resolver = dns.resolver.Resolver()
        if settings.dns_nameservers:
            self._resolver.nameservers = settings.dns_nameservers
        self._resolver.lifetime = settings.DNS_CHECK_TIMEOUT_SECONDS
        self._resolver.timeout = settings.DNS_CHECK_TIMEOUT_SECONDS
        self._deadline = deadline  # time.monotonic() value; after it no lookup starts
        self._budget_logged = False
        self._cache: dict[tuple[str, str], list] = {}

    @classmethod
    def for_one_domain(cls) -> "Resolver":
        """Resolver whose lookups together stay within DNS_CHECK_DOMAIN_BUDGET_SECONDS."""
        return cls(deadline=time.monotonic() + settings.DNS_CHECK_DOMAIN_BUDGET_SECONDS)

    def _answer(self, name: str, rdtype: str):
        if self._deadline is not None:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                if not self._budget_logged:
                    self._budget_logged = True
                    logger.warning("DNS check budget used up before %s %s (DNS_CHECK_DOMAIN_BUDGET_SECONDS=%s)",
                                   rdtype, name, settings.DNS_CHECK_DOMAIN_BUDGET_SECONDS)
                raise LookupFailed(f"{rdtype} {name}: Zeitbudget der Prüfung aufgebraucht")
            self._resolver.lifetime = min(settings.DNS_CHECK_TIMEOUT_SECONDS, remaining)
        try:
            return list(self._resolver.resolve(name, rdtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN, dns.name.NameTooLong,
                dns.name.LabelTooLong, dns.name.EmptyLabel):
            return []
        except (dns.exception.DNSException, OSError) as exc:
            raise LookupFailed(f"{rdtype} {name}: {exc.__class__.__name__}") from exc

    def _cached(self, name: str, rdtype: str, convert) -> list:
        key = (name.lower().rstrip("."), rdtype)
        if key not in self._cache:
            self._cache[key] = [convert(answer) for answer in self._answer(key[0], rdtype)]
        return self._cache[key]

    def txt(self, name: str) -> list[str]:
        return self._cached(name, "TXT", lambda a: clean_text(b"".join(a.strings).decode("utf-8", errors="replace")))

    def mx(self, name: str) -> list[tuple[int, str]]:
        return self._cached(name, "MX", lambda a: (a.preference, a.exchange.to_text().rstrip(".").lower()))

    def addresses(self, name: str) -> list[str]:
        return self._cached(name, "A", lambda a: a.to_text()) + self._cached(name, "AAAA", lambda a: a.to_text())


# Results ------------------------------------------------------------------------------------

@dataclass
class DnsCheck:
    key: str
    title: str
    state: str
    message: str
    record: str | None = None       # DNS name the check looked at
    found: str | None = None        # what that name returned
    suggestion: str | None = None   # value that would fix it


@dataclass
class DnsCheckResult:
    domain: str
    checked_at: datetime
    checks: list[DnsCheck] = field(default_factory=list)

    @property
    def status(self) -> str:
        states = {check.state for check in self.checks}
        for state in (ERROR, WARNING, UNKNOWN):
            if state in states:
                return state
        return OK

    def count(self, state: str) -> int:
        return sum(1 for check in self.checks if check.state == state)

    def to_json(self) -> str:
        return json.dumps({"domain": self.domain, "checked_at": self.checked_at.isoformat(),
                           "checks": [asdict(check) for check in self.checks]}, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str | None) -> "DnsCheckResult | None":
        if not text:
            return None
        try:
            data = json.loads(text)
            checks = [DnsCheck(**check) for check in data.get("checks", [])]
            return cls(domain=data["domain"], checked_at=datetime.fromisoformat(data["checked_at"]), checks=checks)
        except (ValueError, KeyError, TypeError):
            logger.warning("Stored DNS check cannot be read")
            return None


@dataclass
class CheckInput:
    """What a check needs from the database, gathered before the lookups run."""
    domain: str
    addresses: set[str]                 # active report addresses of the organisation, lower case
    report_address: str | None          # the address this domain should name in rua
    dmarc_suggestion: str | None
    tls_suggestion: str | None
    dkim_selectors: list[str] = field(default_factory=list)
    dkim_last_pass: dict[str, datetime] = field(default_factory=dict)  # selector -> newest report with pass


def _failed(key: str, title: str, name: str, exc: LookupFailed) -> DnsCheck:
    return DnsCheck(key, title, UNKNOWN, f"Die DNS-Abfrage für {name} brachte keine Antwort ({exc}). Die nächste "
                                         "Prüfung versucht es erneut.", record=name)


# Tags and addresses -------------------------------------------------------------------------

def parse_tags(text: str) -> list[tuple[str, str | None]]:
    """Tag list of a DMARC, TLS-RPT or DKIM record in written order; a part without = has the value None."""
    tags = []
    for part in text.split(";"):
        if not part.strip():
            continue
        key, sep, value = part.partition("=")
        tags.append((key.strip().lower(), value.strip() if sep else None))
    return tags


def _uris(value: str | None) -> list[str]:
    return [uri.strip() for uri in (value or "").split(",") if uri.strip()]


def _mailto(uri: str) -> str | None:
    """Address of a mailto URI; the size limit after ! (RFC 7489, 6.2) is left out."""
    if not uri.lower().startswith("mailto:"):
        return None
    address = clean_text(unquote(uri[7:]).split("!", 1)[0].split("?", 1)[0], 320, lower=True, single_line=True)
    return address or None


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].rstrip(".")


def _with_address(value: str | None, target: CheckInput) -> str:
    """URI list with the report address of this application; other destinations stay."""
    uris = _uris(value)
    if not any(_mailto(uri) in target.addresses for uri in uris):
        uris.append(f"mailto:{target.report_address}")
    return ",".join(uris)


def _insert_after(tags: list[tuple[str, str]], anchor: str, key: str, value: str) -> None:
    keys = [k for k, _ in tags]
    tags.insert(keys.index(anchor) + 1 if anchor in keys else len(tags), (key, value))


def suggest_from_record(pairs: list[tuple[str, str | None]], target: CheckInput) -> str | None:
    """The live DMARC record with the report address in rua (and in ruf with fo=1, when wanted).

    Policy, alignment and every other tag stay as they are, so the fix changes only what the check found.
    """
    if not target.report_address:
        return None
    want_ruf = settings.FAILURE_REPORTS_ENABLED and settings.DMARC_SUGGEST_FAILURE_REPORTS
    tags: list[tuple[str, str]] = []
    for key, value in pairs:
        if value is None or key in {k for k, _ in tags}:
            continue
        if key == "v":
            value = "DMARC1"
        elif key == "rua" or (key == "ruf" and want_ruf):
            value = _with_address(value, target)
        elif key == "fo" and want_ruf:
            parts = [part.strip() for part in value.split(":") if part.strip() and part.strip() != "0"]
            value = ":".join(["1"] + [part for part in parts if part != "1"])
        tags.append((key, value))
    if not tags or tags[0][0] != "v":
        tags.insert(0, ("v", "DMARC1"))
    keys = {k for k, _ in tags}
    if "p" not in keys:
        _insert_after(tags, "v", "p", "none")
    if "rua" not in keys:
        tags.append(("rua", f"mailto:{target.report_address}"))
    if want_ruf and "ruf" not in keys:
        _insert_after(tags, "rua", "ruf", f"mailto:{target.report_address}")
    if want_ruf and "fo" not in keys:
        _insert_after(tags, "ruf", "fo", "1")
    return "; ".join(f"{key}={value}" for key, value in tags)


def _one_suggestion(checks: list[DnsCheck]) -> None:
    """Every DMARC check suggests the same record; the first failing one shows it, the others point there."""
    first = None
    for check in checks:
        if not check.suggestion or check.state not in (ERROR, WARNING):
            continue
        if first is None:
            first = check
        elif check.suggestion == first.suggestion:
            check.suggestion = None
            check.message += f" Der richtige Wert steht bei „{first.title}“."


# DMARC ------------------------------------------------------------------------------------

@dataclass
class _Dmarc:
    name: str
    domain: str                 # where the record was found
    inherited: bool
    text: str | None = None
    tags: dict[str, str | None] = field(default_factory=dict)


def _is_dmarc(text: str) -> bool:
    return re.match(r"^\s*v\s*=\s*dmarc1\s*(;|$)", text, re.IGNORECASE) is not None


def _find_dmarc(resolver: Resolver, domain: str) -> tuple[_Dmarc, list[str]]:
    name = f"_dmarc.{domain}"
    records = [text for text in resolver.txt(name) if _is_dmarc(text)]
    if records:
        return _Dmarc(name, domain, False), records
    organizational = _organizational_domain(domain)
    if organizational and organizational != domain:
        parent = f"_dmarc.{organizational}"
        inherited = [text for text in resolver.txt(parent) if _is_dmarc(text)]
        if inherited:
            return _Dmarc(parent, organizational, True), inherited
    return _Dmarc(name, domain, False), []


def _check_dmarc_record(target: CheckInput, found: _Dmarc, records: list[str]) -> DnsCheck:
    title = "DMARC-Eintrag"
    if not records:
        return DnsCheck("dmarc", title, ERROR, "Kein DMARC-Eintrag. Ohne ihn schicken Empfänger keine Berichte und "
                        "wenden keine Policy an. Trage den Vorschlag ein.", record=found.name,
                        suggestion=target.dmarc_suggestion)
    if len(records) > 1:
        return DnsCheck("dmarc", title, ERROR, f"{len(records)} DMARC-Einträge. Empfänger werten dann keinen davon "
                        "aus; lösche alle bis auf einen.", record=found.name, found="\n".join(records),
                        suggestion=target.dmarc_suggestion)
    text = records[0]
    if not re.match(r"^\s*[vV]\s*=\s*DMARC1\s*(;|$)", text):
        return DnsCheck("dmarc", title, ERROR, "Der Eintrag muss genau mit v=DMARC1 beginnen, in dieser "
                        "Schreibweise. Empfänger übergehen ihn sonst.", record=found.name, found=text,
                        suggestion=suggest_from_record(parse_tags(text), target))
    if found.inherited:
        return DnsCheck("dmarc", title, INFO, f"{target.domain} hat keinen eigenen Eintrag; es gilt der Eintrag von "
                        f"{found.domain}, für Subdomains mit sp, sonst p.", record=found.name, found=text)
    return DnsCheck("dmarc", title, OK, "Ein gültiger DMARC-Eintrag.", record=found.name, found=text)


def _check_dmarc_policy(found: _Dmarc) -> DnsCheck:
    title = "Policy"
    tags = found.tags
    label = "sp" if found.inherited and tags.get("sp") else "p"
    policy = (tags.get(label) or "").lower()
    extras = []
    if (tags.get("t") or "").lower() == "y":
        extras.append("t=y: Empfänger nach RFC 9989 wenden die Policy im Testmodus nicht an")
    pct = tags.get("pct")
    if pct and _number(pct) and int(pct) < 100:
        extras.append(f"pct={pct}: Empfänger nach RFC 7489 wenden sie nur auf {pct} % der Mails an")
    extra = (" " + "; ".join(extras) + ".") if extras else ""
    if "p" not in tags:
        return DnsCheck("policy", title, WARNING, "Der Eintrag nennt keine Policy. Mit rua werten Empfänger ihn als "
                        "p=none; trage p ausdrücklich ein." + extra, record=found.name)
    if policy not in DMARC_POLICIES:
        return DnsCheck("policy", title, ERROR, f"{label}={tags.get(label)} gibt es nicht; erlaubt sind none, "
                        "quarantine und reject." + extra, record=found.name, found=f"{label}={tags.get(label)}")
    if policy == "none":
        return DnsCheck("policy", title, INFO, f"{label}=none: Empfänger beobachten nur und stellen auch Mails zu, die "
                        "DMARC nicht bestehen. Die Empfehlungen oben zeigen, wann quarantine oder reject passt."
                        + extra, record=found.name, found=f"{label}=none")
    return DnsCheck("policy", title, INFO if extras else OK,
                    f"{label}={policy}: Empfänger "
                    f"{'weisen Mails ab' if policy == 'reject' else 'legen Mails in den Spam'}, die DMARC nicht "
                    "bestehen." + extra, record=found.name, found=f"{label}={policy}")


def _number(value: str) -> bool:
    """ASCII digits only; str.isdigit also accepts characters like ² that int() refuses."""
    return re.fullmatch(r"[0-9]{1,10}", value) is not None


def _check_dmarc_syntax(found: _Dmarc, pairs: list[tuple[str, str | None]]) -> DnsCheck:
    title = "Aufbau des DMARC-Eintrags"
    problems, notes = [], []
    seen = set()
    for key, value in pairs:
        if key in seen:
            problems.append(f"{key} steht doppelt")
        seen.add(key)
        if value is None:
            problems.append(f"„{key}“ hat kein =")
        elif key not in DMARC_KNOWN_TAGS:
            notes.append(f"{key} ist unbekannt und wird übergangen")
    tags = found.tags
    checks = {
        "sp": lambda v: v.lower() in DMARC_POLICIES,
        "np": lambda v: v.lower() in DMARC_POLICIES,
        "t": lambda v: v.lower() in ("y", "n"),
        "pct": lambda v: _number(v) and 0 <= int(v) <= 100,
        "adkim": lambda v: v.lower() in ("r", "s"),
        "aspf": lambda v: v.lower() in ("r", "s"),
        "fo": lambda v: all(part.strip().lower() in ("0", "1", "d", "s") for part in v.split(":")),
        "ri": lambda v: _number(v) and int(v) <= DMARC_RI_MAX,
        "psd": lambda v: v.lower() in ("y", "n", "u"),
    }
    for key, valid in checks.items():
        value = tags.get(key)
        if value is not None and not valid(value):
            problems.append(f"{key}={value} ist ungültig")
    for key in ("rua", "ruf"):
        for uri in _uris(tags.get(key)):
            if not uri.lower().startswith(("mailto:", "https:", "http:")):
                problems.append(f"{uri} in {key} ist keine mailto-Adresse")
    if problems:
        return DnsCheck("syntax", title, WARNING, "; ".join(problems) + ". Empfänger übergehen solche Angaben oder den "
                        "ganzen Eintrag." + (" " + "; ".join(notes) + "." if notes else ""), record=found.name)
    if notes:
        return DnsCheck("syntax", title, INFO, "; ".join(notes) + ".", record=found.name)
    return DnsCheck("syntax", title, OK, "Alle Angaben sind gültig.", record=found.name)


def _check_rua(target: CheckInput, found: _Dmarc, suggestion: str | None) -> DnsCheck:
    title = "Sammelberichte (rua)"
    uris = _uris(found.tags.get("rua"))
    addresses = [a for a in (_mailto(uri) for uri in uris) if a]
    ours = [a for a in addresses if a in target.addresses]
    others = [a for a in addresses if a not in target.addresses]
    wanted = f" Richtig ist {target.report_address}." if target.report_address else ""
    if not uris:
        return DnsCheck("rua", title, ERROR, "Der Eintrag nennt keine Adresse in rua; Empfänger schicken dann keine "
                        "Sammelberichte." + wanted, record=found.name, suggestion=suggestion)
    if not ours:
        stray = [a for a in others if _domain_of(a) == settings.SMTP_INBOUND_DOMAIN.lower()]
        reason = (f"{', '.join(stray)} ist keine aktive Empfangsadresse dieser Organisation."
                  if stray else "Die Adresse dieser Anwendung fehlt; die Berichte kommen hier nicht an.")
        return DnsCheck("rua", title, ERROR, reason + wanted, record=found.name, found=", ".join(uris),
                        suggestion=suggestion)
    extra = f" Außerdem an {', '.join(others)}." if others else ""
    return DnsCheck("rua", title, OK, f"Sammelberichte gehen an {', '.join(ours)}.{extra}", record=found.name,
                    found=", ".join(uris))


def _check_ruf(target: CheckInput, found: _Dmarc, suggestion: str | None) -> DnsCheck | None:
    if not settings.FAILURE_REPORTS_ENABLED:
        return None
    title = "Fehlerberichte (ruf)"
    uris = _uris(found.tags.get("ruf"))
    addresses = [a for a in (_mailto(uri) for uri in uris) if a]
    ours = [a for a in addresses if a in target.addresses]
    missing = WARNING if settings.DMARC_SUGGEST_FAILURE_REPORTS else INFO
    fo = (found.tags.get("fo") or "0").replace(" ", "")
    fo_note = "" if "1" in fo.split(":") else " Mit fo=1 melden Empfänger schon, wenn SPF oder DKIM scheitert."
    if not uris:
        return DnsCheck("ruf", title, missing, "Der Eintrag nennt keine Adresse in ruf; Fehlerberichte kommen nicht an."
                        + fo_note, record=found.name, suggestion=suggestion)
    if not ours:
        return DnsCheck("ruf", title, missing, "Fehlerberichte gehen an eine andere Adresse; hier kommen keine an."
                        + fo_note, record=found.name, found=", ".join(uris), suggestion=suggestion)
    return DnsCheck("ruf", title, INFO if fo_note else OK, f"Fehlerberichte gehen an {', '.join(ours)}." + fo_note,
                    record=found.name, found=", ".join(uris) + (f"; fo={fo}" if found.tags.get("fo") else ""))


def _check_consent(resolver: Resolver, target: CheckInput, found: _Dmarc) -> DnsCheck | None:
    """Consent of the report domain (RFC 7489, 7.1) for the addresses of this application."""
    addresses = {a for key in ("rua", "ruf") for a in (_mailto(uri) for uri in _uris(found.tags.get(key)))
                 if a and a in target.addresses}
    report_domains = sorted({_domain_of(a) for a in addresses
                             if _organizational_domain(_domain_of(a)) != _organizational_domain(found.domain)})
    if not report_domains:
        return None
    title = "Zustimmung der Empfangsdomain"
    missing, found_names = [], []
    for report_domain in report_domains:
        name = f"{found.domain}._report._dmarc.{report_domain}"
        try:
            records = [text for text in resolver.txt(name) if _is_dmarc(text)]
        except LookupFailed as exc:
            return _failed("consent", title, name, exc)
        (found_names if records else missing).append(name)
    if missing:
        return DnsCheck("consent", title, ERROR, f"Es fehlt {', '.join(missing)} mit dem Wert v=DMARC1. Ohne diese "
                        "Zustimmung schicken Empfänger keine Berichte an die Adresse. Den Eintrag setzt, wer die Zone "
                        "der Empfangsdomain verwaltet.", record=missing[0], suggestion="v=DMARC1")
    return DnsCheck("consent", title, OK, "Die Empfangsdomain stimmt zu.", record=", ".join(found_names),
                    found="v=DMARC1")


def check_dmarc(resolver: Resolver, target: CheckInput) -> list[DnsCheck]:
    try:
        found, records = _find_dmarc(resolver, target.domain)
    except LookupFailed as exc:
        return [_failed("dmarc", "DMARC-Eintrag", f"_dmarc.{target.domain}", exc)]
    record_check = _check_dmarc_record(target, found, records)
    if record_check.state == ERROR:
        return [record_check]
    pairs = parse_tags(records[0])
    found.text = records[0]
    for key, value in pairs:
        if value is not None:
            found.tags.setdefault(key, value)  # the first occurrence counts
    suggestion = suggest_from_record(pairs, target)
    checks = [record_check, _check_dmarc_policy(found), _check_dmarc_syntax(found, pairs),
              _check_rua(target, found, suggestion)]
    ruf = _check_ruf(target, found, suggestion)
    if ruf:
        checks.append(ruf)
    _one_suggestion(checks)
    consent = _check_consent(resolver, target, found)
    if consent:
        checks.append(consent)
    return checks


# SPF ----------------------------------------------------------------------------------------

def _is_spf(text: str) -> bool:
    lowered = text.strip().lower()
    return lowered == "v=spf1" or lowered.startswith("v=spf1 ")


@dataclass
class _SpfWalk:
    lookups: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    incomplete: bool = False


def _spf_terms(record: str) -> list[str]:
    return record.split()[1:]


def _walk_spf(resolver: Resolver, record: str, walk: _SpfWalk, path: tuple[str, ...]) -> None:
    redirect = None
    has_all = False
    for term in _spf_terms(record):
        body = term[1:] if term[0] in "+-~?" else term
        lowered = body.lower()
        if "=" in lowered.split(":", 1)[0]:
            key, _, value = lowered.partition("=")
            if key == "redirect":
                redirect = value
            continue
        name, _, argument = lowered.partition(":")
        name = name.split("/", 1)[0]
        if name not in SPF_MECHANISMS:
            walk.errors.append(f"„{term}“ ist kein gültiger Teil eines SPF-Eintrags")
            continue
        if name == "all":
            has_all = True
        if name in SPF_COUNTED:
            walk.lookups += 1
        if name == "ptr" and len(path) == 1:
            walk.warnings.append("ptr ist langsam und laut RFC 7208 nicht mehr zu verwenden")
        if name == "include":
            _follow(resolver, argument.split("/", 1)[0], f"include:{argument}", walk, path)
    if redirect and not has_all:  # RFC 7208, 6.1: with all the redirect is never followed
        walk.lookups += 1
        _follow(resolver, redirect, f"redirect={redirect}", walk, path)


def _follow(resolver: Resolver, target: str, label: str, walk: _SpfWalk, path: tuple[str, ...]) -> None:
    """Count the lookups of an included or redirected record; a name on its own path is a loop."""
    target = target.rstrip(".")
    if not target or "%" in target:
        return  # macros depend on the mail; they cannot be followed here
    if target in path:
        walk.errors.append(f"{label} verweist im Kreis")
        return
    if len(path) > SPF_MAX_DEPTH or walk.lookups > SPF_LOOKUP_LIMIT:
        return
    try:
        records = [text for text in resolver.txt(target) if _is_spf(text)]
    except LookupFailed:
        walk.incomplete = True
        return
    if len(records) != 1:
        walk.errors.append(f"{label} hat {'keinen' if not records else 'mehr als einen'} SPF-Eintrag")
        return
    _walk_spf(resolver, records[0], walk, path + (target,))


def _closing_all(record: str) -> str | None:
    for term in _spf_terms(record):
        if term.lower().lstrip("+-~?") == "all":
            return term.lower()
    return None


def check_spf(resolver: Resolver, target: CheckInput) -> DnsCheck:
    title = "SPF"
    name = target.domain
    try:
        records = [text for text in resolver.txt(name) if _is_spf(text)]
    except LookupFailed as exc:
        return _failed("spf", title, name, exc)
    if not records:
        return DnsCheck("spf", title, WARNING, "Kein SPF-Eintrag. Empfänger kennen dann keine erlaubten Server, und "
                        "DMARC hängt allein an DKIM. Verschickt die Domain keine Mails, reicht v=spf1 -all.",
                        record=name)
    if len(records) > 1:
        return DnsCheck("spf", title, ERROR, f"{len(records)} SPF-Einträge. Empfänger werten SPF dann als Fehler "
                        "(permerror); fasse sie zu einem zusammen.", record=name, found="\n".join(records))
    record = records[0]
    walk = _SpfWalk()
    _walk_spf(resolver, record, walk, (name,))
    closing = _closing_all(record)
    if walk.lookups > SPF_LOOKUP_LIMIT:
        walk.errors.append(f"mindestens {walk.lookups} DNS-Abfragen, erlaubt sind {SPF_LOOKUP_LIMIT} (RFC 7208); "
                           "fasse include-Einträge zusammen")
    if closing in ("all", "+all"):
        walk.errors.append(f"{closing} erlaubt jedem Server, im Namen der Domain zu senden")
    elif closing == "?all":
        walk.warnings.append("?all wertet fremde Server als neutral; üblich sind ~all oder -all")
    elif closing is None and "redirect=" not in record.lower():
        walk.warnings.append("der Eintrag endet ohne all; nicht aufgeführte Server gelten als neutral")
    lookups = f"{walk.lookups} von {SPF_LOOKUP_LIMIT} DNS-Abfragen"
    if walk.errors:
        return DnsCheck("spf", title, ERROR, "; ".join(walk.errors + walk.warnings) + ". Empfänger werten SPF dann "
                        "als Fehler oder als wirkungslos.", record=name, found=record)
    if walk.warnings:
        return DnsCheck("spf", title, WARNING, "; ".join(walk.warnings) + f". {lookups}.", record=name, found=record)
    if walk.incomplete:
        return DnsCheck("spf", title, UNKNOWN, f"Ein include ließ sich nicht abfragen; mindestens {lookups}. Die "
                        "nächste Prüfung zählt erneut.", record=name, found=record)
    return DnsCheck("spf", title, OK, f"Ein gültiger SPF-Eintrag mit {lookups}"
                    + (f", endet mit {closing}." if closing else ", endet über redirect."), record=name, found=record)


# DKIM ---------------------------------------------------------------------------------------

def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Tag, start and end of the DER value at pos."""
    if pos + 2 > len(data):
        raise ValueError("DER zu kurz")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        size = length & 0x7F
        if not 0 < size <= 4 or pos + size > len(data):
            raise ValueError("DER-Länge ungültig")
        length = int.from_bytes(data[pos:pos + size], "big")
        pos += size
    if pos + length > len(data):
        raise ValueError("DER endet vorzeitig")
    return tag, pos, pos + length


def rsa_key_bits(der: bytes, depth: int = 0) -> int | None:
    """Length of an RSA key, as SubjectPublicKeyInfo or as bare RSAPublicKey; None for anything else."""
    if depth >= DER_MAX_DEPTH:
        return None
    try:
        tag, start, end = _tlv(der, 0)
        if tag != 0x30:
            return None
        tag, first_start, first_end = _tlv(der, start)
        if tag == 0x30:  # AlgorithmIdentifier, then the key as BIT STRING
            tag, bits_start, bits_end = _tlv(der, first_end)
            return rsa_key_bits(der[bits_start + 1:bits_end], depth + 1) if tag == 0x03 else None
        if tag == 0x02:  # modulus of an RSAPublicKey
            return int.from_bytes(der[first_start:first_end], "big").bit_length() or None
    except ValueError:
        return None
    return None


def _decode_key(value: str) -> bytes | None:
    compact = re.sub(r"\s+", "", value)
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _in_use(last_pass: datetime | None, now: datetime) -> bool:
    if last_pass is None:
        return True
    last_pass = last_pass.replace(tzinfo=UTC) if last_pass.tzinfo is None else last_pass
    return now - last_pass <= timedelta(days=settings.DNS_CHECK_DKIM_ACTIVE_DAYS)


def _check_selector(resolver: Resolver, target: CheckInput, selector: str, now: datetime) -> DnsCheck:
    domain = target.domain
    title = f"DKIM-Schlüssel {selector}"
    key = f"dkim:{selector}"
    name = f"{selector}._domainkey.{domain}"
    try:
        records = [text for text in resolver.txt(name) if "p=" in text.replace(" ", "")]
    except LookupFailed as exc:
        return _failed(key, title, name, exc)
    if not records:
        last_pass = target.dkim_last_pass.get(selector)
        seen = f" zuletzt am {last_pass:%d.%m.%Y}" if last_pass else ""
        if _in_use(last_pass, now):
            return DnsCheck(key, title, ERROR, f"Der Selektor {selector} hat{seen} DKIM bestanden und ist in Gebrauch, "
                            "sein Schlüssel fehlt jetzt im DNS. Mails mit dieser Signatur scheitern an DKIM.",
                            record=name)
        return DnsCheck(key, title, WARNING, f"Der Selektor {selector} hat{seen} DKIM bestanden, sein Schlüssel fehlt "
                        "jetzt im DNS. Nach einem Schlüsselwechsel ist das gewollt; sonst scheitern Mails mit dieser "
                        "Signatur an DKIM.", record=name)
    if len(records) > 1:
        return DnsCheck(key, title, WARNING, f"{len(records)} Schlüssel unter demselben Namen; Empfänger nehmen einen "
                        "beliebigen davon.", record=name, found="\n".join(records))
    text = records[0]
    tags = dict(parse_tags(text))
    public = tags.get("p")
    if public is None:
        return DnsCheck(key, title, ERROR, "Der Eintrag enthält keinen Schlüssel (p).", record=name, found=text)
    if not public.strip():
        return DnsCheck(key, title, WARNING, "Der Schlüssel ist widerrufen (leeres p). Mails mit diesem Selektor "
                        "scheitern an DKIM; nach einem Schlüsselwechsel ist das gewollt.", record=name, found=text)
    kind = (tags.get("k") or "rsa").lower()
    data = _decode_key(public)
    testing = " Der Eintrag steht im Testmodus (t=y)." if "y" in (tags.get("t") or "").lower().split(":") else ""
    if data is None:
        return DnsCheck(key, title, ERROR, "Der Schlüssel ist kein gültiges Base64.", record=name, found=text)
    if kind == "ed25519":
        if len(data) != ED25519_KEY_BYTES:
            return DnsCheck(key, title, ERROR, "Der Ed25519-Schlüssel hat nicht 32 Byte.", record=name, found=text)
        return DnsCheck(key, title, INFO if testing else OK, "Ed25519-Schlüssel." + testing, record=name, found=text)
    bits = rsa_key_bits(data)
    if bits is None:
        return DnsCheck(key, title, ERROR, "Der RSA-Schlüssel lässt sich nicht lesen.", record=name, found=text)
    if bits < DKIM_MIN_RSA_BITS:
        return DnsCheck(key, title, ERROR, f"RSA mit {bits} Bit. Empfänger werten Schlüssel unter {DKIM_MIN_RSA_BITS} "
                        "Bit nicht (RFC 8301); erzeuge einen neuen.", record=name, found=text)
    if bits < settings.DNS_CHECK_DKIM_RECOMMENDED_BITS:
        return DnsCheck(key, title, INFO, f"RSA mit {bits} Bit; empfohlen sind "
                        f"{settings.DNS_CHECK_DKIM_RECOMMENDED_BITS} Bit." + testing, record=name, found=text)
    return DnsCheck(key, title, INFO if testing else OK, f"RSA mit {bits} Bit." + testing, record=name, found=text)


def check_dkim(resolver: Resolver, target: CheckInput, now: datetime | None = None) -> list[DnsCheck]:
    if not target.dkim_selectors:
        return [DnsCheck("dkim", "DKIM", INFO, f"In den Berichten der letzten {settings.DNS_CHECK_DKIM_DAYS} Tage hat "
                         f"keine Signatur von {target.domain} bestanden; ohne Selektor lässt sich kein Schlüssel "
                         "prüfen.")]
    now = now or datetime.now(UTC)
    return [_check_selector(resolver, target, selector, now) for selector in target.dkim_selectors]


# MX and TLS reporting ---------------------------------------------------------------------------

def check_mx(resolver: Resolver, target: CheckInput) -> tuple[DnsCheck, bool | None]:
    """MX check and whether the domain receives mail; None when the lookup gave no answer."""
    title = "Mailserver (MX)"
    name = target.domain
    try:
        hosts = sorted(resolver.mx(name))
    except LookupFailed as exc:
        return _failed("mx", title, name, exc), None
    if not hosts:
        return DnsCheck("mx", title, INFO, "Kein MX-Eintrag: Die Domain empfängt keine Mails.", record=name), False
    listed = ", ".join(f"{preference} {host or '.'}" for preference, host in hosts)
    if all(host in ("", ".") for _, host in hosts):
        return DnsCheck("mx", title, INFO, "Null-MX (RFC 7505): Die Domain nimmt keine Mails an.", record=name,
                        found=listed), False
    without = []
    for _, host in hosts:
        try:
            if not resolver.addresses(host):
                without.append(host)
        except LookupFailed as exc:
            return _failed("mx", title, host, exc), True
    if without:
        return DnsCheck("mx", title, WARNING, f"{', '.join(without)} hat keine IP-Adresse; Mails an diesen Server "
                        "kommen nicht an.", record=name, found=listed), True
    return DnsCheck("mx", title, OK, f"{len(hosts)} Mailserver mit IP-Adresse.", record=name, found=listed), True


def check_tls_reporting(resolver: Resolver, target: CheckInput, receives_mail: bool | None) -> DnsCheck | None:
    if not settings.TLS_REPORTS_ENABLED:
        return None
    title = "TLS-Berichte"
    name = f"_smtp._tls.{target.domain}"
    if receives_mail is None:
        return DnsCheck("tlsrpt", title, UNKNOWN, "Ob die Domain Mails empfängt, blieb offen, weil die MX-Abfrage "
                        "keine Antwort brachte. Die nächste Prüfung versucht es erneut.", record=name)
    if not receives_mail:
        return DnsCheck("tlsrpt", title, INFO, "Ohne Mailempfang braucht die Domain keinen Eintrag.", record=name)
    try:
        candidates = [text for text in resolver.txt(name) if text.strip().lower().startswith("v=tlsrptv1")]
    except LookupFailed as exc:
        return _failed("tlsrpt", title, name, exc)
    exact = [text for text in candidates if text.strip().startswith("v=TLSRPTv1")]
    records = exact or candidates
    if not records:
        return DnsCheck("tlsrpt", title, WARNING, "Kein Eintrag; Absender melden dann nicht, ob sie deine Mailserver "
                        "verschlüsselt erreichen.", record=name, suggestion=target.tls_suggestion)
    if len(records) > 1:
        return DnsCheck("tlsrpt", title, ERROR, f"{len(records)} Einträge mit v=TLSRPTv1; Absender werten dann keinen "
                        "aus (RFC 8460).", record=name, found="\n".join(records), suggestion=target.tls_suggestion)
    tags = dict(parse_tags(records[0]))
    if not records[0].strip().startswith("v=TLSRPTv1"):
        suggestion = (f"v=TLSRPTv1; rua={_with_address(tags.get('rua'), target)}"
                      if target.report_address else None)
        return DnsCheck("tlsrpt", title, ERROR, "Der Eintrag muss genau mit v=TLSRPTv1 beginnen, in dieser "
                        "Schreibweise. Absender übergehen ihn sonst (RFC 8460).", record=name, found=records[0],
                        suggestion=suggestion)
    addresses = [a for a in (_mailto(uri) for uri in _uris(tags.get("rua"))) if a]
    ours = [a for a in addresses if a in target.addresses]
    if not ours:
        suggestion = (f"v=TLSRPTv1; rua={_with_address(tags.get('rua'), target)}"
                      if target.report_address else None)
        return DnsCheck("tlsrpt", title, WARNING, "TLS-Berichte gehen an eine andere Adresse; hier kommen keine an.",
                        record=name, found=records[0], suggestion=suggestion)
    return DnsCheck("tlsrpt", title, OK, f"TLS-Berichte gehen an {', '.join(ours)}.", record=name, found=records[0])


# One domain ---------------------------------------------------------------------------------

INTERNAL_ERROR = ("Die Prüfung brach mit einem internen Fehler ab. Die nächste Prüfung versucht es erneut; bleibt "
                  "es dabei, wende dich an den Betreiber der Anwendung, der den Grund im Log findet.")


def _broken(key: str, title: str, domain: str) -> DnsCheck:
    logger.exception("DNS check %s: %s failed", domain, key)
    return DnsCheck(key, title, UNKNOWN, INTERNAL_ERROR)


def check_domain(target: CheckInput, resolver: Resolver | None = None, now: datetime | None = None) -> DnsCheckResult:
    """All checks for one domain; runs DNS lookups only and touches no database.

    Every group runs on its own: an unexpected error in one leaves its checks open and the others go on.
    """
    resolver = resolver or Resolver.for_one_domain()
    now = now or datetime.now(UTC)
    result = DnsCheckResult(domain=target.domain, checked_at=now)
    checks = result.checks
    for key, title, run in (("dmarc", "DMARC-Eintrag", lambda: check_dmarc(resolver, target)),
                            ("spf", "SPF", lambda: [check_spf(resolver, target)]),
                            ("dkim", "DKIM", lambda: check_dkim(resolver, target, now))):
        try:
            checks.extend(run())
        except Exception:
            checks.append(_broken(key, title, target.domain))
    try:
        mx, receives_mail = check_mx(resolver, target)
    except Exception:
        mx, receives_mail = _broken("mx", "Mailserver (MX)", target.domain), None
    checks.append(mx)
    try:
        tls = check_tls_reporting(resolver, target, receives_mail)
    except Exception:
        tls = _broken("tlsrpt", "TLS-Berichte", target.domain)
    if tls:
        checks.append(tls)
    return result


def dkim_selectors(db: Session, domain: Domain, now: datetime) -> dict[str, datetime]:
    """Selectors of the domain that passed DKIM in the reports of the last DNS_CHECK_DKIM_DAYS days, most used first,
    with the arrival of the newest report that shows them passing."""
    since = now - timedelta(days=settings.DNS_CHECK_DKIM_DAYS)
    # The day the mails were sent; an upload of old reports must not make old selectors look current
    reported = func.coalesce(DmarcReport.period_end, DmarcReport.created_at)
    rows = (
        db.query(DmarcAuthResult.selector, func.count(DmarcAuthResult.id), func.max(reported))
        .join(DmarcRecord, DmarcAuthResult.record_id == DmarcRecord.id)
        .join(DmarcReport, DmarcRecord.report_id == DmarcReport.id)
        .filter(DmarcReport.organization_id == domain.organization_id, reported >= since,
                DmarcAuthResult.auth_type == "dkim", DmarcAuthResult.result == "pass",
                func.lower(DmarcAuthResult.domain) == domain.name.lower(), DmarcAuthResult.selector.isnot(None),
                DmarcAuthResult.selector != "")
        .group_by(DmarcAuthResult.selector)
        .order_by(func.count(DmarcAuthResult.id).desc(), DmarcAuthResult.selector)
        .limit(settings.DNS_CHECK_DKIM_MAX_SELECTORS)
        .all()
    )
    found: dict[str, datetime] = {}
    for selector, _, last_pass in rows:
        name = clean_text(selector, 255, lower=True, single_line=True)
        if name and name not in found:
            found[name] = _as_datetime(last_pass)
    return found


def _as_datetime(value) -> datetime | None:
    """SQLite hands back the result of coalesce() as text; PostgreSQL as a datetime."""
    if value is None or isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def gather_input(db: Session, domain: Domain, now: datetime | None = None) -> CheckInput:
    address = report_address(db, domain.organization_id, domain.id)
    selectors = dkim_selectors(db, domain, now or datetime.now(UTC))
    return CheckInput(
        domain=domain.name.lower().rstrip("."),
        addresses=active_addresses(db, domain.organization_id),
        report_address=address,
        dmarc_suggestion=suggest_dmarc_record(domain, address) if address else None,
        tls_suggestion=suggest_tls_record(address) if address else None,
        dkim_selectors=list(selectors),
        dkim_last_pass=selectors,
    )


def store_result(domain: Domain, result: DnsCheckResult) -> None:
    domain.dns_status = result.status
    domain.dns_checked_at = result.checked_at
    domain.dns_results = result.to_json()


def stored_result(domain: Domain) -> DnsCheckResult | None:
    return DnsCheckResult.from_json(domain.dns_results)


def run_check(db: Session, domain: Domain, resolver: Resolver | None = None,
              now: datetime | None = None) -> DnsCheckResult:
    """Check one domain now and keep the result on it."""
    now = now or datetime.now(UTC)
    target = gather_input(db, domain, now)
    db.commit()  # the lookups take a while; no transaction and no connection stay open meanwhile
    result = check_domain(target, resolver, now)
    store_result(domain, result)
    db.flush()
    logger.info("DNS check %s: %s", domain.name, result.status)
    return result


def due_domains(db: Session, now: datetime, limit: int) -> list[Domain]:
    """Active domains of active organisations whose last check is older than DNS_CHECK_MAX_AGE_SECONDS, unchecked
    ones first."""
    cutoff = now - timedelta(seconds=settings.DNS_CHECK_MAX_AGE_SECONDS)
    return (
        db.query(Domain)
        .join(Organization, Domain.organization_id == Organization.id)
        .filter(Domain.is_active.is_(True), Organization.is_active.is_(True),
                or_(Domain.dns_checked_at.is_(None), Domain.dns_checked_at <= cutoff))
        .order_by(Domain.dns_checked_at.is_not(None), Domain.dns_checked_at, Domain.name)
        .limit(limit)
        .all()
    )


def run_due_checks(db: Session, now: datetime, resolver_factory=None) -> set[str]:
    """Check the domains that are due, several at once; returns the organisations that got new results.

    No domain starts after DNS_CHECK_JOB_BUDGET_SECONDS; those stay due for the next run. A domain whose check
    breaks still gets a result, so it cannot hold up the others.
    """
    if not settings.DNS_CHECK_ENABLED:
        return set()
    domains = due_domains(db, now, settings.DNS_CHECK_BATCH_SIZE)
    if not domains:
        return set()
    inputs = [gather_input(db, domain, now) for domain in domains]
    db.commit()  # the lookups take a while; no read transaction stays open meanwhile
    job_deadline = time.monotonic() + settings.DNS_CHECK_JOB_BUDGET_SECONDS

    def work(target: CheckInput) -> DnsCheckResult | None:
        if time.monotonic() > job_deadline:
            return None
        try:
            resolver = resolver_factory() if resolver_factory else Resolver.for_one_domain()
            return check_domain(target, resolver, now)
        except Exception:
            return DnsCheckResult(target.domain, now, [_broken("dns", "DNS-Prüfung", target.domain)])

    with ThreadPoolExecutor(max_workers=min(settings.DNS_CHECK_WORKERS, len(inputs))) as pool:
        results = list(pool.map(work, inputs))
    done = [(domain, result) for domain, result in zip(domains, results, strict=True) if result is not None]
    for domain, result in done:
        store_result(domain, result)
    db.flush()
    postponed = len(domains) - len(done)
    logger.info("DNS check of %d domains%s: %s", len(done),
                f", {postponed} postponed after DNS_CHECK_JOB_BUDGET_SECONDS" if postponed else "",
                ", ".join(f"{d.name}={r.status}" for d, r in done))
    return {domain.organization_id for domain, _ in done}


class CheckRefused(Exception):
    """A check on request that does not start now; the text says why, retry_after when to try again."""

    def __init__(self, text: str, retry_after: int) -> None:
        super().__init__(text)
        self.retry_after = retry_after


_manual_lock = threading.Lock()
_manual_running = 0


def _seconds(count: int) -> str:
    return f"{count} Sekunde" if count == 1 else f"{count} Sekunden"


def _claim(db: Session, domain: Domain, now: datetime) -> int:
    """Mark the domain as checked now unless the cooldown still runs; 0 when claimed, else the seconds left.

    A single UPDATE with the condition, so two requests at the same moment cannot both pass.
    """
    cooldown = settings.DNS_CHECK_MANUAL_COOLDOWN_SECONDS
    if not cooldown:
        return 0
    cutoff = now - timedelta(seconds=cooldown)
    claimed = db.execute(
        update(Domain)
        .where(Domain.id == domain.id, or_(Domain.dns_checked_at.is_(None), Domain.dns_checked_at <= cutoff))
        .values(dns_checked_at=now)
        .execution_options(synchronize_session=False)
    ).rowcount == 1
    db.commit()
    if claimed:
        return 0
    db.refresh(domain)
    return max(1, cooldown_left(domain, now))


def run_manual_check(db: Session, domain: Domain, resolver: Resolver | None = None,
                     now: datetime | None = None) -> DnsCheckResult:
    """Check a domain on request: once per DNS_CHECK_MANUAL_COOLDOWN_SECONDS, at most DNS_CHECK_MANUAL_PARALLEL
    checks at once in this process. Raises CheckRefused with a text for the person who asked."""
    global _manual_running
    now = now or datetime.now(UTC)
    with _manual_lock:
        if _manual_running >= settings.DNS_CHECK_MANUAL_PARALLEL:
            raise CheckRefused(f"Gerade laufen schon {settings.DNS_CHECK_MANUAL_PARALLEL} Prüfungen auf Knopfdruck. "
                               "Starte die Prüfung gleich noch einmal.", 10)
        _manual_running += 1
    try:
        wait = _claim(db, domain, now)
        if wait:
            raise CheckRefused(f"{domain.name} wurde gerade geprüft. Das Ergebnis steht in der Liste; eine neue "
                               f"Prüfung ist in {_seconds(wait)} möglich.", wait)
        return run_check(db, domain, resolver, now)
    finally:
        with _manual_lock:
            _manual_running -= 1


def cooldown_left(domain: Domain, now: datetime | None = None) -> int:
    """Seconds until the domain may be checked again on request (DNS_CHECK_MANUAL_COOLDOWN_SECONDS)."""
    if not domain.dns_checked_at or not settings.DNS_CHECK_MANUAL_COOLDOWN_SECONDS:
        return 0
    now = now or datetime.now(UTC)
    checked = domain.dns_checked_at
    checked = checked.replace(tzinfo=UTC) if checked.tzinfo is None else checked
    left = settings.DNS_CHECK_MANUAL_COOLDOWN_SECONDS - (now - checked).total_seconds()
    return max(0, int(left + 0.999))
