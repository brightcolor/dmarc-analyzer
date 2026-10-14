"""
DNS lookups for source IPs: host name (PTR, confirmed by a forward lookup) and network operator.

The operator comes from the IP-to-ASN service of Team Cymru, which answers over DNS
(SENDER_ASN_ZONE_V4 / _V6 / _NAME_ZONE). Every lookup has the time limit SENDER_LOOKUP_TIMEOUT_SECONDS;
a failed lookup leaves the field empty and never raises.
"""
import ipaddress
import logging
import re
from dataclasses import dataclass

import dns.exception
import dns.resolver
import dns.reversename

from app.config import settings

logger = logging.getLogger(__name__)

COUNTRY_SUFFIX = re.compile(r",\s*[A-Z]{2}$")


@dataclass
class LookupResult:
    reverse_dns: str | None = None
    reverse_dns_confirmed: bool = False
    asn: str | None = None
    asn_org: str | None = None
    country_code: str | None = None


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    if settings.dns_nameservers:
        resolver.nameservers = settings.dns_nameservers
    resolver.lifetime = settings.SENDER_LOOKUP_TIMEOUT_SECONDS
    resolver.timeout = settings.SENDER_LOOKUP_TIMEOUT_SECONDS
    return resolver


def _query(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    try:
        return [answer.to_text() for answer in resolver.resolve(name, rdtype)]
    except (dns.exception.DNSException, OSError) as exc:
        logger.debug("DNS %s %s: %s", rdtype, name, exc.__class__.__name__)
        return []


def reverse_name(resolver: dns.resolver.Resolver, ip: str) -> tuple[str | None, bool]:
    """PTR name of the address and whether that name resolves back to it."""
    names = _query(resolver, dns.reversename.from_address(ip).to_text(), "PTR")
    if not names:
        return None, False
    name = names[0].rstrip(".").lower()
    address = ipaddress.ip_address(ip)
    forward = _query(resolver, name, "AAAA" if address.version == 6 else "A")
    return name, any(ipaddress.ip_address(value) == address for value in forward if _is_ip(value))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _txt(values: list[str]) -> str | None:
    """First TXT answer as plain text."""
    return values[0].strip('"').replace('" "', "") if values else None


def asn_name(ip: str) -> str:
    """DNS name that answers with the AS number of an address at Team Cymru."""
    address = ipaddress.ip_address(ip)
    reverse = dns.reversename.from_address(ip).to_text().rstrip(".")
    if address.version == 6:
        return reverse.removesuffix(".ip6.arpa") + "." + settings.SENDER_ASN_ZONE_V6
    return reverse.removesuffix(".in-addr.arpa") + "." + settings.SENDER_ASN_ZONE_V4


def network_operator(resolver: dns.resolver.Resolver, ip: str) -> tuple[str | None, str | None, str | None]:
    """AS number, operator name and country of an address."""
    origin = _txt(_query(resolver, asn_name(ip), "TXT"))
    # "15169 | 209.85.128.0/17 | US | arin | 2005-09-21"; several AS numbers are separated by spaces
    if not origin:
        return None, None, None
    fields = [f.strip() for f in origin.split("|")]
    asn = fields[0].split()[0] if fields and fields[0] else None
    country = fields[2].upper() if len(fields) > 2 and len(fields[2]) == 2 else None
    if not asn or not asn.isdigit():
        return None, None, country
    described = _txt(_query(resolver, f"AS{asn}.{settings.SENDER_ASN_NAME_ZONE}", "TXT"))
    # "15169 | US | arin | 2000-03-30 | GOOGLE, US"
    name = described.split("|")[-1].strip() if described else None
    if name:
        # The registry country follows the name ("GOOGLE - Google LLC, US"); the address country is separate
        name = COUNTRY_SUFFIX.sub("", name)
    return asn, name or None, country


def lookup(ip: str) -> LookupResult:
    """Host name and operator of one address; empty fields when DNS has no answer."""
    result = LookupResult()
    if not settings.SENDER_LOOKUP_ENABLED:
        return result
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return result
    resolver = _resolver()
    result.reverse_dns, result.reverse_dns_confirmed = reverse_name(resolver, ip)
    if settings.SENDER_ASN_LOOKUP_ENABLED:
        result.asn, result.asn_org, result.country_code = network_operator(resolver, ip)
    return result
