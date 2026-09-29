"""DNS check per domain: DMARC, consent, SPF, DKIM, MX, TLS reporting, storage, schedule, pages and API.

Every answer comes from a fake resolver; names and addresses are invented or reserved for documentation.
"""
import base64
import json
from datetime import timedelta

import pytest

from app import scheduler
from app.config import load_settings, settings
from app.models import AlertEvent, DmarcAuthResult, DmarcRecord, Domain, InboundMailAddress, Organization, User
from app.services import dns_check
from app.services.alert_service import alert_type_hints, evaluate_rules_for_org
from app.services.auth import create_api_token
from app.services.dns_check import (
    CheckInput,
    DnsCheckResult,
    LookupFailed,
    check_domain,
    due_domains,
    gather_input,
    rsa_key_bits,
    run_check,
    run_due_checks,
    stored_result,
)
from app.services.inbound_address import create_domain_address
from tests.helpers import NOW, add_report, make_domain, make_org, make_rule
from tests.test_web import _login, _seed

ADDRESS = "dom-example-com-abc123@reports.example.test"
CONSENT = "example.com._report._dmarc.reports.example.test"

# Throwaway public keys, their private halves are gone
RSA_512 = ("MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ3tbXLTRMz9NLtKNcwJd7zEAMW3jIoOWS258ivJM6IDK4Q47F0YUcFlJy3iRKLbFy+A"
           "x8Z1YJxFa3bCRj2zpyECAwEAAQ==")
RSA_1024 = ("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpkiP7bMUrnlN8ca60faK5bgrdKoyvaWpe9mr10xXLrenmM6aKsk3oudgtWrSt"
            "xgdgI9seDov3phci2nS3arHBHfinFNxWmnPalI7wI4NZ9c6D4teSMwJn7XwOXzs8OThpQ4qBg4IEzlIsd3t4sFKaFi+njwisRcev"
            "qaRudRwroQIDAQAB")
RSA_2048 = ("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqM9e313aRF168eURITsDePDU8EcdzQ7KdqFdJhQ6Q5ykJ1JP+LXtbcaK"
            "k5kECp93X74+sN0Cjz4d25P8Jdd3u5eVtt1dEw2O6+W60r785jdAJfsN7uwbh8jlM9nnrX3NGCofAM9O3AmBqlwxMtTLEzO5xwvv"
            "1t6NMXaJn95tQbKXNYtg7cLsGDo5lxJFC1H76wSYnPStzcQf6uwlnYMmXE263Rb4/HHwz/4mWIWsomB0dxbiRJ18/z3qvOvZCyO5"
            "1sMRCSCVz8L1fGDOgwxJC4KaADfnsqceqGvzEXwX+jzuC+IL+OmTCdNQhbIU8e923xWsEBx2iWtFRYAJ30gtuwIDAQAB")
PKCS1_1024 = ("MIGJAoGBAKmSI/tsxSueU3xxrrR9orluCt0qjK9pal72avXTFcut6eYzpoqyTei52C1atK3GB2Aj2x4Oi/emFyLadLdqscEd+KcU"
              "3Faac9qUjvAjg1n1zoPi15IzAmftfA5fOzw5OGlDioGDggTOUix3e3iwUpoWL6ePCKxFx6+ppG51HCuhAgMBAAE=")
ED25519 = base64.b64encode(bytes(range(32))).decode()


class FakeResolver:
    """Answers from dictionaries; names in failing time out."""

    def __init__(self, txt=None, mx=None, addresses=None, failing=()):
        self.txt_answers = {k.lower(): list(v) for k, v in (txt or {}).items()}
        self.mx_answers = {k.lower(): list(v) for k, v in (mx or {}).items()}
        self.address_answers = {k.lower(): list(v) for k, v in (addresses or {}).items()}
        self.failing = {name.lower() for name in failing}
        self.asked = []

    def _answer(self, table, name):
        self.asked.append(name)
        if name.lower() in self.failing:
            raise LookupFailed(f"{name}: Timeout")
        return list(table.get(name.lower(), []))

    def txt(self, name):
        return self._answer(self.txt_answers, name)

    def mx(self, name):
        return self._answer(self.mx_answers, name)

    def addresses(self, name):
        return self._answer(self.address_answers, name)


def good_txt(**changes):
    txt = {
        "_dmarc.example.com": [f"v=DMARC1; p=reject; rua=mailto:{ADDRESS}; ruf=mailto:{ADDRESS}; fo=1"],
        CONSENT: ["v=DMARC1"],
        "example.com": ["v=spf1 include:_spf.mail.example ip4:192.0.2.0/24 -all", "google-site-verification=abc"],
        "_spf.mail.example": ["v=spf1 ip4:198.51.100.0/24 ~all"],
        "s1._domainkey.example.com": [f"v=DKIM1; k=rsa; p={RSA_2048}"],
        "_smtp._tls.example.com": [f"v=TLSRPTv1; rua=mailto:{ADDRESS}"],
    }
    txt.update(changes)
    return {name: value for name, value in txt.items() if value is not None}


def resolver(txt=None, mx=None, addresses=None, failing=()):
    return FakeResolver(
        txt=good_txt() if txt is None else txt,
        mx={"example.com": [(10, "mx.example.com")]} if mx is None else mx,
        addresses={"mx.example.com": ["192.0.2.25"]} if addresses is None else addresses,
        failing=failing,
    )


def target(**changes):
    values = {
        "domain": "example.com", "addresses": {ADDRESS}, "report_address": ADDRESS,
        "dmarc_suggestion": f"v=DMARC1; p=none; rua=mailto:{ADDRESS}",
        "tls_suggestion": f"v=TLSRPTv1; rua=mailto:{ADDRESS}", "dkim_selectors": ["s1"],
    }
    values.update(changes)
    return CheckInput(**values)


def run(res=None, **changes) -> dict:
    result = check_domain(target(**changes), res or resolver(), NOW)
    return {check.key: check for check in result.checks}


class TestWellConfigured:
    def test_everything_in_place(self):
        result = check_domain(target(), resolver(), NOW)
        states = {check.key: check.state for check in result.checks}
        assert states == {"dmarc": "ok", "policy": "ok", "syntax": "ok", "rua": "ok", "ruf": "ok", "consent": "ok",
                          "spf": "ok", "dkim:s1": "ok", "mx": "ok", "tlsrpt": "ok"}
        assert result.status == "ok"

    def test_messages_name_what_was_found(self):
        checks = run()
        assert checks["rua"].message == f"Sammelberichte gehen an {ADDRESS}."
        assert checks["spf"].message == "Ein gültiger SPF-Eintrag mit 1 von 10 DNS-Abfragen, endet mit -all."
        assert checks["dkim:s1"].message == "RSA mit 2048 Bit."
        assert checks["mx"].found == "10 mx.example.com"
        assert checks["consent"].record == CONSENT


class TestDmarc:
    def test_missing_record(self):
        result = check_domain(target(), resolver(txt=good_txt(**{"_dmarc.example.com": None})), NOW)
        record = result.checks[0]
        assert (record.key, record.state, record.record) == ("dmarc", "error", "_dmarc.example.com")
        assert record.suggestion == f"v=DMARC1; p=none; rua=mailto:{ADDRESS}"
        assert "policy" not in {check.key for check in result.checks}
        assert result.status == "error"

    def test_two_records(self):
        checks = run(resolver(txt=good_txt(**{"_dmarc.example.com": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]})))
        assert checks["dmarc"].state == "error"
        assert checks["dmarc"].message.startswith("2 DMARC-Einträge.")

    def test_version_must_be_written_exactly(self):
        checks = run(resolver(txt=good_txt(**{"_dmarc.example.com": [f"v=dmarc1; p=none; rua=mailto:{ADDRESS}"]})))
        assert checks["dmarc"].state == "error"
        assert "genau mit v=DMARC1" in checks["dmarc"].message

    def test_subdomain_inherits_the_record_of_its_organizational_domain(self):
        txt = good_txt(**{"_dmarc.example.com": [f"v=DMARC1; p=none; sp=quarantine; rua=mailto:{ADDRESS}"]})
        checks = run(resolver(txt=txt, mx={}), domain="news.example.com", dkim_selectors=[])
        assert checks["dmarc"].state == "info"
        assert "es gilt der Eintrag von example.com" in checks["dmarc"].message
        assert checks["policy"].found == "sp=quarantine"
        assert checks["consent"].record == CONSENT

    @pytest.mark.parametrize(("record", "state", "text"), [
        (f"v=DMARC1; rua=mailto:{ADDRESS}", "warning", "nennt keine Policy"),
        (f"v=DMARC1; p=block; rua=mailto:{ADDRESS}", "error", "p=block gibt es nicht"),
        (f"v=DMARC1; p=none; rua=mailto:{ADDRESS}", "info", "p=none: Empfänger beobachten nur"),
        (f"v=DMARC1; p=quarantine; pct=20; rua=mailto:{ADDRESS}", "info", "nur auf 20 % der Mails"),
        (f"v=DMARC1; p=reject; t=y; rua=mailto:{ADDRESS}", "info", "im Testmodus nicht an"),
    ])
    def test_policy(self, record, state, text):
        check = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))["policy"]
        assert check.state == state
        assert text in check.message

    def test_invalid_and_unknown_tags(self):
        record = f"v=DMARC1; p=reject; pct=150; adkim=x; fo=2; rua=mailto:{ADDRESS}; foo=bar; p=none"
        check = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))["syntax"]
        assert check.state == "warning"
        for part in ("p steht doppelt", "pct=150 ist ungültig", "adkim=x ist ungültig", "fo=2 ist ungültig",
                     "foo ist unbekannt"):
            assert part in check.message

    def test_unknown_tag_alone_is_a_note(self):
        record = f"v=DMARC1; p=reject; rua=mailto:{ADDRESS}; ruf=mailto:{ADDRESS}; fo=1; foo=bar"
        assert run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))["syntax"].state == "info"

    def test_rua_without_this_application(self):
        record = "v=DMARC1; p=reject; rua=mailto:dmarc@anderswo.example"
        check = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))["rua"]
        assert check.state == "error"
        assert check.message == ("Die Adresse dieser Anwendung fehlt; die Berichte kommen hier nicht an. Richtig ist "
                                 f"{ADDRESS}.")
        assert check.suggestion.startswith("v=DMARC1")

    def test_suggestion_keeps_the_live_record(self):
        record = "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@anderswo.example; fo=d"
        checks = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))
        assert checks["rua"].suggestion == (
            f"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@anderswo.example,mailto:{ADDRESS}; "
            f"ruf=mailto:{ADDRESS}; fo=1:d")
        # ruf fails too; it points to the one suggestion
        assert checks["ruf"].suggestion is None
        assert checks["ruf"].message.endswith("Der richtige Wert steht bei „Sammelberichte (rua)“.")

    def test_suggestion_without_failure_reports(self, monkeypatch):
        monkeypatch.setattr(settings, "DMARC_SUGGEST_FAILURE_REPORTS", False)
        checks = run(resolver(txt=good_txt(**{"_dmarc.example.com": ["v=DMARC1; p=none"]})))
        assert checks["rua"].suggestion == f"v=DMARC1; p=none; rua=mailto:{ADDRESS}"

    def test_suggestion_writes_the_version_correctly(self):
        record = f"v=dmarc1; rua=mailto:{ADDRESS}"
        check = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))["dmarc"]
        assert check.suggestion == f"v=DMARC1; p=none; rua=mailto:{ADDRESS}; ruf=mailto:{ADDRESS}; fo=1"

    def test_rua_with_an_inactive_address_of_this_reception(self, monkeypatch):
        monkeypatch.setattr(settings, "SMTP_INBOUND_DOMAIN", "reports.example.test")
        record = "v=DMARC1; p=reject; rua=mailto:alt-123@reports.example.test"
        check = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))["rua"]
        assert check.state == "error"
        assert check.message.startswith("alt-123@reports.example.test ist keine aktive Empfangsadresse")

    def test_rua_with_size_limit_and_a_second_destination(self):
        record = f"v=DMARC1; p=reject; rua=mailto:{ADDRESS.upper()}!10m,mailto:dmarc@anderswo.example"
        check = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))["rua"]
        assert check.state == "ok"
        assert check.message == f"Sammelberichte gehen an {ADDRESS}. Außerdem an dmarc@anderswo.example."

    def test_rua_missing(self):
        check = run(resolver(txt=good_txt(**{"_dmarc.example.com": ["v=DMARC1; p=reject"]})))["rua"]
        assert check.state == "error"
        assert "keine Adresse in rua" in check.message

    def test_ruf(self, monkeypatch):
        record = f"v=DMARC1; p=reject; rua=mailto:{ADDRESS}"
        res = resolver(txt=good_txt(**{"_dmarc.example.com": [record]}))
        assert run(res)["ruf"].state == "warning"
        monkeypatch.setattr(settings, "DMARC_SUGGEST_FAILURE_REPORTS", False)
        assert run(res)["ruf"].state == "info"
        monkeypatch.setattr(settings, "FAILURE_REPORTS_ENABLED", False)
        assert "ruf" not in run(res)

    def test_ruf_without_fo_is_a_note(self):
        record = f"v=DMARC1; p=reject; rua=mailto:{ADDRESS}; ruf=mailto:{ADDRESS}"
        check = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record]})))["ruf"]
        assert check.state == "info"
        assert "Mit fo=1 melden Empfänger" in check.message

    def test_consent_missing(self):
        checks = run(resolver(txt=good_txt(**{CONSENT: None})))
        assert checks["consent"].state == "error"
        assert checks["consent"].record == CONSENT
        assert checks["consent"].suggestion == "v=DMARC1"

    def test_consent_by_wildcard_record(self):
        # A wildcard answers for every name below it; the resolver sees the answer for the full name
        checks = run(resolver(txt=good_txt(**{CONSENT: ["v=DMARC1;"]})))
        assert checks["consent"].state == "ok"

    def test_no_consent_needed_within_the_same_organizational_domain(self):
        address = "dmarc@reports.example.com"
        record = f"v=DMARC1; p=reject; rua=mailto:{address}; ruf=mailto:{address}; fo=1"
        checks = run(resolver(txt=good_txt(**{"_dmarc.example.com": [record], CONSENT: None})),
                     addresses={address}, report_address=address)
        assert "consent" not in checks


def spf(record=None, extra=None, failing=()):
    txt = good_txt(**{"example.com": [record] if record else None})
    txt.update(extra or {})
    return run(resolver(txt=txt, failing=failing))["spf"]


class TestSpf:
    def test_missing(self):
        check = spf()
        assert check.state == "warning"
        assert "v=spf1 -all" in check.message

    def test_two_records(self):
        check = run(resolver(txt=good_txt(**{"example.com": ["v=spf1 -all", "v=spf1 mx -all"]})))["spf"]
        assert (check.state, check.message.split(".")[0]) == ("error", "2 SPF-Einträge")

    @pytest.mark.parametrize(("record", "state", "text"), [
        ("v=spf1 +all", "error", "+all erlaubt jedem Server"),
        ("v=spf1 mx all", "error", "all erlaubt jedem Server"),
        ("v=spf1 mx ?all", "warning", "?all wertet fremde Server als neutral"),
        ("v=spf1 mx", "warning", "endet ohne all"),
        ("v=spf1 ptr -all", "warning", "ptr ist langsam"),
        ("v=spf1 mx foo:bar -all", "error", "„foo:bar“ ist kein gültiger Teil"),
        ("v=spf1 a mx ~all", "ok", "2 von 10 DNS-Abfragen, endet mit ~all"),
    ])
    def test_terms(self, record, state, text):
        check = spf(record)
        assert check.state == state
        assert text in check.message

    def test_redirect_counts_and_decides_the_end(self):
        check = spf("v=spf1 redirect=_spf.mail.example")
        assert check.state == "ok"
        assert check.message == "Ein gültiger SPF-Eintrag mit 1 von 10 DNS-Abfragen, endet über redirect."

    def test_too_many_lookups(self):
        extra = {f"s{i}.spf.example": [f"v=spf1 include:s{i + 1}.spf.example -all"] for i in range(12)}
        check = spf("v=spf1 include:s0.spf.example -all", extra)
        assert check.state == "error"
        assert "mindestens 11 DNS-Abfragen, erlaubt sind 10 (RFC 7208)" in check.message

    def test_loop(self):
        extra = {"a.spf.example": ["v=spf1 include:b.spf.example -all"],
                 "b.spf.example": ["v=spf1 include:a.spf.example -all"]}
        check = spf("v=spf1 include:a.spf.example -all", extra)
        assert check.state == "error"
        assert "include:a.spf.example verweist im Kreis" in check.message

    def test_same_include_in_two_branches_is_no_loop(self):
        extra = {"a.spf.example": ["v=spf1 include:common.spf.example -all"],
                 "b.spf.example": ["v=spf1 include:common.spf.example -all"],
                 "common.spf.example": ["v=spf1 ip4:192.0.2.0/24 -all"]}
        check = spf("v=spf1 include:a.spf.example include:b.spf.example -all", extra)
        assert check.state == "ok"
        assert "4 von 10 DNS-Abfragen" in check.message

    def test_include_without_spf(self):
        check = spf("v=spf1 include:leer.spf.example -all")
        assert check.state == "error"
        assert "include:leer.spf.example hat keinen SPF-Eintrag" in check.message

    def test_macro_counts_but_is_not_followed(self):
        check = spf("v=spf1 exists:%{i}._spf.example.com -all")
        assert check.state == "ok"
        assert "1 von 10" in check.message

    def test_unanswered_include(self):
        check = spf("v=spf1 include:langsam.spf.example -all", failing=("langsam.spf.example",))
        assert check.state == "unknown"


def dkim(record):
    return run(resolver(txt=good_txt(**{"s1._domainkey.example.com": record})))["dkim:s1"]


class TestDkim:
    def test_key_lengths(self):
        assert rsa_key_bits(base64.b64decode(RSA_2048)) == 2048
        assert rsa_key_bits(base64.b64decode(RSA_1024)) == 1024
        assert rsa_key_bits(base64.b64decode(PKCS1_1024)) == 1024
        assert rsa_key_bits(b"\x30\x03\x02\x01") is None
        assert rsa_key_bits(b"kein schluessel") is None

    def test_strong_key(self):
        assert dkim([f"v=DKIM1; k=rsa; p={RSA_2048}"]).state == "ok"

    def test_short_key_gets_a_note(self):
        check = dkim([f"v=DKIM1; p={RSA_1024}"])
        assert (check.state, check.message) == ("info", "RSA mit 1024 Bit; empfohlen sind 2048 Bit.")

    def test_recommendation_comes_from_the_settings(self, monkeypatch):
        monkeypatch.setattr(settings, "DNS_CHECK_DKIM_RECOMMENDED_BITS", 1024)
        assert dkim([f"v=DKIM1; p={RSA_1024}"]).state == "ok"
        monkeypatch.setattr(settings, "DNS_CHECK_DKIM_RECOMMENDED_BITS", 4096)
        assert dkim([f"v=DKIM1; p={RSA_2048}"]).message == "RSA mit 2048 Bit; empfohlen sind 4096 Bit."

    def test_key_below_the_minimum(self):
        check = dkim([f"v=DKIM1; p={RSA_512}"])
        assert check.state == "error"
        assert "unter 1024 Bit nicht (RFC 8301)" in check.message

    def test_key_split_over_strings_and_spaces(self):
        assert dkim([f"v=DKIM1; k=rsa; p={RSA_2048[:100]} {RSA_2048[100:]}"]).state == "ok"

    @pytest.mark.parametrize(("record", "state", "text"), [
        (None, "error", "fehlt jetzt im DNS"),
        (["v=DKIM1; p="], "warning", "widerrufen"),
        (["v=DKIM1; p=!!!"], "error", "kein gültiges Base64"),
        ([f"v=DKIM1; k=ed25519; p={ED25519}"], "ok", "Ed25519-Schlüssel."),
        (["v=DKIM1; k=ed25519; p=AAAA"], "error", "nicht 32 Byte"),
        ([f"v=DKIM1; t=y; p={RSA_2048}"], "info", "Testmodus"),
        ([f"v=DKIM1; p={RSA_2048}", f"v=DKIM1; p={RSA_1024}"], "warning", "2 Schlüssel"),
    ])
    def test_records(self, record, state, text):
        check = dkim(record)
        assert check.state == state
        assert text in check.message

    def test_without_selectors(self):
        checks = run(dkim_selectors=[])
        assert checks["dkim"].state == "info"
        assert "keine Signatur von example.com bestanden" in checks["dkim"].message


class TestMailServers:
    def test_without_mx(self):
        checks = run(resolver(mx={}))
        assert checks["mx"].state == "info"
        assert (checks["tlsrpt"].state, checks["tlsrpt"].message) == (
            "info", "Ohne Mailempfang braucht die Domain keinen Eintrag.")

    def test_null_mx(self):
        checks = run(resolver(mx={"example.com": [(0, "")]}))
        assert checks["mx"].state == "info"
        assert "Null-MX" in checks["mx"].message

    def test_mx_without_address(self):
        check = run(resolver(addresses={}))["mx"]
        assert check.state == "warning"
        assert check.message.startswith("mx.example.com hat keine IP-Adresse")

    @pytest.mark.parametrize(("records", "state", "text", "suggestion"), [
        (None, "warning", "Kein Eintrag", f"v=TLSRPTv1; rua=mailto:{ADDRESS}"),
        ([f"v=TLSRPTv1; rua=mailto:{ADDRESS}", "v=TLSRPTv1; rua=mailto:x@y.example"], "error", "2 Einträge",
         f"v=TLSRPTv1; rua=mailto:{ADDRESS}"),
        (["v=TLSRPTv1; rua=mailto:tls@anderswo.example"], "warning", "andere Adresse",
         f"v=TLSRPTv1; rua=mailto:tls@anderswo.example,mailto:{ADDRESS}"),
    ])
    def test_tls_reporting(self, records, state, text, suggestion):
        check = run(resolver(txt=good_txt(**{"_smtp._tls.example.com": records})))["tlsrpt"]
        assert check.state == state
        assert text in check.message
        assert check.suggestion == suggestion

    def test_tls_reporting_switched_off(self, monkeypatch):
        monkeypatch.setattr(settings, "TLS_REPORTS_ENABLED", False)
        assert "tlsrpt" not in run()


class TestUnanswered:
    def test_unanswered_dmarc_leaves_the_state_open(self):
        result = check_domain(target(), resolver(failing=("_dmarc.example.com",)), NOW)
        assert result.checks[0].state == "unknown"
        assert "brachte keine Antwort" in result.checks[0].message
        assert result.status == "unknown"

    def test_error_outweighs_a_missing_answer(self):
        result = check_domain(target(), resolver(txt=good_txt(**{CONSENT: None}), failing=("example.com",)), NOW)
        assert result.status == "error"

    def test_result_survives_storage(self):
        result = check_domain(target(), resolver(), NOW)
        again = DnsCheckResult.from_json(result.to_json())
        assert again.status == "ok" and again.checks == result.checks
        assert DnsCheckResult.from_json("{kaputt") is None


# With the database --------------------------------------------------------------------------

def _our_address(db, org, domain):
    """The report address the fake DNS names, as an active address of the organisation."""
    db.add(InboundMailAddress(organization_id=org.id, domain_id=domain.id, address=ADDRESS, token="dom-example-abc123",
                              status="active", purpose="domain_report"))
    db.flush()


def _dkim_row(db, report, selector, result="pass", domain="example.com"):
    record = db.query(DmarcRecord).filter_by(report_id=report.id).first()
    db.add(DmarcAuthResult(record_id=record.id, auth_type="dkim", domain=domain, result=result, selector=selector))
    db.flush()


class TestWithDatabase:
    def test_input_from_the_organisation(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        address = create_domain_address(session, org, domain).address
        report = add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)])
        _dkim_row(session, report, "s1")
        _dkim_row(session, report, "s1")
        _dkim_row(session, report, "s2")
        _dkim_row(session, report, "gefälscht", result="fail")
        _dkim_row(session, report, "fremd", domain="mailer.example")
        old = add_report(session, org, domain, [("192.0.2.2", 5, True, True, True)],
                         created_at=NOW - timedelta(days=40))
        _dkim_row(session, old, "alt")
        found = gather_input(session, domain, NOW)
        assert found.report_address == address
        assert address in found.addresses
        assert found.dkim_selectors == ["s1", "s2"]
        assert found.dmarc_suggestion.startswith("v=DMARC1; p=none; rua=mailto:" + address)

    @pytest.mark.parametrize(("days", "limit", "selectors"), [(60, 10, ["alt", "s1"]), (30, 1, ["s1"])])
    def test_selector_window_and_limit_come_from_the_settings(self, session, monkeypatch, days, limit, selectors):
        monkeypatch.setattr(settings, "DNS_CHECK_DKIM_DAYS", days)
        monkeypatch.setattr(settings, "DNS_CHECK_DKIM_MAX_SELECTORS", limit)
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        report = add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)])
        _dkim_row(session, report, "s1")
        old = add_report(session, org, domain, [("192.0.2.2", 5, True, True, True)],
                         created_at=NOW - timedelta(days=40))
        _dkim_row(session, old, "alt")
        assert sorted(gather_input(session, domain, NOW).dkim_selectors) == selectors

    def test_run_check_keeps_the_result(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        run_check(session, domain, resolver(txt={}), NOW)
        assert domain.dns_status == "error"
        assert stored_result(domain).checks[0].message.startswith("Kein DMARC-Eintrag")
        assert domain.dns_checked_at == NOW

    def test_due_domains(self, session, monkeypatch):
        monkeypatch.setattr(settings, "DNS_CHECK_MAX_AGE_SECONDS", 3600)
        org = make_org(session)
        fresh = make_domain(session, org, "frisch.example")
        fresh.dns_checked_at = NOW - timedelta(minutes=10)
        old = make_domain(session, org, "alt.example")
        old.dns_checked_at = NOW - timedelta(hours=5)
        older = make_domain(session, org, "aelter.example")
        older.dns_checked_at = NOW - timedelta(hours=9)
        make_domain(session, org, "neu.example")
        idle = make_domain(session, org, "ruhend.example")
        idle.is_active = False
        session.flush()
        assert [d.name for d in due_domains(session, NOW, 10)] == ["neu.example", "aelter.example", "alt.example"]
        assert [d.name for d in due_domains(session, NOW, 1)] == ["neu.example"]

    def test_scheduled_run(self, session, monkeypatch):
        monkeypatch.setattr(settings, "DNS_CHECK_ENABLED", True)
        monkeypatch.setattr(settings, "DNS_CHECK_BATCH_SIZE", 2)
        org = make_org(session)
        for name in ("a.example", "b.example", "c.example"):
            make_domain(session, org, name)
        assert run_due_checks(session, NOW, lambda: resolver(txt={})) == {org.id}
        checked = session.query(Domain).filter(Domain.dns_checked_at.isnot(None)).count()
        assert checked == 2
        monkeypatch.setattr(settings, "DNS_CHECK_ENABLED", False)
        assert run_due_checks(session, NOW, lambda: resolver(txt={})) == set()

    def test_faulty_domain_raises_one_alert(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        make_domain(session, org, "example.org")
        rule = make_rule(session, org, "dns_problem")
        run_check(session, domain, resolver(txt=good_txt(**{"_dmarc.example.com": None})), NOW)
        events = evaluate_rules_for_org(session, org.id, NOW)
        assert [e.title for e in events] == ["DNS-Einträge fehlerhaft für example.com"]
        assert events[0].description.startswith("DMARC-Eintrag: Kein DMARC-Eintrag.")
        assert json.loads(events[0].metrics)["errors"] == ["dmarc"]
        assert evaluate_rules_for_org(session, org.id, NOW + timedelta(hours=1)) == []
        assert session.query(AlertEvent).filter_by(rule_id=rule.id).count() == 1

    def test_warnings_raise_no_alert(self, session):
        org = make_org(session)
        domain = make_domain(session, org, "example.com")
        _our_address(session, org, domain)
        make_rule(session, org, "dns_problem")
        run_check(session, domain, resolver(txt=good_txt(**{"_smtp._tls.example.com": None})), NOW)
        assert domain.dns_status == "warning"
        assert evaluate_rules_for_org(session, org.id, NOW) == []

    def test_hint(self):
        assert "Hinweise lösen keinen Alarm aus" in alert_type_hints()["dns_problem"]


def test_scheduler_job_checks_and_alerts(session, monkeypatch):
    monkeypatch.setattr(settings, "DNS_CHECK_ENABLED", True)
    monkeypatch.setattr(dns_check, "Resolver", lambda: resolver(txt={}))
    org = make_org(session)
    make_domain(session, org, "example.com")
    make_rule(session, org, "dns_problem")
    session.commit()
    assert scheduler._run_dns(session, NOW) == 1
    assert session.query(AlertEvent).count() == 1


# Pages and API --------------------------------------------------------------------------------

def page_txt(**changes):
    """DNS of the seeded example.com: its reports name the DKIM selectors default and s2026."""
    keys = {f"{selector}._domainkey.example.com": [f"v=DKIM1; p={RSA_2048}"] for selector in ("default", "s2026")}
    return good_txt(**keys, **changes)


@pytest.fixture
def fake_dns(monkeypatch):
    answers = {"txt": page_txt()}
    monkeypatch.setattr(dns_check, "Resolver", lambda: resolver(txt=answers["txt"]))
    return answers


def _seed_with_address(session_factory, **kwargs) -> dict:
    ids = _seed(session_factory, **kwargs)
    db = session_factory()
    _our_address(db, db.get(Organization, ids["org"]), db.get(Domain, ids["domain"]))
    db.commit()
    db.close()
    return ids


def _domain_id(session_factory, org_id, name="example.com"):
    db = session_factory()
    domain_id = db.query(Domain).filter_by(organization_id=org_id, name=name).one().id
    db.close()
    return domain_id


class TestPages:
    def test_domain_page_before_the_first_check(self, web, session_factory):
        ids = _seed(session_factory)
        _login(web, ids["org"])
        page = web.get(f"/domains/{ids['domain']}").text
        assert 'id="dns-pruefung"' in page
        assert "Noch nicht geprüft" in page and "noch nicht geprüft" in page

    def test_check_now(self, web, session_factory, fake_dns):
        ids = _seed_with_address(session_factory)
        fake_dns["txt"] = page_txt(**{"_dmarc.example.com": None})
        _login(web, ids["org"])
        response = web.post(f"/domains/{ids['domain']}/dns-check")
        assert response.status_code == 303
        assert response.headers["location"].endswith("#dns-pruefung")
        page = web.get(f"/domains/{ids['domain']}").text
        assert "example.com: 1 Fehler im DNS" in page
        assert "Kein DMARC-Eintrag. Ohne ihn schicken Empfänger keine Berichte" in page
        assert "Richtiger Wert für _dmarc.example.com" in page
        assert 'class="bc-row-title">DMARC-Eintrag</span>' in page

    def test_all_in_order(self, web, session_factory, fake_dns):
        ids = _seed_with_address(session_factory)
        _login(web, ids["org"])
        web.post(f"/domains/{ids['domain']}/dns-check")
        page = web.get(f"/domains/{ids['domain']}").text
        assert "example.com: DNS in Ordnung" in page
        assert "Richtiger Wert für" not in page

    def test_check_now_needs_the_analyst_role(self, web, session_factory, fake_dns):
        ids = _seed(session_factory, role="read_only", superadmin=False)
        _login(web, ids["org"])
        page = web.get(f"/domains/{ids['domain']}").text
        assert ">Jetzt prüfen</button>" not in page
        assert "Die Prüfung starten Mitglieder ab der Rolle Analyst." in page
        assert web.post(f"/domains/{ids['domain']}/dns-check").status_code == 403

    def test_domain_of_another_organisation(self, web, session_factory, fake_dns):
        ids = _seed(session_factory)
        db = session_factory()
        other = Organization(name="Andere", slug="andere", is_active=True)
        db.add(other)
        db.flush()
        foreign = make_domain(db, other, "fremd.example")
        db.commit()
        foreign_id = foreign.id
        db.close()
        _login(web, ids["org"])
        assert web.post(f"/domains/{foreign_id}/dns-check").status_code == 404

    def test_list_column_filter_and_dashboard(self, web, session_factory, fake_dns):
        ids = _seed(session_factory)
        fake_dns["txt"] = {}
        _login(web, ids["org"])
        web.post(f"/domains/{ids['domain']}/dns-check")
        listing = web.get("/domains?dns=error").text
        assert "example.com" in listing and "Fehler" in listing
        assert "Keine Domain passt zur Suche" in web.get("/domains?dns=ok").text
        dashboard = web.get("/dashboard").text
        assert "1 Domain hat Fehler im DNS" in dashboard
        assert 'href="/domains?dns=error"' in dashboard

    def test_api(self, web, session_factory, fake_dns):
        ids = _seed(session_factory)
        db = session_factory()
        user = db.query(User).filter_by(email="admin@example.test").one()
        raw, _ = create_api_token(db, ids["org"], user.id, "Automatik")
        db.commit()
        db.close()
        headers = {"Authorization": f"Bearer {raw}"}
        before = web.get(f"/api/v1/domains/{ids['domain']}/dns-check", headers=headers).json()
        assert before == {"domain": "example.com", "status": None, "checked_at": None, "checks": []}
        after = web.post(f"/api/v1/domains/{ids['domain']}/dns-check", headers=headers).json()
        assert after["status"] in ("ok", "warning", "error")
        assert after["checks"][0]["key"] == "dmarc"
        listed = web.get("/api/v1/domains", headers=headers).json()
        assert listed[0]["dns_status"] == after["status"]
        assert web.get("/api/v1/domains/unbekannt/dns-check", headers=headers).status_code == 404


@pytest.mark.parametrize(("name", "value", "reason"), [
    ("DNS_CHECK_INTERVAL_SECONDS", "10", "muss mindestens 60 sein"),
    ("DNS_CHECK_MAX_AGE_SECONDS", "60", "muss mindestens 600 sein"),
    ("DNS_CHECK_BATCH_SIZE", "0", "muss mindestens 1 sein"),
    ("DNS_CHECK_WORKERS", "64", "darf höchstens 32 sein"),
    ("DNS_CHECK_TIMEOUT_SECONDS", "0.1", "muss mindestens 0.5 sein"),
    ("DNS_CHECK_DKIM_RECOMMENDED_BITS", "512", "muss mindestens 1024 sein"),
    ("DNS_CHECK_ENABLED", "vielleicht", "muss true oder false sein"),
])
def test_settings_have_bounds(name, value, reason, monkeypatch):
    monkeypatch.setenv(name, value)
    with pytest.raises(SystemExit) as exc:
        load_settings()
    assert f"{name}: {reason}" in str(exc.value)
