"""
Fill a local SQLite database with invented demo data for previews and screenshots.

    DATABASE_URL=sqlite:///./demo.db python scripts/demo_data.py

Creates an organisation, an administrator, three domains and about a month of reports in
both formats (RFC 7489 and RFC 9990). The administrator's login goes to demo-login.txt
(ignored by git). Refuses to run against anything other than SQLite.
"""
import os
import random
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402

if not settings.DATABASE_URL.startswith("sqlite"):
    sys.exit("Das Demo-Skript läuft nur gegen eine lokale SQLite-Datenbank. Setze DATABASE_URL=sqlite:///./demo.db.")

from app.database import SessionLocal  # noqa: E402
from app.migrate import run_migrations  # noqa: E402
from app.models import (  # noqa: E402
    AlertEvent,
    Domain,
    ImportJob,
    Organization,
    OrganizationMembership,
    SourceIp,
)
from app.services.auth import create_user  # noqa: E402
from app.services.dmarc_parser import parse_xml_bytes  # noqa: E402
from app.services.import_service import store_parsed_report  # noqa: E402
from app.services.inbound_address import create_domain_address, create_org_address  # noqa: E402
from app.services.setup import clear_setup_code  # noqa: E402

LOGIN_FILE = Path(__file__).resolve().parent.parent / "demo-login.txt"
DOMAINS = [("example.com", "reject", "quarantine", 100), ("example.org", "quarantine", None, 0),
           ("example.net", "none", None, 100)]
SOURCES = {
    "192.0.2.10": ("example.com", True), "192.0.2.11": ("example.com", True),
    "198.51.100.20": ("example.com", True), "198.51.100.66": ("example.org", False),
    "203.0.113.5": ("example.net", False), "203.0.113.77": ("example.net", True),
}


def _record(ip: str, count: int, passed: bool, domain: str, dmarcbis: bool, testing: bool) -> str:
    if passed:
        disposition = "pass" if dmarcbis else "none"
        dkim = f"<dkim><domain>{domain}</domain><selector>s1</selector><result>pass</result></dkim>"
        spf = f"<spf><domain>{domain}</domain><scope>mfrom</scope><result>pass</result></spf>"
        evaluated = "<dkim>pass</dkim><spf>pass</spf>"
        reason = ""
    else:
        disposition = "none"
        dkim = "<dkim><domain>mailer.example</domain><selector>m1</selector><result>fail</result></dkim>"
        spf = "<spf><domain>mailer.example</domain><scope>mfrom</scope><result>softfail</result></spf>"
        evaluated = "<dkim>fail</dkim><spf>fail</spf>"
        reason = "<reason><type>policy_test_mode</type></reason>" if dmarcbis and testing else ""
    return (f"<record><row><source_ip>{ip}</source_ip><count>{count}</count><policy_evaluated>"
            f"<disposition>{disposition}</disposition>{evaluated}{reason}</policy_evaluated></row>"
            f"<identifiers><header_from>{domain}</header_from></identifiers>"
            f"<auth_results>{dkim}{spf}</auth_results></record>")


def _report(reporter: str, email: str, domain: str, policy: tuple, day: datetime, dmarcbis: bool,
            namespace: bool, rng: random.Random) -> bytes:
    _, p, sp, pct = policy
    testing = pct == 0
    begin = int(day.timestamp())
    records = []
    for ip, (ip_domain, passed) in SOURCES.items():
        if ip_domain != domain:
            continue
        count = rng.randint(20, 400) if passed else rng.randint(1, 30)
        records.append(_record(ip, count, passed, domain, dmarcbis, testing))
    if dmarcbis:
        policy_xml = (f"<domain>{domain}</domain><discovery_method>treewalk</discovery_method><p>{p}</p>"
                      + (f"<sp>{sp}</sp>" if sp else "") + "<np>reject</np>"
                      + f"<testing>{'y' if testing else 'n'}</testing>")
        head = '<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">' if namespace else "<feedback>"
        meta_extra = "<generator>Demo Reporter 1.0</generator>"
    else:
        policy_xml = (f"<domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>{p}</p>"
                      + (f"<sp>{sp}</sp>" if sp else "") + f"<pct>{pct}</pct>")
        head = "<feedback>"
        meta_extra = ""
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>{head}<version>1.0</version><report_metadata>'
           f"<org_name>{reporter}</org_name><email>{email}</email>"
           f"<report_id>{reporter.split()[0].lower()}-{domain}-{day:%Y%m%d}</report_id>"
           f"<date_range><begin>{begin}</begin><end>{begin + 86399}</end></date_range>{meta_extra}"
           f"</report_metadata><policy_published>{policy_xml}</policy_published>{''.join(records)}</feedback>")
    return xml.encode("utf-8")


def main() -> None:
    run_migrations()
    db = SessionLocal()
    rng = random.Random(7)
    try:
        if db.query(Organization).filter_by(slug="muster-farben").first():
            sys.exit("Die Demo-Daten sind schon angelegt. Lösche demo.db für einen frischen Stand.")

        org = Organization(name="Muster Farben", slug="muster-farben", is_active=True)
        db.add(org)
        db.flush()
        password = secrets.token_urlsafe(14)
        user = create_user(db, email="admin@example.test", password=password, full_name="Max Mustermann",
                           is_superadmin=True)
        db.add(OrganizationMembership(user_id=user.id, organization_id=org.id, role="org_admin"))
        create_org_address(db, org)
        clear_setup_code(db)

        reporters = [("Beispiel Mail AG", "reports@mail.example", True, True),
                     ("Nordlicht Post", "dmarc@post.example", False, False),
                     ("Muster Webmail", "noreply@webmail.example", True, False)]
        today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        for policy in DOMAINS:
            domain = Domain(organization_id=org.id, name=policy[0], is_active=True)
            db.add(domain)
            db.flush()
            create_domain_address(db, org, domain)
            job = ImportJob(organization_id=org.id, source="smtp_inbound", status="completed",
                            file_name=f"{policy[0]}-reports.zip", file_type="zip", records_imported=0)
            db.add(job)
            db.flush()
            for offset in range(1, 29):
                day = today - timedelta(days=offset)
                for name, email, dmarcbis, namespace in reporters:
                    if rng.random() < 0.15:
                        continue
                    parsed = parse_xml_bytes(_report(name, email, policy[0], policy, day, dmarcbis, namespace, rng))
                    store_parsed_report(db, parsed, org.id, job.id, import_source="smtp_inbound")
                    job.records_imported += 1
        db.add(ImportJob(organization_id=org.id, source="web_upload", status="failed", file_name="export.zip",
                         file_type="zip", error_message="Die ZIP-Datei ist beschädigt oder unvollständig. "
                         "Bitte lade sie erneut hoch."))

        classifications = {"192.0.2.10": "trusted", "192.0.2.11": "trusted", "198.51.100.66": "suspicious"}
        for ip, classification in classifications.items():
            source = db.query(SourceIp).filter_by(organization_id=org.id, ip_address=ip).first()
            if source:
                source.classification = classification

        example_net = db.query(Domain).filter_by(organization_id=org.id, name="example.net").one()
        db.add(AlertEvent(organization_id=org.id, domain_id=example_net.id, alert_type="new_unknown_source",
                          severity="warning", title="Neue unbekannte Versandquelle 203.0.113.5",
                          description="203.0.113.5 verschickt Mails für example.net und besteht DMARC nicht.",
                          source_ip="203.0.113.5", status="open"))
        db.commit()
        LOGIN_FILE.write_text(f"E-Mail: admin@example.test\nPasswort: {password}\n", encoding="utf-8")
        print(f"Demo-Daten angelegt. Anmeldung steht in {LOGIN_FILE.name}.")
    finally:
        db.close()


if __name__ == "__main__":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    main()
