"""
Show or change the limits of an organisation (operator tool).

    docker compose exec web python -m app.org_limits
    docker compose exec web python -m app.org_limits <kennung> --max-domains 500
"""
import argparse
import sys

from sqlalchemy import func

from app.database import SessionLocal
from app.migrate import run_migrations
from app.models import ApiToken, Domain, Organization, OrganizationMembership

LIMITS = {
    "max_domains": ("Domains", 1, 1_000_000),
    "max_users": ("Benutzer", 1, 1_000_000),
    "max_api_tokens": ("API-Tokens", 0, 1_000_000),
    "max_alert_rules": ("Alarmregeln", 0, 1_000_000),
    "max_inbound_addresses": ("Empfangsadressen", 1, 1_000_000),
    "report_retention_days": ("Tage Aufbewahrung", 1, 36_500),
}


def _usage(db, org: Organization) -> dict[str, int]:
    return {
        "max_domains": db.query(func.count(Domain.id)).filter_by(organization_id=org.id).scalar(),
        "max_users": db.query(func.count(OrganizationMembership.id)).filter_by(organization_id=org.id).scalar(),
        "max_api_tokens": db.query(func.count(ApiToken.id)).filter_by(organization_id=org.id, is_active=True).scalar(),
    }


def _show(db, org: Organization) -> None:
    used = _usage(db, org)
    print(f"{org.name} ({org.slug})")
    for field, (label, _, _) in LIMITS.items():
        in_use = f", genutzt {used[field]}" if field in used else ""
        print(f"  {label}: {getattr(org, field)}{in_use}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.org_limits",
                                     description="Grenzen einer Organisation anzeigen oder ändern.")
    parser.add_argument("slug", nargs="?", help="Kennung der Organisation; ohne Angabe zeigt das Werkzeug alle.")
    for field, (label, _, _) in LIMITS.items():
        parser.add_argument("--" + field.replace("_", "-"), type=int, dest=field, help=label)
    args = parser.parse_args(argv)

    run_migrations()
    db = SessionLocal()
    try:
        if not args.slug:
            for org in db.query(Organization).order_by(Organization.name):
                _show(db, org)
            return 0
        org = db.query(Organization).filter_by(slug=args.slug).first()
        if org is None:
            print(f"Eine Organisation mit der Kennung „{args.slug}“ gibt es nicht. Ohne Kennung zeigt das Werkzeug "
                  "alle Organisationen.")
            return 2
        changes = {field: getattr(args, field) for field in LIMITS if getattr(args, field) is not None}
        for field, value in changes.items():
            label, low, high = LIMITS[field]
            if not low <= value <= high:
                print(f"{label} muss zwischen {low} und {high} liegen, angegeben war {value}.")
                return 2
        for field, value in changes.items():
            setattr(org, field, value)
        db.commit()
        _show(db, org)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
