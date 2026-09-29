"""
Check the way out for mail without sending one.

    docker compose exec web python -m app.mail_check
"""
import sys

from app.services.mailer import MailDeliveryError, MailNotConfigured, check_connection, describe_backend


def main() -> int:
    print(f"Mailversand: {describe_backend()}")
    try:
        print(check_connection())
    except (MailNotConfigured, MailDeliveryError) as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
