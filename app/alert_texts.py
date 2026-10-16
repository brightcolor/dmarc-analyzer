"""
Bring title and text of the open alerts to the current wording (domains, host name, provider, causes).

    docker compose exec web python -m app.alert_texts
"""
import sys

from app.database import SessionLocal
from app.migrate import run_migrations
from app.services.alert_service import refresh_event_texts


def main() -> int:
    run_migrations()
    db = SessionLocal()
    try:
        changed = refresh_event_texts(db)
        db.commit()
    finally:
        db.close()
    print(f"Titel und Text von {changed} offenen Alarmen aktualisiert.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
