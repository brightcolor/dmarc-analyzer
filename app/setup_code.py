"""
Show the setup code for the first administrator account.

    docker compose exec web python -m app.setup_code
"""
import sys

from app.database import SessionLocal
from app.migrate import run_migrations
from app.services.setup import ensure_setup_code


def main() -> int:
    run_migrations()
    db = SessionLocal()
    try:
        code = ensure_setup_code(db)
    finally:
        db.close()
    if code is None:
        print("Ein Administratorkonto existiert bereits. Die Ersteinrichtung ist geschlossen.")
        return 1
    print(f"Einrichtungscode: {code}")
    print("Öffne /auth/setup in der Anwendung und lege damit das erste Administratorkonto an.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
