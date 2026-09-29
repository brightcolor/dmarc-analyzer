"""
Bring the database schema up to date with Alembic.

Databases created by v0.1.0 (via create_all, without migration history) are adopted
by stamping the baseline revision before upgrading.

Run manually with: python -m app.migrate
"""
import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASELINE_REVISION = "0001"
# Table that exists in every schema since v0.1.0; marks a database created before migrations.
SENTINEL_TABLE = "organizations"


def _alembic_config(connection: Connection) -> Config:
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    cfg.attributes["configure_logger"] = False
    cfg.attributes["connection"] = connection
    return cfg


def _has_revision(connection: Connection) -> bool:
    if not inspect(connection).has_table("alembic_version"):
        return False
    return connection.execute(text("SELECT COUNT(*) FROM alembic_version")).scalar() > 0


def run_migrations(engine: Engine | None = None) -> None:
    if engine is None:
        from app.database import engine as app_engine
        engine = app_engine
    with engine.begin() as connection:
        cfg = _alembic_config(connection)
        if inspect(connection).has_table(SENTINEL_TABLE) and not _has_revision(connection):
            logger.info("Existing database without migration history, marking it as revision %s",
                        BASELINE_REVISION)
            command.stamp(cfg, BASELINE_REVISION)
        command.upgrade(cfg, "head")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    run_migrations()
