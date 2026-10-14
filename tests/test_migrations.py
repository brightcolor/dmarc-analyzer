"""Schema migrations: fresh databases and databases created by v0.1.0 without migration history."""
import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool

from app.migrate import BASELINE_REVISION, PROJECT_ROOT, _alembic_config, run_migrations

# Newest revision in migrations/versions
HEAD = ScriptDirectory(str(PROJECT_ROOT / "migrations")).get_current_head()


@pytest.fixture
def file_engine():
    # One shared in-memory connection keeps the schema between connections
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    yield engine
    engine.dispose()


def _head(engine) -> str:
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _columns(engine, table: str) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns(table)}


def test_fresh_database_gets_full_schema(file_engine):
    run_migrations(file_engine)
    assert "report_format" in _columns(file_engine, "dmarc_reports")
    assert "override_reasons" in _columns(file_engine, "dmarc_records")
    assert "dmarc_policy_testing" in _columns(file_engine, "domains")
    assert _head(file_engine) == HEAD


def test_database_without_history_is_adopted(file_engine):
    # v0.1.0 created its tables without recording a revision
    with file_engine.begin() as conn:
        command.upgrade(_alembic_config(conn), BASELINE_REVISION)
        conn.execute(text("DELETE FROM alembic_version"))
        conn.execute(text(
            "INSERT INTO organizations (id, name, slug, is_active, max_domains, max_users, max_api_tokens, "
            "max_alert_rules, max_inbound_addresses, report_retention_days, smtp_rate_limit_per_hour, "
            "api_rate_limit_per_hour, created_at, updated_at) "
            "VALUES ('org-1', 'Muster Farben', 'muster-farben', 1, 10, 5, 5, 20, 20, 365, 200, 1000, "
            "'2026-05-28', '2026-05-28')"
        ))
    assert "report_format" not in _columns(file_engine, "dmarc_reports")

    run_migrations(file_engine)

    assert "report_format" in _columns(file_engine, "dmarc_reports")
    assert _head(file_engine) == HEAD
    with file_engine.connect() as conn:
        assert conn.execute(text("SELECT name FROM organizations")).scalar() == "Muster Farben"


def test_running_twice_changes_nothing(file_engine):
    run_migrations(file_engine)
    run_migrations(file_engine)
    assert _head(file_engine) == HEAD


def test_migrations_match_models(file_engine):
    """Autogenerate finds no difference between the migrated schema and the models."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from app.models import Base

    run_migrations(file_engine)
    with file_engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


def test_existing_classifications_count_as_manual(file_engine):
    with file_engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "0003")
        conn.execute(text(
            "INSERT INTO organizations (id, name, slug, is_active, max_domains, max_users, max_api_tokens, "
            "max_alert_rules, max_inbound_addresses, report_retention_days, smtp_rate_limit_per_hour, "
            "api_rate_limit_per_hour, digest_enabled, created_at, updated_at) "
            "VALUES ('org-1', 'Muster Farben', 'muster-farben', 1, 10, 5, 5, 20, 20, 365, 200, 1000, 1, "
            "'2026-05-28', '2026-05-28')"
        ))
        for ip, classification in (("192.0.2.1", "trusted"), ("192.0.2.2", "unknown")):
            conn.execute(text(
                "INSERT INTO source_ips (id, organization_id, ip_address, total_messages, pass_count, fail_count, "
                "classification, created_at, updated_at) "
                f"VALUES ('{ip}', 'org-1', '{ip}', 1, 1, 0, '{classification}', '2026-05-28', '2026-05-28')"
            ))
    run_migrations(file_engine)
    with file_engine.connect() as conn:
        rows = dict(conn.execute(text("SELECT ip_address, classification_source FROM source_ips")).all())
    assert rows == {"192.0.2.1": "manual", "192.0.2.2": None}
