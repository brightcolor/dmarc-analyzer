"""Builders for test data and a local SMTP server that collects mails."""
import json
import socket
from datetime import UTC, datetime, timedelta
from email import message_from_bytes
from email.policy import default as default_policy

import pytest
from aiosmtpd.controller import Controller
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import get_db
from app.main import app
from app.models import (
    AlertRule,
    Base,
    DmarcRecord,
    DmarcReport,
    Domain,
    NotificationChannel,
    Organization,
    SourceIp,
)

# A Monday, 10:00 UTC (12:00 in Berlin)
NOW = datetime(2026, 9, 28, 10, 0, tzinfo=UTC)


@pytest.fixture
def session():
    """Own in-memory database per test; jobs that commit leave nothing behind."""
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    db = factory()
    db.info["factory"] = factory
    yield db
    db.close()
    engine.dispose()


def make_org(db, name: str = "Muster Farben", slug: str = "muster-farben", created_at: datetime | None = None):
    org = Organization(name=name, slug=slug, is_active=True)
    if created_at:
        org.created_at = created_at
    db.add(org)
    db.flush()
    return org


def make_domain(db, org, name: str = "example.org", policy: str | None = None):
    domain = Domain(organization_id=org.id, name=name, is_active=True, dmarc_policy=policy)
    db.add(domain)
    db.flush()
    return domain


def add_report(db, org, domain, rows, created_at: datetime = NOW, report_format: str = "rfc7489",
               reporting_org: str = "Beispiel-Empfänger", report_id: str | None = None):
    """rows: (ip, count, dmarc_pass, spf_aligned, dkim_aligned)"""
    report = DmarcReport(
        organization_id=org.id, domain_id=domain.id if domain else None,
        report_id=report_id or f"r-{created_at.timestamp()}-{len(rows)}-{id(rows)}",
        reporting_org=reporting_org, report_format=report_format,
        total_messages=sum(r[1] for r in rows), created_at=created_at,
    )
    db.add(report)
    db.flush()
    for ip, count, passed, spf, dkim in rows:
        db.add(DmarcRecord(
            report_id=report.id, organization_id=org.id, domain_id=domain.id if domain else None,
            source_ip=ip, count=count, dmarc_pass=passed, spf_aligned=spf, dkim_aligned=dkim,
            disposition="none", created_at=created_at,
        ))
    db.flush()
    return report


def add_source(db, org, ip: str, total: int, failed: int = 0, first_seen: datetime = NOW,
               classification: str = "unknown", reverse_dns: str | None = None):
    source = SourceIp(
        organization_id=org.id, ip_address=ip, first_seen_at=first_seen, last_seen_at=first_seen,
        total_messages=total, pass_count=total - failed, fail_count=failed,
        pass_rate=round((total - failed) / total * 100, 2) if total else None,
        classification=classification, reverse_dns=reverse_dns,
    )
    db.add(source)
    db.flush()
    return source


def make_rule(db, org, alert_type: str, threshold: float | None = None, window: int = 60, cooldown: int = 60,
              domain=None, channels=(), min_messages: int = 1, severity: str = "warning"):
    rule = AlertRule(
        organization_id=org.id, domain_id=domain.id if domain else None, name=f"Regel {alert_type}",
        alert_type=alert_type, threshold=threshold, time_window_minutes=window, cooldown_minutes=cooldown,
        min_message_count=min_messages, severity=severity, is_active=True,
        notification_channel_ids=json.dumps([c.id for c in channels]),
    )
    db.add(rule)
    db.flush()
    return rule


def make_channel(db, org, channel_type: str = "webhook", config: dict | None = None, name: str = "Technik",
                 active: bool = True):
    channel = NotificationChannel(
        organization_id=org.id, name=name, channel_type=channel_type,
        config=json.dumps(config or {"url": "https://hooks.example.test/dmarc"}), is_active=active,
    )
    db.add(channel)
    db.flush()
    return channel


def aware(value: datetime | None) -> datetime | None:
    """SQLite returns times without zone; the application stores UTC."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def minutes_ago(minutes: int) -> datetime:
    return NOW - timedelta(minutes=minutes)


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine)
    engine.dispose()


@pytest.fixture
def web(session_factory):
    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.setup_done = False
    with TestClient(app, follow_redirects=False) as client:
        client.app.state.setup_done = False
        yield client
    app.dependency_overrides.clear()
    app.state.setup_done = False


# Local SMTP server --------------------------------------------------------------------

class _Collector:
    def __init__(self) -> None:
        self.envelopes = []

    async def handle_DATA(self, server, session, envelope):  # noqa: N802 - aiosmtpd hook name
        self.envelopes.append(envelope)
        return "250 OK"

    @property
    def messages(self):
        return [message_from_bytes(e.content, policy=default_policy) for e in self.envelopes]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def smtp_server(monkeypatch):
    collector = _Collector()
    port = _free_port()
    controller = Controller(collector, hostname="127.0.0.1", port=port)
    controller.start()
    monkeypatch.setattr(settings, "MAIL_SMTP_HOST", "127.0.0.1")
    monkeypatch.setattr(settings, "MAIL_SMTP_PORT", port)
    monkeypatch.setattr(settings, "MAIL_SMTP_SECURITY", "none")
    monkeypatch.setattr(settings, "MAIL_SMTP_USER", "")
    monkeypatch.setattr(settings, "MAIL_FROM", "DMARC Analyzer <dmarc@example.test>")
    yield collector
    controller.stop()
