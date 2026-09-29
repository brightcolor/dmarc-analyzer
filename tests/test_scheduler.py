"""Scheduler turns and the retention job."""
from datetime import timedelta
from pathlib import Path

import pytest

from app import scheduler
from app.config import settings
from app.models import (
    AlertEvent,
    DmarcAuthResult,
    DmarcRecord,
    DmarcReport,
    ImportJob,
    SchedulerRun,
    SmtpInboundMessage,
    SmtpInboundRejection,
)
from app.scheduler import Job, claim, run_job
from app.services.retention import run_retention
from tests.helpers import NOW, add_report, make_domain, make_org


class TestClaim:
    def test_one_turn_per_interval(self, session):
        assert claim(session, "alerts", 300, NOW) is True
        assert claim(session, "alerts", 300, NOW + timedelta(seconds=10)) is False
        assert claim(session, "alerts", 300, NOW + timedelta(seconds=300)) is True

    def test_jobs_have_their_own_turns(self, session):
        assert claim(session, "alerts", 300, NOW) is True
        assert claim(session, "digest", 900, NOW) is True

    def test_two_sessions_compete(self, session):
        other = session.info["factory"]()
        try:
            assert claim(session, "alerts", 300, NOW) is True
            assert claim(other, "alerts", 300, NOW) is False
        finally:
            other.close()


@pytest.fixture
def job_session(session, monkeypatch):
    monkeypatch.setattr(scheduler, "SessionLocal", session.info["factory"])
    return session


class TestRunJob:
    def test_success_is_recorded(self, job_session):
        calls = []
        job = Job("probe", "Probe", lambda: 60, lambda db, now: calls.append(now))
        assert run_job(job, NOW) is True
        assert run_job(job, NOW + timedelta(seconds=30)) is False
        assert calls == [NOW]
        run = job_session.get(SchedulerRun, "probe")
        job_session.refresh(run)
        assert run.last_status == "ok"
        assert run.last_error is None
        assert run.last_finished_at is not None

    def test_failure_is_recorded_and_rolled_back(self, job_session):
        def broken(db, now):
            make_org(db, "Halbfertig", "halbfertig")
            raise RuntimeError("Datenbank nicht erreichbar")

        assert run_job(Job("probe", "Probe", lambda: 60, broken), NOW) is True
        run = job_session.get(SchedulerRun, "probe")
        job_session.refresh(run)
        assert run.last_status == "failed"
        assert run.last_error == "RuntimeError: Datenbank nicht erreichbar"
        from app.models import Organization
        assert job_session.query(Organization).count() == 0

    def test_interval_comes_from_the_settings(self, job_session, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_EVAL_INTERVAL_SECONDS", 120)
        alerts = next(job for job in scheduler.JOBS if job.name == "alerts")
        assert run_job(alerts, NOW) is True
        assert run_job(alerts, NOW + timedelta(seconds=119)) is False
        assert run_job(alerts, NOW + timedelta(seconds=120)) is True

    def test_all_jobs_run_on_an_empty_database(self, job_session):
        names = ["senders", "alerts", "notifications", "retention", "digest"]
        assert scheduler.run_due_jobs(NOW) == names
        runs = {run.name: run.last_status for run in job_session.query(SchedulerRun)}
        assert runs == dict.fromkeys(names, "ok")


@pytest.fixture
def storage(tmp_path, monkeypatch):
    uploads = tmp_path / "uploads"
    raw = tmp_path / "raw"
    uploads.mkdir()
    raw.mkdir()
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(uploads))
    monkeypatch.setattr(settings, "RAW_MAIL_DIR", str(raw))
    return uploads, raw


class TestRetention:
    def test_old_reports_go_with_their_records(self, session, storage):
        org = make_org(session)
        org.report_retention_days = 30
        domain = make_domain(session, org)
        old = add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)],
                         created_at=NOW - timedelta(days=31), report_id="alt")
        record = session.query(DmarcRecord).filter_by(report_id=old.id).one()
        session.add(DmarcAuthResult(record_id=record.id, auth_type="spf", result="pass"))
        session.add(AlertEvent(organization_id=org.id, alert_type="import_failed", severity="info", title="x",
                               report_id=old.id, status="open"))
        add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)],
                   created_at=NOW - timedelta(days=29), report_id="neu")
        session.flush()

        result = run_retention(session, NOW)

        assert result.reports == 1
        assert [r.report_id for r in session.query(DmarcReport)] == ["neu"]
        assert session.query(DmarcRecord).count() == 1
        assert session.query(DmarcAuthResult).count() == 0
        assert session.query(AlertEvent).one().report_id is None

    def test_retention_follows_the_organisation(self, session, storage):
        org = make_org(session)
        org.report_retention_days = 400
        domain = make_domain(session, org)
        add_report(session, org, domain, [("192.0.2.1", 5, True, True, True)], created_at=NOW - timedelta(days=380))
        assert run_retention(session, NOW).reports == 0

    def test_batch_size(self, session, storage, monkeypatch):
        monkeypatch.setattr(settings, "RETENTION_BATCH_SIZE", 2)
        org = make_org(session)
        org.report_retention_days = 1
        domain = make_domain(session, org)
        for index in range(3):
            add_report(session, org, domain, [("192.0.2.1", 1, True, True, True)],
                       created_at=NOW - timedelta(days=5, minutes=index), report_id=f"r{index}")
        assert run_retention(session, NOW).reports == 2
        assert run_retention(session, NOW).reports == 1

    def test_import_jobs_and_files(self, session, storage):
        uploads, _ = storage
        org = make_org(session)
        org.report_retention_days = 30
        stored = uploads / org.id / "bericht.xml"
        stored.parent.mkdir()
        stored.write_text("<feedback/>")
        outside = uploads.parent / "fremd.xml"
        outside.write_text("bleibt")
        session.add(ImportJob(organization_id=org.id, status="completed", file_path=str(stored),
                              created_at=NOW - timedelta(days=40)))
        session.add(ImportJob(organization_id=org.id, status="failed", file_path=str(outside),
                              created_at=NOW - timedelta(days=40)))
        session.flush()

        result = run_retention(session, NOW)

        assert result.import_jobs == 2
        assert result.files == 1
        assert not stored.exists()
        assert outside.exists()

    def test_raw_mails_and_rejections(self, session, storage, monkeypatch):
        _, raw = storage
        monkeypatch.setattr(settings, "SMTP_INBOUND_RAW_RETENTION_DAYS", 3)
        monkeypatch.setattr(settings, "SMTP_REJECTION_RETENTION_DAYS", 10)
        org = make_org(session)
        old_file = raw / "alt.eml"
        old_file.write_bytes(b"From: a")
        new_file = raw / "neu.eml"
        new_file.write_bytes(b"From: b")
        for name, path, age in (("alt", old_file, 4), ("neu", new_file, 2)):
            session.add(SmtpInboundMessage(organization_id=org.id, envelope_recipient=f"{name}@example.test",
                                           raw_path=str(path), received_at=NOW - timedelta(days=age)))
        session.add(SmtpInboundRejection(rejection_code="550", rejection_reason="unbekannt",
                                         created_at=NOW - timedelta(days=11)))
        session.add(SmtpInboundRejection(rejection_code="550", rejection_reason="unbekannt",
                                         created_at=NOW - timedelta(days=9)))
        session.flush()

        result = run_retention(session, NOW)

        assert result.raw_mails == 1
        assert result.rejections == 1
        assert not old_file.exists()
        assert new_file.exists()
        paths = {m.envelope_recipient: m.raw_path for m in session.query(SmtpInboundMessage)}
        assert paths == {"alt@example.test": None, "neu@example.test": str(new_file)}

    def test_old_messages_leave_with_their_raw_file(self, session, storage):
        _, raw = storage
        org = make_org(session)
        org.report_retention_days = 30
        path = Path(raw) / "sehr-alt.eml"
        path.write_bytes(b"From: c")
        session.add(SmtpInboundMessage(organization_id=org.id, envelope_recipient="c@example.test",
                                       raw_path=str(path), received_at=NOW - timedelta(days=31)))
        session.flush()
        result = run_retention(session, NOW)
        assert result.messages == 1
        assert not path.exists()
        assert session.query(SmtpInboundMessage).count() == 0
