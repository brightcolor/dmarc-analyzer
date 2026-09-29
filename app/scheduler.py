"""
Scheduler in the web process: checks alert rules, sends notifications, cleans up and sends the weekly digest.

The loop runs as an asyncio task in the lifespan of the web app; each job runs in a worker thread.
A job claims its turn through its row in scheduler_runs: the UPDATE succeeds for one process only,
so several web workers or containers never run the same job twice in one interval.
"""
import asyncio
import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import or_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models import Organization, SchedulerRun
from app.security import utcnow

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Job:
    name: str
    label: str
    interval: Callable[[], int]  # seconds, read from the settings on every tick
    run: Callable[[Session, datetime], object]


def _run_alerts(db: Session, now: datetime) -> int:
    from app.services.alert_service import evaluate_rules_for_org

    fired = 0
    for (org_id,) in db.query(Organization.id).filter_by(is_active=True).all():
        fired += len(evaluate_rules_for_org(db, org_id, now))
        db.commit()
    return fired


def _run_notifications(db: Session, now: datetime) -> dict:
    from app.services.notification import dispatch_pending

    return dispatch_pending(db, now)


def _run_retention(db: Session, now: datetime):
    from app.services.retention import run_retention

    return run_retention(db, now)


def _run_digest(db: Session, now: datetime) -> int:
    from app.services.digest import send_due_digests

    return send_due_digests(db, now)


JOBS = (
    Job("alerts", "Alarmregeln prüfen", lambda: settings.ALERT_EVAL_INTERVAL_SECONDS, _run_alerts),
    Job("notifications", "Benachrichtigungen senden", lambda: settings.NOTIFICATION_DISPATCH_INTERVAL_SECONDS,
        _run_notifications),
    Job("retention", "Alte Daten löschen", lambda: settings.RETENTION_INTERVAL_SECONDS, _run_retention),
    Job("digest", "Wochenberichte senden", lambda: settings.DIGEST_CHECK_INTERVAL_SECONDS, _run_digest),
)
JOB_LABELS = {job.name: job.label for job in JOBS}


def claim(db: Session, name: str, interval_seconds: int, now: datetime) -> bool:
    """Take the turn for a job when its interval has passed; False when another process has it."""
    if db.get(SchedulerRun, name) is None:
        db.add(SchedulerRun(name=name))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
    cutoff = now - timedelta(seconds=interval_seconds)
    result = db.execute(
        update(SchedulerRun)
        .where(SchedulerRun.name == name)
        .where(or_(SchedulerRun.last_started_at.is_(None), SchedulerRun.last_started_at <= cutoff))
        .values(last_started_at=now, last_status="running")
        .execution_options(synchronize_session=False)
    )
    db.commit()
    return result.rowcount == 1


def run_job(job: Job, now: datetime | None = None) -> bool:
    """Run one job if it is due. Returns True when it ran."""
    now = now or utcnow()
    db = SessionLocal()
    try:
        if not claim(db, job.name, job.interval(), now):
            return False
        status, error = "ok", None
        try:
            outcome = job.run(db, now)
            db.commit()
            logger.debug("Job %s finished: %s", job.name, outcome)
        except Exception as exc:
            db.rollback()
            logger.exception("Job %s failed", job.name)
            status, error = "failed", f"{exc.__class__.__name__}: {exc}"[:2000]
        db.execute(
            update(SchedulerRun)
            .where(SchedulerRun.name == job.name)
            .values(last_finished_at=utcnow(), last_status=status, last_error=error)
            .execution_options(synchronize_session=False)
        )
        db.commit()
        return True
    finally:
        db.close()


def run_due_jobs(now: datetime | None = None) -> list[str]:
    """Run every due job once; returns the names that ran."""
    return [job.name for job in JOBS if run_job(job, now)]


async def scheduler_loop(stop: asyncio.Event) -> None:
    logger.info("Scheduler started, tick every %d seconds", settings.SCHEDULER_TICK_SECONDS)
    while not stop.is_set():
        for job in JOBS:
            if stop.is_set():
                break
            try:
                await asyncio.to_thread(run_job, job)
            except Exception:
                logger.exception("Scheduler could not run job %s", job.name)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=settings.SCHEDULER_TICK_SECONDS)
    logger.info("Scheduler stopped")


class Scheduler:
    """Start and stop the loop from the lifespan of the app."""

    def __init__(self) -> None:
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if settings.SCHEDULER_ENABLED and self._task is None:
            self._task = asyncio.create_task(scheduler_loop(self._stop), name="scheduler")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=settings.SCHEDULER_TICK_SECONDS)
        except TimeoutError:
            self._task.cancel()
        self._task = None
