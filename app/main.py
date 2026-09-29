"""
DMARC Analyzer — FastAPI application entry point.
"""
import logging
import mimetypes
import os
import secrets
from contextlib import asynccontextmanager
from http import HTTPStatus
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.version import APP_NAME, VERSION

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Slim container images lack /etc/mime.types; without these, fonts and icons go out as text/plain
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("image/svg+xml", ".svg")

# Methods that change something; they need a form from this application
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Title and next step per status for pages people see
ERROR_TEXT = {
    400: ("Die Anfrage ließ sich nicht bearbeiten", "Prüfe die Eingaben und versuche es erneut."),
    401: ("Anmeldung nötig", "Melde dich an und versuche es danach erneut."),
    403: ("Kein Zugriff", "Dein Konto darf diese Seite nicht öffnen. Frage einen Administrator, wenn du Zugriff "
                          "brauchst."),
    404: ("Seite nicht gefunden", "Diese Adresse gibt es nicht, oder der Eintrag wurde entfernt. Prüfe den Link oder "
                                  "gehe zur Übersicht."),
    405: ("Aktion nicht vorgesehen", "Diese Aktion lässt sich so nicht auslösen. Nutze die Schaltflächen der Seite."),
    413: ("Datei zu groß", "Die Datei überschreitet die erlaubte Größe. Lade eine kleinere Datei hoch."),
    422: ("Eingaben unvollständig", "Ein Pflichtfeld fehlt oder hat das falsche Format. Prüfe das Formular und sende "
                                    "es erneut."),
    429: ("Zu viele Anfragen", "Warte einen Moment und versuche es dann erneut."),
    500: ("Interner Fehler", "Die Anwendung konnte die Anfrage nicht bearbeiten. Versuche es später erneut; bleibt "
                             "der Fehler, wende dich mit der Kennung unten an den Administrator."),
}


def _wants_json(request: Request) -> bool:
    return request.url.path.startswith("/api/") or "application/json" in request.headers.get("accept", "")


def _error_response(request: Request, status_code: int, detail: str | None = None, reference: str | None = None):
    title, hint = ERROR_TEXT.get(status_code, ERROR_TEXT[500 if status_code >= 500 else 400])
    standard_phrase = HTTPStatus(status_code).phrase if status_code in HTTPStatus._value2member_map_ else None
    message = detail if detail and detail != standard_phrase else hint
    if _wants_json(request):
        body = {"detail": message, "status": status_code}
        if reference:
            body["reference"] = reference
        return JSONResponse(body, status_code=status_code)
    from app.templates_config import templates
    return templates.TemplateResponse(request, "errors/error.html", {
        "status_code": status_code, "title": title, "message": message, "reference": reference,
        "page_title": title,
    }, status_code=status_code)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup tasks on application start."""
    settings.upload_dir_path  # noqa: B018
    settings.raw_mail_dir_path  # noqa: B018

    from app.migrate import run_migrations
    run_migrations()

    _create_default_plan()
    _announce_setup()

    from app.scheduler import Scheduler
    scheduler = Scheduler()
    scheduler.start()

    logger.info("%s v%s started", APP_NAME, VERSION)
    yield
    logger.info("%s shutting down", APP_NAME)
    await scheduler.stop()


def _announce_setup() -> None:
    """Log the setup code while no administrator exists."""
    from app.database import SessionLocal
    from app.services.setup import ensure_setup_code, log_setup_hint
    db = SessionLocal()
    try:
        code = ensure_setup_code(db)
        if code:
            log_setup_hint(code)
    finally:
        db.close()


def _create_default_plan() -> None:
    from app.database import SessionLocal
    from app.models import PlanDefinition
    db = SessionLocal()
    try:
        if not db.query(PlanDefinition).filter_by(slug="default").first():
            db.add(PlanDefinition(
                name="Default",
                slug="default",
                max_domains=settings.DEFAULT_PLAN_MAX_DOMAINS,
                max_users=settings.DEFAULT_PLAN_MAX_USERS,
                max_api_tokens=settings.DEFAULT_PLAN_MAX_API_TOKENS,
                max_alert_rules=settings.DEFAULT_PLAN_MAX_ALERT_RULES,
                max_inbound_addresses=settings.DEFAULT_PLAN_MAX_INBOUND_ADDRESSES,
                report_retention_days=settings.DEFAULT_PLAN_REPORT_RETENTION_DAYS,
                smtp_rate_limit_per_hour=settings.DEFAULT_PLAN_SMTP_RATE_LIMIT_PER_HOUR,
                api_rate_limit_per_hour=settings.DEFAULT_PLAN_API_RATE_LIMIT_PER_HOUR,
            ))
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title=APP_NAME,
        version=VERSION,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.setup_done = False

    @app.middleware("http")
    async def setup_gate(request: Request, call_next):
        """While no administrator exists, every page leads to the first-run setup."""
        if not app.state.setup_done:
            from app.database import get_db
            from app.services.setup import admin_exists, setup_path_is_open
            session_source = app.dependency_overrides.get(get_db, get_db)()
            try:
                app.state.setup_done = admin_exists(next(session_source))
            finally:
                session_source.close()
            if not app.state.setup_done and not setup_path_is_open(request.url.path):
                return RedirectResponse(url="/auth/setup", status_code=303)
        return await call_next(request)

    @app.middleware("http")
    async def same_origin_forms(request: Request, call_next):
        """Forms only count when they come from this application (Origin, else Referer)."""
        if request.method in UNSAFE_METHODS and not request.url.path.startswith("/api/"):
            source = request.headers.get("origin") or request.headers.get("referer")
            if source is not None:
                host = urlsplit(source).netloc.lower() if source != "null" else ""
                allowed = settings.csrf_trusted_origins | {request.headers.get("host", "").lower()}
                if host not in allowed:
                    logger.warning("Refused %s %s from foreign origin %r", request.method, request.url.path, source)
                    return _error_response(request, 403, (
                        f"Das Formular kam von einer fremden Seite ({host or 'ohne Absender'}) und wurde deshalb "
                        "abgelehnt. Öffne den DMARC Analyzer direkt über seine Adresse und sende das Formular "
                        "dort erneut. Nutzt ihr eine weitere Adresse, trägt der Betreiber sie in "
                        "CSRF_TRUSTED_ORIGINS ein."
                    ))
        return await call_next(request)

    # Added last, so it runs first and the gate above can rely on it
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        session_cookie=settings.SESSION_COOKIE_NAME,
        max_age=settings.SESSION_MAX_AGE,
        https_only=settings.SESSION_HTTPS_ONLY,
        same_site=settings.SESSION_SAME_SITE,
    )

    static_path = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(static_path):
        app.mount("/static", StaticFiles(directory=static_path), name="static")

    from app.routers import (
        alerts,
        api_tokens,
        auth,
        dashboard,
        domains,
        failure_reports,
        help,
        imports,
        organizations,
        reports,
        senders,
        smtp_admin,
        source_ips,
        upload,
        users,
    )
    from app.routers.api import v1 as api_v1

    app.include_router(auth.router)
    app.include_router(dashboard.router)
    app.include_router(organizations.router)
    app.include_router(users.router)
    app.include_router(domains.router)
    app.include_router(reports.router)
    app.include_router(failure_reports.router)
    app.include_router(upload.router)
    app.include_router(imports.router)
    app.include_router(smtp_admin.router)
    app.include_router(senders.router)
    app.include_router(source_ips.router)
    app.include_router(alerts.router)
    app.include_router(api_tokens.router)
    app.include_router(help.router)
    app.include_router(api_v1.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if 300 <= exc.status_code < 400 and exc.headers and "Location" in exc.headers:
            return RedirectResponse(url=exc.headers["Location"], status_code=exc.status_code)
        detail = exc.detail if isinstance(exc.detail, str) else None
        response = _error_response(request, exc.status_code, detail)
        for key, value in (exc.headers or {}).items():
            response.headers.setdefault(key, value)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        fields = sorted({str(err["loc"][-1]) for err in exc.errors() if err.get("loc")})
        detail = None
        if fields:
            detail = ("Diese Angaben fehlen oder haben das falsche Format: " + ", ".join(fields)
                      + ". Prüfe das Formular und sende es erneut.")
        return _error_response(request, 422, detail)

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        reference = secrets.token_hex(4)
        logger.exception("Unexpected error %s on %s %s", reference, request.method, request.url.path)
        return _error_response(request, 500, reference=reference)

    return app


app = create_app()
