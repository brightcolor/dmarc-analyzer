"""
DMARC Analyzer — FastAPI application entry point.
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.database import get_db

from app.config import settings
from app.version import APP_NAME, VERSION

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup tasks on application start."""
    # Ensure upload directories exist
    settings.upload_dir_path
    settings.raw_mail_dir_path

    # Create DB tables and run migrations
    from app.database import engine
    from app.models import Base  # noqa: F401 — registers all models
    Base.metadata.create_all(bind=engine)

    # Create initial admin if configured
    _create_initial_admin()

    # Create default plan if missing
    _create_default_plan()

    logger.info("%s v%s started", APP_NAME, VERSION)
    yield
    logger.info("%s shutting down", APP_NAME)


def _create_initial_admin() -> None:
    if not settings.INITIAL_ADMIN_EMAIL or not settings.INITIAL_ADMIN_PASSWORD:
        return
    from app.database import SessionLocal
    from app.models import User
    from app.services.auth import create_user
    db = SessionLocal()
    try:
        existing = db.query(User).filter_by(email=settings.INITIAL_ADMIN_EMAIL).first()
        if not existing:
            create_user(
                db,
                email=settings.INITIAL_ADMIN_EMAIL,
                password=settings.INITIAL_ADMIN_PASSWORD,
                full_name="Super Admin",
                is_superadmin=True,
            )
            db.commit()
            logger.info("Initial admin created: %s", settings.INITIAL_ADMIN_EMAIL)
    except Exception as exc:
        logger.warning("Could not create initial admin: %s", exc)
        db.rollback()
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
                max_domains=50,
                max_users=20,
                max_api_tokens=10,
                max_alert_rules=50,
                max_inbound_addresses=50,
                report_retention_days=365,
                smtp_rate_limit_per_hour=500,
                api_rate_limit_per_hour=2000,
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

    # Session middleware (must be first)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        session_cookie=settings.SESSION_COOKIE_NAME,
        max_age=settings.SESSION_MAX_AGE,
        https_only=settings.SESSION_HTTPS_ONLY,
        same_site=settings.SESSION_SAME_SITE,
    )

    # Static files
    static_path = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(static_path):
        app.mount("/static", StaticFiles(directory=static_path), name="static")

    # Register routers
    from app.routers import (
        alerts, api_tokens, auth, dashboard, domains,
        imports, organizations, reports, smtp_admin, source_ips, upload, users,
    )
    from app.routers.api import v1 as api_v1

    app.include_router(auth.router)
    app.include_router(dashboard.router)
    app.include_router(organizations.router)
    app.include_router(users.router)
    app.include_router(domains.router)
    app.include_router(reports.router)
    app.include_router(upload.router)
    app.include_router(imports.router)
    app.include_router(smtp_admin.router)
    app.include_router(source_ips.router)
    app.include_router(alerts.router)
    app.include_router(api_tokens.router)
    app.include_router(api_v1.router)

    # Root redirect — send to setup when no users exist yet
    @app.get("/", include_in_schema=False)
    def root(db: Session = Depends(get_db)):
        from app.models import User
        if not db.query(User.id).first():
            return RedirectResponse(url="/auth/setup", status_code=302)
        return RedirectResponse(url="/dashboard", status_code=302)

    # Exception handlers
    @app.exception_handler(403)
    async def forbidden_handler(request: Request, exc):
        from app.templates_config import templates
        return templates.TemplateResponse(
            "errors/403.html",
            {"request": request},
            status_code=403,
        )

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        from app.templates_config import templates
        return templates.TemplateResponse(
            "errors/404.html",
            {"request": request},
            status_code=404,
        )

    return app


app = create_app()
