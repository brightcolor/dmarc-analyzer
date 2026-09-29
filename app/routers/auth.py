import re
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_client_ip, get_current_user_optional
from app.services.audit import log_action
from app.services.auth import authenticate_user, create_user, get_user_orgs
from app.services.passwords import password_problem
from app.services.setup import admin_exists, consume_setup_code
from app.templates_config import templates

router = APIRouter(prefix="/auth", tags=["auth"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SETUP_CODE_HINT = ("Du findest ihn im Serverlog beim Start der Anwendung oder mit dem Befehl "
                   "docker compose exec web python -m app.setup_code.")


def _safe_next(target: str | None) -> str:
    """Only relative paths inside this application; everything else goes to the dashboard."""
    if not target:
        return "/dashboard"
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return "/dashboard"
    return target


def _setup_form(request: Request, values: dict | None = None, error: str | None = None,
                error_field: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(request, "auth/setup.html", {
        "values": values or {}, "error": error, "error_field": error_field, "page_title": "Ersteinrichtung",
    }, status_code=status_code)


@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, db: Session = Depends(get_db)):
    if admin_exists(db):
        raise HTTPException(status_code=404)
    return _setup_form(request)


@router.post("/setup")
def setup_submit(
    request: Request,
    setup_code: str = Form(""),
    email: str = Form(""),
    full_name: str = Form(""),
    password: str = Form(""),
    password_confirm: str = Form(""),
    org_name: str = Form(""),
    db: Session = Depends(get_db),
):
    if admin_exists(db):
        raise HTTPException(status_code=404)

    values = {"email": email, "full_name": full_name, "org_name": org_name, "setup_code": setup_code}
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        return _setup_form(request, values, "Die E-Mail-Adresse ist unvollständig. Sie braucht die Form "
                           "name@example.com.", "email", 400)
    if not org_name.strip():
        return _setup_form(request, values, "Gib einen Namen für die erste Organisation an, etwa deinen "
                           "Firmennamen.", "org_name", 400)
    problem = password_problem(password, password_confirm)
    if problem:
        return _setup_form(request, values, problem, "password", 400)

    from app.models import Organization, OrganizationMembership, User
    from app.services.inbound_address import create_org_address

    if db.query(User.id).filter_by(email=email).first():
        return _setup_form(request, values, "Zu dieser E-Mail-Adresse gibt es schon ein Konto ohne "
                           "Administratorrechte. Nimm eine andere Adresse.", "email", 400)
    if not consume_setup_code(db, setup_code):
        return _setup_form(request, values, "Der Einrichtungscode stimmt nicht. " + SETUP_CODE_HINT,
                           "setup_code", 400)

    folded = org_name.lower().strip().translate(str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss"}))
    base_slug = re.sub(r"[^a-z0-9]+", "-", folded).strip("-")[:70] or "organisation"
    slug, suffix = base_slug, 1
    while db.query(Organization.id).filter_by(slug=slug).first():
        suffix += 1
        slug = f"{base_slug}-{suffix}"
    org = Organization(name=org_name.strip(), slug=slug, is_active=True)
    db.add(org)
    db.flush()
    user = create_user(db, email=email, password=password, full_name=full_name.strip() or None, is_superadmin=True)
    org.owner_id = user.id
    db.add(OrganizationMembership(user_id=user.id, organization_id=org.id, role="org_admin"))
    create_org_address(db, org)
    log_action(db, "setup.initial_admin_created", org_id=org.id, user_id=user.id,
               resource_type="user", resource_id=user.id, new_value={"email": email},
               ip_address=get_client_ip(request))
    db.commit()

    request.app.state.setup_done = True
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["org_id"] = org.id
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, user=Depends(get_current_user_optional)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    error = request.session.pop("login_error", None)
    return templates.TemplateResponse(request, "auth/login.html", {
        "error": error, "email": request.session.pop("login_email", ""),
        "next": _safe_next(request.query_params.get("next")), "page_title": "Anmelden",
    })


@router.post("/login")
def login(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    next: str = Form("/dashboard"),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, email, password)
    if not user:
        request.session["login_error"] = ("E-Mail-Adresse oder Passwort stimmen nicht. Prüfe die Schreibweise; "
                                          "beim Passwort zählt Groß- und Kleinschreibung.")
        request.session["login_email"] = email
        return RedirectResponse(url="/auth/login", status_code=303)

    request.session.clear()
    request.session["user_id"] = user.id

    # Pick the organisation automatically when there is exactly one
    orgs = get_user_orgs(db, user.id) if not user.is_superadmin else []
    if len(orgs) == 1:
        request.session["org_id"] = orgs[0].id

    log_action(db, "user.login", user_id=user.id, ip_address=get_client_ip(request),
               user_agent=request.headers.get("User-Agent"))
    db.commit()
    return RedirectResponse(url=_safe_next(next), status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/auth/login", status_code=303)


@router.get("/select-org")
def select_org_page():
    return RedirectResponse(url="/organizations/select", status_code=302)
