from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user_optional, get_client_ip
from app.services.auth import authenticate_user, create_user, get_user_orgs
from app.services.audit import log_action
from app.templates_config import templates

router = APIRouter(prefix="/auth", tags=["auth"])


def _any_users_exist(db: Session) -> bool:
    from app.models import User
    return db.query(User.id).first() is not None


@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, db: Session = Depends(get_db)):
    if _any_users_exist(db):
        return RedirectResponse(url="/auth/login", status_code=302)
    error = request.session.pop("setup_error", None)
    return templates.TemplateResponse("auth/setup.html", {"request": request, "error": error})


@router.post("/setup")
def setup_submit(
    request: Request,
    email: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    org_name: str = Form(...),
    db: Session = Depends(get_db),
):
    if _any_users_exist(db):
        return RedirectResponse(url="/auth/login", status_code=303)

    if password != password_confirm:
        request.session["setup_error"] = "Passwords do not match."
        return RedirectResponse(url="/auth/setup", status_code=303)

    if len(password) < 10:
        request.session["setup_error"] = "Password must be at least 10 characters."
        return RedirectResponse(url="/auth/setup", status_code=303)

    from app.models import Organization, OrganizationMembership
    import re

    slug = re.sub(r"[^a-z0-9]+", "-", org_name.lower().strip()).strip("-")[:80] or "default-org"

    try:
        org = Organization(name=org_name.strip(), slug=slug, is_active=True)
        db.add(org)
        db.flush()

        user = create_user(db, email=email, password=password, full_name=full_name, is_superadmin=True)
        db.add(OrganizationMembership(user_id=user.id, organization_id=org.id, role="org_admin"))

        log_action(db, "setup.initial_admin_created", user_id=user.id,
                   ip_address=get_client_ip(request))
        db.commit()
    except Exception as exc:
        db.rollback()
        request.session["setup_error"] = f"Setup failed: {exc}"
        return RedirectResponse(url="/auth/setup", status_code=303)

    request.session["user_id"] = user.id
    request.session["org_id"] = org.id
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, user=Depends(get_current_user_optional), db: Session = Depends(get_db)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    if not _any_users_exist(db):
        return RedirectResponse(url="/auth/setup", status_code=302)
    error = request.session.pop("login_error", None)
    return templates.TemplateResponse("auth/login.html", {
        "request": request,
        "error": error,
    })


@router.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, email, password)
    if not user:
        request.session["login_error"] = "Invalid email or password."
        return RedirectResponse(url="/auth/login", status_code=303)

    request.session["user_id"] = user.id

    # Auto-select org if user has exactly one
    orgs = get_user_orgs(db, user.id) if not user.is_superadmin else []
    if orgs and len(orgs) == 1:
        request.session["org_id"] = orgs[0].id

    log_action(
        db,
        "user.login",
        user_id=user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    db.commit()

    next_url = request.query_params.get("next", "/dashboard")
    return RedirectResponse(url=next_url, status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/auth/login", status_code=303)


@router.get("/select-org", response_class=HTMLResponse)
def select_org_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/auth/login", status_code=302)
    from app.services.auth import get_user_by_id
    user = get_user_by_id(db, user_id)
    orgs = get_user_orgs(db, user_id) if user and not user.is_superadmin else []
    if user and user.is_superadmin:
        from app.models import Organization
        orgs = db.query(Organization).filter_by(is_active=True).all()
    return templates.TemplateResponse("auth/select_org.html", {
        "request": request,
        "orgs": orgs,
        "user": user,
    })


@router.post("/select-org")
def select_org(request: Request, org_id: str = Form(...), db: Session = Depends(get_db)):
    from app.models import Organization
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/auth/login", status_code=303)

    from app.services.auth import can_access_org, get_user_by_id
    user = get_user_by_id(db, user_id)
    if not user or not can_access_org(db, user, org_id):
        raise HTTPException(status_code=403)

    request.session["org_id"] = org_id
    return RedirectResponse(url="/dashboard", status_code=303)
