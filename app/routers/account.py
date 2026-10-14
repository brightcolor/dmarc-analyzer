from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_client_ip, get_current_user
from app.models import Organization, User
from app.services.account import AccountError, change_password, change_profile
from app.services.audit import log_action
from app.templates_config import flash, templates

router = APIRouter(prefix="/account", tags=["account"])

PROFILE_FIELDS = ("full_name", "email")


def _org(request: Request, db: Session) -> Organization | None:
    org_id = request.session.get("org_id")
    return db.query(Organization).filter_by(id=org_id, is_active=True).first() if org_id else None


def _page(request: Request, db: Session, user: User, section: str | None = None, error: AccountError | None = None,
          values: dict | None = None, status_code: int = 200):
    return templates.TemplateResponse(request, "account/index.html", {
        "user": user, "org": _org(request, db), "page_title": "Konto",
        "error_section": section, "error": error,
        "values": values or {"full_name": user.full_name or "", "email": user.email},
    }, status_code=status_code)


@router.get("", response_class=HTMLResponse)
def account_page(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _page(request, db, user)


@router.post("/profile")
def save_profile(
    request: Request,
    full_name: str = Form(""),
    email: str = Form(""),
    current_password: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = get_client_ip(request)
    try:
        result = change_profile(db, user, full_name[:1000], email[:1000], current_password, ip)
    except AccountError as exc:
        db.rollback()
        return _page(request, db, user, "profile", exc,
                     {"full_name": full_name[:300], "email": email[:300]}, 400)
    if result.email_changed:
        log_action(db, "user.email_change", user_id=user.id, resource_type="user", resource_id=user.id,
                   old_value={"email": result.old_email}, new_value={"email": user.email}, ip_address=ip,
                   user_agent=request.headers.get("User-Agent"))
    if result.name_changed:
        log_action(db, "user.name_change", user_id=user.id, resource_type="user", resource_id=user.id,
                   ip_address=ip, user_agent=request.headers.get("User-Agent"))
    db.commit()
    if result.email_changed:
        flash(request, "ok", "E-Mail-Adresse geändert", f"Du meldest dich ab jetzt mit {user.email} an.")
    elif result.name_changed:
        flash(request, "ok", "Name gespeichert")
    else:
        flash(request, "ok", "Nichts geändert", "Die Angaben waren schon so gespeichert.")
    return RedirectResponse(url="/account", status_code=303)


@router.post("/password")
def save_password(
    request: Request,
    current_password: str = Form(""),
    password: str = Form(""),
    password_confirm: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = get_client_ip(request)
    try:
        stamp = change_password(db, user, current_password[:1000], password[:1000], password_confirm[:1000], ip)
    except AccountError as exc:
        db.rollback()
        return _page(request, db, user, "password", exc, None, 400)
    log_action(db, "user.password_change", user_id=user.id, resource_type="user", resource_id=user.id,
               ip_address=ip, user_agent=request.headers.get("User-Agent"))
    db.commit()
    # This session goes on; every older one ends
    request.session["iat"] = stamp
    flash(request, "ok", "Passwort geändert",
          "Alle anderen angemeldeten Geräte sind abgemeldet. Melde dich dort mit dem neuen Passwort an.")
    return RedirectResponse(url="/account", status_code=303)
