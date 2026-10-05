import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_client_ip, get_current_org, get_current_org_admin, get_current_user
from app.models import Organization, OrganizationMembership, User
from app.services.audit import log_action
from app.services.auth import create_user, get_user_role_in_org
from app.services.passwords import password_problem
from app.templates_config import templates

router = APIRouter(prefix="/users", tags=["users"])

# Roles an organisation administrator can hand out; operators are set up separately
INVITABLE_ROLES = ("org_admin", "manager", "analyst", "read_only")
# Dots only between domain labels: overlapping character classes made long input backtrack quadratically
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")


@router.get("", response_class=HTMLResponse)
def user_list(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    memberships = (
        db.query(OrganizationMembership)
        .filter_by(organization_id=org.id)
        .order_by(OrganizationMembership.is_active.desc(), OrganizationMembership.created_at)
        .all()
    )
    can_manage = user.is_superadmin or get_user_role_in_org(db, user.id, org.id) == "org_admin"
    return templates.TemplateResponse(request, "users/index.html", {
        "user": user, "org": org, "memberships": memberships, "can_manage": can_manage,
        "page_title": "Benutzer",
    })


def _invite_form(request: Request, user: User, org: Organization, values: dict | None = None,
                 error: str | None = None, error_field: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(request, "users/invite.html", {
        "user": user, "org": org, "roles": INVITABLE_ROLES, "values": values or {},
        "error": error, "error_field": error_field, "page_title": "Benutzer einladen",
    }, status_code=status_code)


@router.get("/invite", response_class=HTMLResponse)
def invite_form(
    request: Request,
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    return _invite_form(request, user, org)


@router.post("/invite")
def invite_user(
    request: Request,
    email: str = Form(""),
    full_name: str = Form(""),
    password: str = Form(""),
    role: str = Form("analyst"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    values = {"email": email, "full_name": full_name, "role": role}
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        return _invite_form(request, user, org, values, "Die E-Mail-Adresse ist unvollständig. Sie braucht die "
                            "Form name@example.com.", "email", 400)
    if role not in INVITABLE_ROLES:
        return _invite_form(request, user, org, values, "Wähle eine Rolle aus der Liste.", "role", 400)
    active = db.query(OrganizationMembership).filter_by(organization_id=org.id, is_active=True).count()
    if active >= org.max_users:
        return _invite_form(request, user, org, values, f"Diese Organisation darf höchstens {org.max_users} "
                            "Benutzer haben. Entferne erst jemanden oder bitte den Betreiber, die Grenze zu erhöhen.",
                            None, 400)

    invitee = db.query(User).filter_by(email=email).first()
    if not invitee:
        problem = password_problem(password)
        if problem:
            return _invite_form(request, user, org, values, problem, "password", 400)
        invitee = create_user(db, email, password, full_name=full_name.strip() or None)

    membership = db.query(OrganizationMembership).filter_by(user_id=invitee.id, organization_id=org.id).first()
    if membership:
        membership.role = role
        membership.is_active = True
    else:
        db.add(OrganizationMembership(user_id=invitee.id, organization_id=org.id, role=role, invited_by=user.id))

    log_action(
        db, "user.invite", org_id=org.id, user_id=user.id,
        resource_type="user", resource_id=invitee.id,
        new_value={"email": email, "role": role},
        ip_address=get_client_ip(request),
    )
    db.commit()
    return RedirectResponse(url="/users", status_code=303)


@router.post("/{membership_id}/remove")
def remove_member(
    membership_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    membership = db.query(OrganizationMembership).filter_by(id=membership_id, organization_id=org.id).first()
    if not membership:
        raise HTTPException(status_code=404)
    if membership.user_id == user.id:
        raise HTTPException(status_code=400, detail="Du kannst dich nicht selbst entfernen. Bitte einen anderen "
                            "Administrator darum.")
    membership.is_active = False
    log_action(db, "user.remove", org_id=org.id, user_id=user.id, resource_type="user",
               resource_id=membership.user_id, ip_address=get_client_ip(request))
    db.commit()
    return RedirectResponse(url="/users", status_code=303)
