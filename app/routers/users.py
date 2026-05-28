from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, get_current_org, get_client_ip
from app.models import Organization, OrganizationMembership, User
from app.services.audit import log_action
from app.services.auth import ROLES, create_user, get_user_role_in_org
from app.templates_config import templates

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_class=HTMLResponse)
def user_list(
    request: Request,
    page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    memberships = (
        db.query(OrganizationMembership)
        .filter_by(organization_id=org.id)
        .all()
    )
    return templates.TemplateResponse("users/index.html", {
        "request": request, "user": user, "org": org,
        "memberships": memberships, "page_title": "Users",
    })


@router.get("/invite", response_class=HTMLResponse)
def invite_form(
    request: Request,
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    role = get_user_role_in_org(None, user.id, org.id) if not user.is_superadmin else "super_admin"
    return templates.TemplateResponse("users/invite.html", {
        "request": request, "user": user, "org": org,
        "roles": ROLES, "page_title": "Invite User",
    })


@router.post("/invite")
def invite_user(
    request: Request,
    email: str = Form(...),
    full_name: str = Form(""),
    password: str = Form(...),
    role: str = Form("analyst"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    if role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")

    # Check member count
    count = db.query(OrganizationMembership).filter_by(organization_id=org.id, is_active=True).count()
    if count >= org.max_users:
        raise HTTPException(status_code=400, detail="User limit reached")

    existing = db.query(User).filter_by(email=email.lower().strip()).first()
    if not existing:
        existing = create_user(db, email, password, full_name=full_name or None)

    # Check not already member
    existing_membership = db.query(OrganizationMembership).filter_by(
        user_id=existing.id, organization_id=org.id
    ).first()
    if existing_membership:
        existing_membership.role = role
        existing_membership.is_active = True
    else:
        db.add(OrganizationMembership(
            user_id=existing.id,
            organization_id=org.id,
            role=role,
            invited_by=user.id,
        ))

    log_action(
        db, "user.invite", org_id=org.id, user_id=user.id,
        resource_type="user", resource_id=existing.id,
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
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    membership = db.query(OrganizationMembership).filter_by(
        id=membership_id, organization_id=org.id
    ).first()
    if not membership:
        raise HTTPException(status_code=404)
    if membership.user_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot remove yourself")
    membership.is_active = False
    db.commit()
    return RedirectResponse(url="/users", status_code=303)
